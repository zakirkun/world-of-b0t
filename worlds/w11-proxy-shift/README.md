# w11 :: Edge Shift

- **Category:** Web
- **Difficulty:** hard
- **Stack:** Go / stdlib gateway + Python origin (2 containers)
- **URL:** http://localhost:30011

## Brief

EDGE SHIFT is the API gateway in front of an internal origin. Public traffic is
published under `/api/v1`; the gateway strips that prefix and forwards the rest
to an origin that speaks unversioned paths.

The origin is not published to the host. It holds the flag behind an
administrative route, and the gateway has rules that are supposed to keep the
public out of it:

```
reject a .. path segment   -> 400
reject an encoded dot %2e  -> 400
reject a nested resource   -> 404
```

The gateway makes those decisions on the **raw** request target. The origin
makes its routing decision on the **decoded, normalized** path. Those two views
of the same URL disagree.

## Goal

Reach the origin's `/admin/secret` through the gateway and read the flag.

## Hint

The gateway counts *literal* slashes. An encoded slash is not a literal slash to
it — but it is to the layer that resolves dot-segments.

What does the gateway actually forward, and what does the origin do with it?

<details>
<summary>Spoiler</summary>

The gateway trims `/api/v1` from the **escaped** path and enforces its
flat-resource rule by counting literal `/` in that escaped remainder. So the
trivial `GET /api/v1/admin/secret` is refused — its raw remainder `/admin/secret`
has two slashes.

Glue the dot-dot to an **encoded** slash instead:

```bash
curl -s --path-as-is 'http://localhost:30011/api/v1/..%2fadmin%2fsecret'
```

The raw remainder is `/..%2fadmin%2fsecret` — exactly one literal slash, so the
flat rule is satisfied. The origin then unquotes it to `/../admin/secret` and
resolves dot-segments, arriving at `/admin/secret`:

```json
{"service":"origin-9","route":"admin/secret","via_edge":true,"flag":"hex4b0t{...}"}
```

`--path-as-is` is required: without it curl collapses the `..` client-side and
the payload never leaves your machine intact.

The double-encoded `..%252f` form is a dead end — it resolves to the literal
`..%2f`, which is not a route.

`solution/exploit.sh` runs the payload; `solution/probe.sh` asserts both that the
gateway's rules still fire and that the traversal gets through.

</details>
