"""CACHE-AWARE PREVIEW NODE :: an edge cache that mints its own cache keys.

World Of B0t challenge 16
Category: Web | Difficulty: easy | Vuln: CRLF injection / HTTP response splitting
        via an unvalidated value concatenated into a response header.

The node sits in front of a preview service. For every preview request it builds
an X-Cache-Key from the request URL and the client-supplied X-Forwarded-Host,
writes that key into the response headers, and stores the *whole header block* in
an in-memory cache so the next request for the same URL is a cheap replay.

--------------------------------------------------------------------------
The bug: the cache key is built by string concatenation and written straight
into the response header block. Nothing rejects CR/LF in the value, so an
attacker who controls any part of it controls where the header block ends.

    X-Cache-Key: <forwarded-host>/page/<name>\r\n
    <-- injected header line here -->

The node's own rule is that a request is "internal" when its cache entry carries
the marker header X-Internal-Cache: 1. That marker is supposed to be stripped by
the edge for outside traffic. Once an attacker can write it into a cached
representation, the next ordinary request for that same URL replays the poisoned
entry and is treated as internal.
--------------------------------------------------------------------------

GET  /                landing page
GET  /page?name=...   the cacheable preview route
GET  /admin/flag      internal route; needs X-Internal-Cache: 1 (else 403)
GET  /api/health      liveness + cache stats
"""

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

LAB = "w16"
SERVICE = "cache-poison"
VERSION = "1.16.0"
START = time.time()

FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# The edge is documented as stripping this from outside traffic. It never
# reaches an ordinary client, which is why the node trusts it as a marker.
INTERNAL_MARKER = "X-Internal-Cache"

# ponytail: one dict + one lock is the whole cache. It is deliberately not an
# LRU and has no TTL - the lab wants a stable entry to replay, and a real cache
# would only add eviction noise. Bounded by CACHE_SLOTS so it cannot be used to
# exhaust memory.
CACHE_SLOTS = 64
CACHE = {}                     # url-key -> {"headers": bytes, "body": bytes}
CACHE_LOCK = threading.Lock()


def cache_key(path, query_name):
    """The node's cache key.

    VULNERABLE: `name` comes straight out of the URL, is URL-decoded here, and
    is concatenated into the value below without any CR/LF screening.
    """
    return f"/page?name={query_name}"


def preview_headers(forwarded_host, name):
    """Build the raw response header block for a preview response.

    VULNERABLE: `name` (attacker-controlled, URL-decoded) is concatenated into
    the X-Cache-Key line. A \\r\\n in it ends the header early and everything
    after it is parsed as further response headers.
    """
    return (
        "HTTP/1.1 200 OK\r\n"
        f"X-Cache-Key: {forwarded_host}/page/{name}\r\n"
        f"X-Preview-Node: {SERVICE}/{VERSION}\r\n"
        "content-type: text/html; charset=utf-8\r\n"
    )


def parse_header_block(raw_headers):
    """Parse the node's own header block back into a list of (name, value).

    The cache stores what it wrote and replays it; it also inspects its own
    block to decide whether the entry carries the internal marker. This is the
    trust decision that the injection subverts.
    """
    fields = []
    for line in raw_headers.split("\r\n"):
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        fields.append((k.strip().lower(), v.strip()))
    return fields


class Handler(BaseHTTPRequestHandler):
    server_version = "cachepoison/" + VERSION
    protocol_version = "HTTP/1.1"

    # -- helpers ------------------------------------------------------------
    def _write_raw(self, status, extra_headers, body):
        """Write a complete response by hand.

        ponytail: hand-rolled response, +0 ms off the framework path. The node
        caches and replays *raw header bytes*, so it cannot use send_header /
        end_headers - those buffer through the framework's header list and would
        re-encode what it wants to store verbatim. Building the block as a string
        and writing the bytes is the whole point of the design.
        """
        head = f"HTTP/1.1 {status}\r\n{extra_headers}"
        head += f"content-length: {len(body)}\r\n"
        head += "connection: close\r\n\r\n"
        self.wfile.write(head.encode("latin-1", "replace") + body)

    def _json(self, code, payload):
        import json
        body = json.dumps(payload).encode()
        self._write_raw(code, "content-type: application/json\r\n", body)

    def _body_text(self, code, text, extra=""):
        body = text.encode()
        self._write_raw(code, "content-type: text/html; charset=utf-8\r\n" + extra, body)

    def log_message(self, *a):
        # Quiet: the launcher owns the interesting output.
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path

        if path == "/":
            return self._body_text(200, LANDING)

        if path == "/api/health":
            with CACHE_LOCK:
                slots = len(CACHE)
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "cache_slots": slots,
                "cache_capacity": CACHE_SLOTS,
                "uptime": int(time.time() - START),
            })

        if path == "/admin/flag":
            # The internal route. Outside traffic never carries the marker -
            # the edge strips it - so a direct hit is a 403.
            if self.headers.get(INTERNAL_MARKER) == "1":
                return self._json(200, {"flag": FLAG})
            return self._json(403, {"error": "forbidden", "need": INTERNAL_MARKER})

        if path == "/page":
            return self._preview(parts)

        return self._json(404, {"error": "not found", "path": path})

    def _preview(self, parts):
        """The cacheable preview route.

        On a cache MISS the node builds a fresh header block, stores it, and
        serves it. On a HIT it replays the stored bytes. Because the stored
        block is what the node *wrote* - including anything an attacker injected
        into it - a hit replays the injected headers too.
        """
        # Attacker-controlled: the name is URL-decoded with no validation.
        name = ""
        for pair in parts.query.split("&"):
            if pair.startswith("name="):
                name = unquote(pair[len("name="):])
                break
        forwarded_host = self.headers.get("X-Forwarded-Host", "localhost")
        key = cache_key(parts.path, name)

        with CACHE_LOCK:
            entry = CACHE.get(key)

        if entry is not None:
            # HIT: replay the stored header block verbatim.
            fields = dict(parse_header_block(entry["headers"].decode("latin-1")))
            internal = fields.get(INTERNAL_MARKER.lower()) == "1"
            body = entry["body"]
            if internal:
                body = self._internal_body(name).encode()
            head = entry["headers"] + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode("latin-1")
            self.wfile.write(head + body)
            return

        # MISS: build and cache the block.
        raw_headers = preview_headers(forwarded_host, name)
        body = self._public_body(name).encode()
        with CACHE_LOCK:
            if len(CACHE) < CACHE_SLOTS:
                CACHE[key] = {"headers": raw_headers.encode("latin-1", "replace"), "body": body}
        self.wfile.write(
            (raw_headers + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n").encode("latin-1", "replace") + body
        )

    @staticmethod
    def _public_body(name):
        # The name also appears in the body, but escaped: the body is not the
        # bug and an unescaped reflection here would confuse the lab with a
        # second, unrelated injection. Only the header path is spliced raw.
        from html import escape
        return (
            "<!doctype html><meta charset=utf-8><title>preview</title>"
            f"<h1>preview</h1><p>rendered preview for <code>{escape(name)}</code></p>"
            "<p>cached at the edge; re-request this URL to read the cache entry.</p>"
        )

    @staticmethod
    def _internal_body(name):
        # Served only when the cache entry for this URL carries the marker.
        return (
            "<!doctype html><meta charset=utf-8><title>preview :: internal</title>"
            f"<h1>internal preview</h1><p>cache entry treated as internal.</p><pre>{FLAG}</pre>"
        )


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w16">
<title>CACHE POISON</title>
<style>
  :root { color-scheme: dark; }
  body { background:#05050c; color:#c8d6e5; font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
         margin:0; padding:32px; }
  h1 { color:#00f0ff; letter-spacing:.22em; margin:0 0 4px; font-size:22px; }
  .sub { color:#ff2e97; letter-spacing:.14em; font-size:11px; text-transform:uppercase; }
  section { max-width:820px; margin:26px auto 0; border:1px solid #1b2340; background:#0a0a16; padding:18px 20px; }
  code { color:#00f0ff; }
  pre { background:#05050c; border-left:2px solid #ff2e97; padding:12px 14px; overflow-x:auto; color:#9fb3c8; }
  a { color:#ff2e97; }
  table { border-collapse:collapse; width:100%; }
  td,th { text-align:left; padding:4px 10px 4px 0; border-bottom:1px solid #131a30; vertical-align:top; }
  th { color:#00f0ff; font-weight:400; }
</style>
<h1>CACHE POISON</h1>
<div class="sub">cache-aware preview node :: edge cache v1.16.0</div>

<section>
  <p>This node fronts a preview service and caches one header block per URL.
  Every preview response carries an <code>X-Cache-Key</code> built from the
  client-supplied <code>X-Forwarded-Host</code> and the requested name, so the
  edge and the origin agree on what is cached.</p>

  <table>
    <tr><th>method</th><th>path</th><th>notes</th></tr>
    <tr><td>GET</td><td><code>/</code></td><td>this page</td></tr>
    <tr><td>GET</td><td><code>/page?name=...</code></td><td>cacheable preview</td></tr>
    <tr><td>GET</td><td><code>/admin/flag</code></td><td>internal only</td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness + cache stats</td></tr>
  </table>

<pre>cache policy
  key            : /page?name=&lt;name&gt;      (the URL, nothing else)
  stored         : the header block the node wrote, plus the body
  replay         : a HIT returns the stored header block verbatim
  trust          : an entry with X-Internal-Cache: 1 is served as internal

trusted request headers
  X-Forwarded-Host   reflected into the cache key (from the edge)

headers stripped at the edge (never reach the node from outside)
  X-Internal-Cache</pre>

  <p>Preview entries are cheap to replay, so the edge keeps them hot. There is
  no reason for a cache key to contain a newline &mdash; and that is exactly the
  assumption an attacker will test.</p>
</section>
"""


def main():
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
