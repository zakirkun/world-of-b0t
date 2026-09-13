"""ORIGIN-9 :: internal api surface (World Of B0t challenge 11)

World Of B0t challenge 11 - internal half.
Category: Web | Difficulty: hard | Vuln: reverse-proxy path-normalization bypass

This is the service the edge gateway forwards to. It is NOT published to the
host; the gateway is the only route in.

The origin is the second half of the bug. It unquotes the raw path it receives
and then resolves dot-segments against its own routing table *before* matching
routes. So a path that looked like a harmless sub-resource at the edge becomes a
different route entirely by the time it is dispatched here.

    GET /status        public
    GET /echo?msg=     public, reflects
    GET /admin/secret  the flag - no public route maps to it
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

LAB = "w11"
SERVICE = "origin-9"
VERSION = "9.4.0"
START = time.time()

FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")


def normalize(path: str) -> str:
    """Resolve . and .. segments exactly as a typical static/routing layer does.

    This is the operation the edge did NOT perform on the decoded path it used
    for its decision. Doing it here, on a raw path the edge already blessed, is
    what makes the gateway's rule and the origin's reality disagree.
    """
    parts = []
    for seg in path.split("/"):
        if seg == "..":
            if parts:
                parts.pop()
            continue
        if seg in ("", "."):
            continue
        parts.append(seg)
    return "/" + "/".join(parts)


class Handler(BaseHTTPRequestHandler):
    server_version = "origin-9/" + VERSION

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("x-origin", SERVICE)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        raw_path, _, query = urlsplit(self.path).path, None, urlsplit(self.path).query

        # The origin works on the RAW path it was handed. It unquotes, THEN
        # resolves dot-segments, THEN routes.
        decoded = unquote(raw_path)
        route = normalize(decoded)

        if route == "/status":
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "status": "nominal",
                "uptime": int(time.time() - START),
                "routes": ["/status", "/echo", "/admin/secret"],
            })

        if route == "/echo":
            msg = parse_qs(query or "").get("msg", [""])[0]
            return self._json(200, {"echo": msg[:400]})

        if route == "/admin/secret":
            # Reached only if a request is dispatched here with the admin route
            # as the RESOLVED path. Nothing in the public gateway surface is
            # supposed to be able to produce that.
            edge = self.headers.get("x-edge-hop")
            return self._json(200, {
                "service": SERVICE,
                "route": "admin/secret",
                "via_edge": edge == "1",
                "flag": FLAG,
            })

        if route == "/":
            return self._json(200, {"service": SERVICE, "note": "internal surface"})

        return self._json(404, {
            "error": "no such route",
            "received_raw": raw_path,
            "resolved": route,
        })


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (internal only)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
