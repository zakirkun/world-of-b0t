"""CONTROL-0 :: internal upstream for RELAY VEIL (World Of B0t challenge 20)

World Of B0t challenge 20 - internal half.
Category: Infra | Difficulty: hard | Vuln: config-path traversal -> admin route

The relay forwards to this service. It has two surfaces:

    /health /status /echo     the public upstream the world reaches via public.conf
    /_control/secret          the flag - only reachable if a route names it

Nothing here decides authorisation. The relay's route table decides, and only
public.conf is loaded at boot, so /_control/secret has no path in.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

SERVICE = "control-0"
VERSION = "0.20.0"
START = time.time()

FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")


class Handler(BaseHTTPRequestHandler):
    server_version = SERVICE + "/" + VERSION

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("x-upstream", SERVICE)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path
        query = urlsplit(self.path).query

        if path == "/health":
            return self._json(200, {"service": SERVICE, "lab": "w20", "status": "ok",
                                    "uptime": int(time.time() - START)})

        if path == "/status":
            return self._json(200, {"service": SERVICE, "version": VERSION,
                                    "surfaces": ["public", "control"]})

        if path == "/echo":
            return self._json(200, {"echo": parse_qs(query).get("msg", [""])[0][:400]})

        if path == "/_control/secret":
            via = self.headers.get("x-relay-hop")
            return self._json(200, {
                "service": SERVICE,
                "surface": "control",
                "via_relay": via == "1",
                "flag": FLAG,
            })

        if path == "/_control/reload":
            return self._json(200, {"service": SERVICE, "note": "control plane"})

        return self._json(404, {"error": "no such path", "path": path})


def main():
    port = int(os.environ.get("PORT", "9000"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (internal only)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
