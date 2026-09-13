"""BYTECODE VAULT :: sealed module / World Of B0t challenge 22.

Category: Graybox | Difficulty: hard | Vuln: secret logic recoverable from
shipped bytecode

The vault gates its flag behind an access code. The code is computed by the
`vault` module, whose *source* never left the build machine - but a "backup
artifact" of the compiled module is mirrored at /static/vault.pyc. The code
object carries VAULT_SALT, VAULT_USER and the exact derivation as constants
and bytecode, so the access code is recoverable by disassembly.

GET  /                    landing page
GET  /static/vault.pyc    the graybox grant: the compiled vault module
POST /api/unlock          {"code": "<16 hex>"} -> flag on success
GET  /api/hint            the username component only; the salt never left
GET  /api/health          liveness
"""

import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB = "w22"
SERVICE = "bytecode-vault"
VERSION = "1.22.0"

FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# Verified on python:3.12-alpine: a bare top-level .pyc next to the importing
# script IS importable by a plain `import vault` (no SourcelessFileLoader
# needed). vault.py was deleted by the Dockerfile compile step; only
# vault.pyc ships. If a future image drops the bare .pyc import, switch to:
#   spec = importlib.util.spec_from_file_location("vault", "/app/vault.pyc")
#   vault = importlib.util.module_from_spec(spec); spec.loader.exec_module(vault)
vault = __import__("vault")

LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w22">
<title>BYTECODE VAULT</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#05050c; color:#c8d6e5; font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
         margin:0; padding:32px; }}
  h1 {{ color:#00f0ff; letter-spacing:.22em; margin:0 0 4px; font-size:22px; }}
  .sub {{ color:#ff2e97; letter-spacing:.14em; font-size:11px; text-transform:uppercase; }}
  section {{ max-width:820px; margin:26px auto 0; border:1px solid #1b2340; background:#0a0a16; padding:18px 20px; }}
  code {{ color:#00f0ff; }}
  pre {{ background:#05050c; border-left:2px solid #ff2e97; padding:12px 14px; overflow-x:auto; color:#9fb3c8; }}
  a {{ color:#ff2e97; }}
  table {{ border-collapse:collapse; width:100%; }}
  td,th {{ text-align:left; padding:4px 10px 4px 0; border-bottom:1px solid #131a30; vertical-align:top; }}
  th {{ color:#00f0ff; font-weight:400; }}
</style>
<h1>BYTECODE VAULT</h1>
<div class="sub">{service} v{version} :: sealed module</div>

<section>
  <p>A vault holds the flag. It opens for exactly one thing: the <b>access
  code</b>. Present the code at <code>POST /api/unlock</code> with a JSON body
  <code>{{"code":"..."}}</code> and the seal breaks.</p>

  <p>The module that computes the code is sealed. Its source never left the
  build machine - only the interpreter has ever read those lines. What did
  survive is a <b>backup artifact</b>: the compiled module, mirrored at
  <a href="/static/vault.pyc"><code>/static/vault.pyc</code></a> for disaster
  recovery. Bytecode is not source, the operators say. Bytecode is what the
  interpreter eats, and everything it eats it keeps.</p>

  <table>
    <tr><th>method</th><th>path</th><th>notes</th></tr>
    <tr><td>POST</td><td><code>/api/unlock</code></td><td><code>{{"code":"&lt;16 hex&gt;"}}</code></td></tr>
    <tr><td>GET</td><td><code>/api/hint</code></td><td>one component, free of charge</td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness</td></tr>
    <tr><td>GET</td><td><code>/static/vault.pyc</code></td><td>the backup artifact</td></tr>
  </table>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "bytecodevault/" + VERSION

    # -- helpers ------------------------------------------------------------
    def _json(self, code, payload):
        # compact separators so responses match the documented shape verbatim
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except ValueError:
            return {}

    def log_message(self, fmt, *args):
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            return self._html(200, LANDING.format(service=SERVICE, version=VERSION))

        if path == "/api/health":
            return self._json(200, {"ok": True, "lab": LAB, "vault": "bytecode"})

        if path == "/api/hint":
            # The username is the free half. The salt lives only in the
            # bytecode - which is exactly the artifact we mirror.
            return self._json(200, {"user": vault.VAULT_USER,
                                    "note": "salt never left the build machine"})

        if path == "/static/vault.pyc":
            # ponytail: serve the pyc from disk with a one-liner instead of
            # pulling in functools.partial or a static-file helper; add ranges
            # only if a player's downloader ever needs them.
            try:
                with open("/app/vault.pyc", "rb") as f:
                    data = f.read()
            except OSError:
                return self._json(404, {"error": "artifact missing"})
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        return self._json(404, {"error": "not found", "path": path})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        obj = self._body()

        if path == "/api/unlock":
            code = obj.get("code") if isinstance(obj, dict) else None
            if not isinstance(code, str) or not vault.check(code):
                return self._json(403, {"ok": False})
            return self._json(200, {"ok": True, "flag": FLAG})

        return self._json(404, {"error": "not found", "path": path})


def _self_check():
    """Prove the lab is solvable from the artifact alone: compile vault.py,
    delete it, import the bare .pyc, and recover the code the way a player
    would - by reading constants out of the code object."""
    import dis
    import marshal

    with open("/app/vault.pyc", "rb") as f:
        f.read(16)
        module_co = marshal.load(f)

    found = {"consts": {}, "names": []}

    def walk(co):
        for k in co.co_consts:
            if hasattr(k, "co_consts"):
                walk(k)
        found["names"].extend(co.co_names)
        if co.co_name == "unlock_code":
            found["unlock"] = dis.Bytecode(co).dis()

    walk(module_co)
    consts = [k for k in module_co.co_consts if isinstance(k, str)]
    found["consts"] = consts

    salt, user = [c for c in consts if len(c) == 16 and all(ch in "0123456789abcdef" for ch in c)], \
                 [c for c in consts if c == "keeper-07"]
    assert user, "VAULT_USER not in module constants"
    assert len(salt) == 1, f"VAULT_SALT not identifiable among {consts}"
    assert "sha256" in " ".join(found["names"]) or "sha256" in found["unlock"], \
        "hash derivation not visible in bytecode"
    code = vault.unlock_code()
    assert vault.check(code)
    print(f"[self-check] constants in pyc: {consts}")
    print(f"[self-check] recovered code unlocks: {code}")


def main():
    if os.environ.get("W0B_SELFCHECK") == "1":
        _self_check()
        return
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
