"""TOKEN CRYPT :: a 3DES token mint.

World Of B0t challenge 12
Category: Crypto | Difficulty: hard | Vuln: semi-weak DES keys in a triple-DES construction

The service holds a secret (the flag) and can produce "sealed tokens" over it.
It exposes two versions of the sealing routine and, because the customer wanted
to be able to verify tokens without shipping the master key, it lets the caller
supply part of the key schedule.

--------------------------------------------------------------------------
v1(token)  =  E_k1( data )
v2(token)  =  E_k1( E_k3( E_k2( data ) ) )

k1 is the service's own per-boot key; k2 and k3 are supplied by the caller on
the request. That is the whole bug: two thirds of a triple-DES key schedule is
under attacker control, and DES has semi-weak key pairs for which the two inner
applications cancel out completely.
--------------------------------------------------------------------------

GET  /                landing page
GET  /api/keys        the key material the service considers "safe to publish"
POST /api/v1/encrypt  {"data": "<hex>"}              -> E_k1(data)
POST /api/v1/decrypt  {"data": "<hex>"}              -> D_k1(data)
POST /api/v2/encrypt  {"data": "<hex>", "k2": <hex64>, "k3": <hex64>}
POST /api/v2/decrypt  {"data": "<hex>", "k2": <hex64>, "k3": <hex64>}
GET  /api/health
"""

import base64
import binascii
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import des

LAB = "w12"
SERVICE = "token-crypt"
VERSION = "1.12.0"
START = time.time()

# The secret the service refuses to hand over directly. Read from the
# environment at boot so nothing is baked into the image layer.
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# The master key: per-boot, 8 bytes, never leaves this process.
K1 = secrets.token_bytes(8)

# ponytail: the flag is the plaintext here, so a 25-byte flag pads to 32 bytes =
# exactly 4 DES blocks. ECB is deliberate - CBC would chain the blocks and the
# per-block oracle below would not work. The writeup documents the consequence.


def _seal_v1(data: bytes) -> bytes:
    """v1: plain single-DES ECB over k1."""
    return des.ecb_encrypt(K1, des.pad(data))


def _open_v1(data: bytes) -> bytes:
    return des.unpad(des.ecb_decrypt(K1, data))


def _seal_v2(data: bytes, k2: bytes, k3: bytes) -> bytes:
    """v2: E_k1( E_k3( E_k2( data ) ) ) - the "triple" upgrade.

    The outer and inner keys come from the request, so two of the three
    applications are entirely attacker-chosen. DES has semi-weak key pairs
    {a, b} for which E_a(E_b(x)) == x, so for such a pair the two inner
    applications cancel and v2 degenerates to v1 - the master key never has to
    be known to unwrap a v1 ciphertext.
    """
    inner = des.ecb_encrypt(k2, des.pad(data))
    middle = des.ecb_encrypt(k3, inner)
    return des.ecb_encrypt(K1, middle)


def _open_v2(data: bytes, k2: bytes, k3: bytes) -> bytes:
    middle = des.ecb_decrypt(K1, data)
    inner = des.ecb_decrypt(k3, middle)
    return des.unpad(des.ecb_decrypt(k2, inner))


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w12">
<title>TOKEN CRYPT</title>
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
<h1>TOKEN CRYPT</h1>
<div class="sub">{service} v{version} :: stateless seal box</div>

<section>
  <p>A vault holds one secret. Sealing it used to be single DES, which the
  security review called &ldquo;not enough&rdquo;, so v2 applies the cipher three times.
  To let downstream verifiers check tokens without holding the master key, the
  two non-master keys travel in the request.</p>

<pre>v1(data) = E_k1(data)
v2(data) = E_k1( E_k3( E_k2( data ) ) )</pre>

  <table>
    <tr><th>method</th><th>path</th><th>body</th></tr>
    <tr><td>GET</td><td><code>/api/keys</code></td><td>publishable key material</td></tr>
    <tr><td>POST</td><td><code>/api/v1/encrypt</code></td><td><code>{{"data":"&lt;hex&gt;"}}</code></td></tr>
    <tr><td>POST</td><td><code>/api/v1/decrypt</code></td><td><code>{{"data":"&lt;hex&gt;"}}</code></td></tr>
    <tr><td>POST</td><td><code>/api/v2/encrypt</code></td><td><code>{{"data":"&lt;hex&gt;","k2":"&lt;16 hex&gt;","k3":"&lt;16 hex&gt;"}}</code></td></tr>
    <tr><td>POST</td><td><code>/api/v2/decrypt</code></td><td><code>{{"data":"&lt;hex&gt;","k2":"&lt;16 hex&gt;","k3":"&lt;16 hex&gt;"}}</code></td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness</td></tr>
  </table>

  <p>Every payload is ECB over raw DES blocks. Decrypting the vault with
  <code>/api/v1/decrypt</code> is refused &mdash; the endpoint is for tokens you minted
  yourself, and it never sees the vault.</p>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "tokencrypt/" + VERSION

    # -- helpers ------------------------------------------------------------
    def _json(self, code, payload):
        body = json.dumps(payload).encode()
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
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except ValueError:
            # Accept form encoding too, so the lab is usable from a browser.
            from urllib.parse import parse_qs
            return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    @staticmethod
    def _hexfield(obj, name, size=None):
        """Pull a hex field, returning (bytes|None, error|None)."""
        if name not in obj:
            return None, f"missing field: {name}"
        try:
            raw = binascii.unhexlify(str(obj[name]).strip())
        except (binascii.Error, ValueError):
            return None, f"field {name} is not valid hex"
        if size is not None and len(raw) != size:
            return None, f"field {name} must be {size} bytes ({size * 2} hex chars)"
        return raw, None

    def log_message(self, fmt, *args):
        # Keep the container log quiet; the launcher owns the interesting output.
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            return self._html(200, LANDING.format(service=SERVICE, version=VERSION))

        if path == "/api/health":
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "mode": "ECB",
                "block_bytes": des.BLOCK,
                "uptime": int(time.time() - START),
            })

        if path == "/api/keys":
            # The service considers the published semi-weak set "known-safe",
            # which is exactly the set that must never be used as a key pair.
            return self._json(200, {
                "note": "DES has keys that are weaker than they look. Published for "
                        "interoperability with the legacy verifier.",
                "semi_weak_pairs": [{"a": a, "b": b} for a, b in des.SEMI_WEAK_PAIRS],
                "publishable_k2": des.SEMI_WEAK_PAIRS[0][0],
                "publishable_k3": des.SEMI_WEAK_PAIRS[0][1],
            })

        if path == "/api/vault":
            # The whole point of the lab: the vault is sealed, and only sealed.
            sealed = _seal_v1(FLAG.encode()).hex()
            return self._json(200, {
                "vault": "sealed",
                "ciphertext": sealed,
                "blocks": len(sealed) // 16,
                "note": "single-DES ECB, key withheld",
            })

        return self._json(404, {"error": "not found", "path": path})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        obj = self._body()

        if path == "/api/v1/encrypt":
            data, err = self._hexfield(obj, "data")
            if err:
                return self._json(400, {"error": err})
            return self._json(200, {"schema": "v1", "ciphertext": _seal_v1(data).hex()})

        if path == "/api/v1/decrypt":
            data, err = self._hexfield(obj, "data")
            if err:
                return self._json(400, {"error": err})
            if len(data) % des.BLOCK:
                return self._json(400, {"error": f"ciphertext must be a multiple of {des.BLOCK} bytes"})
            return self._json(200, {"schema": "v1", "plaintext": _open_v1(data).hex()})

        if path == "/api/v2/encrypt":
            data, err = self._hexfield(obj, "data")
            if err:
                return self._json(400, {"error": err})
            k2, err = self._hexfield(obj, "k2", des.BLOCK)
            if err:
                return self._json(400, {"error": err})
            k3, err = self._hexfield(obj, "k3", des.BLOCK)
            if err:
                return self._json(400, {"error": err})
            return self._json(200, {
                "schema": "v2",
                "ciphertext": _seal_v2(data, k2, k3).hex(),
            })

        if path == "/api/v2/decrypt":
            data, err = self._hexfield(obj, "data")
            if err:
                return self._json(400, {"error": err})
            k2, err = self._hexfield(obj, "k2", des.BLOCK)
            if err:
                return self._json(400, {"error": err})
            k3, err = self._hexfield(obj, "k3", des.BLOCK)
            if err:
                return self._json(400, {"error": err})
            if len(data) % des.BLOCK:
                return self._json(400, {"error": f"ciphertext must be a multiple of {des.BLOCK} bytes"})
            return self._json(200, {
                "schema": "v2",
                "plaintext": _open_v2(data, k2, k3).hex(),
            })

        if path == "/api/vault/open":
            # Guarded: this is the "just give me the flag" route and it is shut.
            return self._json(403, {"error": "vault open requires the master key (k1 withheld)"})

        return self._json(404, {"error": "not found", "path": path})


def main():
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
