"""PICKLE VAULT :: a session/preference store for the vault dashboard.

World Of B0t challenge 14
Category: Pwn | Difficulty: medium | Vuln: pickle.loads() on an attacker-supplied cookie

The dashboard keeps your session in a cookie. The cookie is the session: the
server base64-decodes it and hands the bytes straight to pickle.loads(), then
treats whatever comes back as the session object and echoes it to you.

--------------------------------------------------------------------------
session = pickle.loads(base64.b64decode(cookie["vault_session"]))   # <-- here
--------------------------------------------------------------------------

pickle is not a data format - it is a small virtual machine, and the opcodes it
runs include REDUCE, which calls an arbitrary callable on an arbitrary argument.
A class whose __reduce__ returns (os.system, ("id",)) therefore runs the command
as the service user the moment it is loaded.

GET  /                  landing page (session is locked: no flag here)
GET  /api/health        liveness
GET  /api/vault         vault status, intentionally opaque
GET  /api/session       echoes your session as JSON (vault: locked)
"""

import base64
import json
import os
import pickle
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# vault.py is root-owned and 0400, so this import only works during the boot
# phase while the entrypoint is still root. By the time we serve a request we
# have dropped to uid 10001 and the file is unreadable - the value lives on in
# this imported module object, in memory, reachable only by running code here.
from vault import VAULT_FLAG

LAB = "w14"
SERVICE = "pickle-vault"
VERSION = "1.14.0"
COOKIE = "vault_session"
START = time.time()


class Session:
    """The user's dashboard state.

    Anything the deserializer hands back is treated as one of these, which is
    how a malicious payload's messages (or any reflected output) reach the
    response body.
    """

    def __init__(self, user="guest", theme="cyberpunk", messages=None):
        self.user = user
        self.theme = theme
        self.messages = list(messages or ["vault: locked"])


DEFAULT_SESSION = Session(user="guest", messages=["vault: locked"])


def _encode(session):
    """Cookie form: base64(pickle(session))."""
    return base64.b64encode(pickle.dumps(session)).decode()


# A real, valid cookie minted at boot so the service demonstrably works.
DEFAULT_COOKIE = _encode(DEFAULT_SESSION)


def _shows_flag(strings):
    """Sanity guard for the self-check only - never used on the request path."""
    return any("hex4b0t{" in s for s in strings)


def _self_check():
    """Import-time proof that the lab works end to end.

    A benign cookie must round-trip, and a hostile one must execute. If either
    half is broken the container refuses to start rather than shipping a lab
    that cannot be solved (or cannot be used).
    """
    # 1. Benign round-trip (the boot-minted cookie the landing page shows).
    session = pickle.loads(base64.b64decode(DEFAULT_COOKIE))
    assert isinstance(session, Session), type(session)
    assert session.messages == ["vault: locked"], session.messages

    # 1b. A wire-format dict also renders - the handler duck-types it.
    as_dict = pickle.loads(pickle.dumps({"messages": ["vault: locked"]}))
    assert Handler._describe(as_dict)["messages"] == ["vault: locked"]

    # 2. The classic __reduce__ REDUCE gadget. No network needed: os.popen
    #    runs locally and hands back a file object.
    class Payload:
        def __reduce__(self):
            return (os.popen, ("echo hex4b0t{selfcheck}",))

    handle = pickle.loads(pickle.dumps(Payload()))
    assert _shows_flag([handle.read()]), "REDUCE gadget did not execute"

    # 3. The flag is importable at runtime (the only way it was ever reachable).
    assert VAULT_FLAG, "W0B_FLAG was not injected"
    return True


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w14">
<title>PICKLE VAULT</title>
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
  .locked {{ color:#ff2e97; }}
</style>
<h1>PICKLE VAULT</h1>
<div class="sub">{service} v{version} :: stateless session store</div>

<section>
  <p>The vault holds one secret. Your dashboard state - username, theme, the
  messages pinned to your panel - travels entirely in the
  <code>{cookie}</code> cookie, so the box stays stateless. The server decodes
  the cookie and rebuilds your session from it.</p>

<pre>session = pickle.loads(base64.b64decode(cookie["{cookie}"]))
# then: resp["session"] = vars(session), messages echoed back to you</pre>

  <p>A freshly minted session cookie, so you can see the shape of the thing:</p>
<pre>{default_cookie}</pre>

  <table>
    <tr><th>method</th><th>path</th><th>returns</th></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness</td></tr>
    <tr><td>GET</td><td><code>/api/session</code></td><td>your decoded session</td></tr>
    <tr><td>GET</td><td><code>/api/vault</code></td><td>vault status: <span class="locked">locked</span></td></tr>
  </table>

  <p>The vault is sealed independently of your session. There is no route that
  returns it - <code>GET /api/vault</code> only ever reports
  <span class="locked">vault: locked</span>.</p>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "picklevault/" + VERSION

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

    def _cookie(self, name):
        raw = self.headers.get("cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _session(self):
        """Rebuild the caller's session from the cookie.

        The cookie is the session: it is decoded and deserialized with no
        integrity check of any kind, because the original author did not know
        that pickle.loads() is a code-execution primitive.
        """
        cookie = self._cookie(COOKIE)
        if not cookie:
            return Session(), False
        try:
            data = base64.b64decode(cookie)
        except Exception:
            return Session(), False
        # --- the bug -----------------------------------------------------
        session = pickle.loads(data)
        # -----------------------------------------------------------------
        return session, True

    @staticmethod
    def _describe(session):
        """Render the session back to the caller.

        Duck-typed on purpose: whatever object the deserializer produced is
        reflected here, so a payload that runs a command and stores the output
        on the session sees that output in the response.
        """
        def field(name, default):
            if isinstance(session, dict):
                return session.get(name, default)
            return getattr(session, name, default)

        messages = field("messages", [])
        # A payload that returns a bare string (eval, subprocess output...) has
        # no `messages`, so surface it directly rather than dropping it.
        if isinstance(session, (str, bytes)):
            messages = [session]
        elif hasattr(session, "read"):  # file objects from os.popen
            messages = [session.read()]
        return {
            "user": field("user", "guest"),
            "theme": field("theme", "cyberpunk"),
            "messages": [str(m) for m in messages],
        }

    def log_message(self, fmt, *args):
        # Keep the container log quiet; the launcher owns the interesting output.
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            return self._html(200, LANDING.format(
                service=SERVICE, version=VERSION, cookie=COOKIE,
                default_cookie=DEFAULT_COOKIE,
            ))

        if path == "/api/health":
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "session_cookie": COOKIE,
                "serializer": "pickle",
                "uptime": int(time.time() - START),
            })

        if path == "/api/vault":
            # Deliberately opaque: the vault never leaves this process.
            return self._json(200, {
                "vault": "locked",
                "note": "the vault is not a session field and no route returns it",
            })

        if path == "/api/session":
            session, provided = self._session()
            return self._json(200, {
                "cookie_present": provided,
                "session": self._describe(session),
            })

        return self._json(404, {"error": "not found", "path": path})


def main():
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
