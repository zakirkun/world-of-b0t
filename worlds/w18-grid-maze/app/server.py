"""GRID MAZE :: a session mint for a legless robot.

World Of B0t challenge 18
Category: Web | Difficulty: medium | Vuln: predictable session id + role bleed

The service hands out a session id on login. The id is built from a per-boot
counter and a per-container seed that /api/health happily reports, so the id
space is fully computable rather than random. An admin session is created at
boot at a known counter value, which makes the admin id derivable from the
public health output alone.

Second half of the bug: /api/session/preauth opens a temporary session and
lets the *client* name a role preference. That value is copied into the real
session at authentication time and honoured, so a pre-auth role request becomes
an authenticated role.

GET  /                     landing page
GET  /api/health           liveness + per-container session_seed (the leak)
POST /api/login            {"user": "<name>"} -> creates a session
GET  /api/me               session identity (cookie or ?sid=)
GET  /api/flag             requires role == admin
GET  /api/sessions         non-admin session counts (ids withheld)
POST /api/session/preauth  {"pending_role": "..."} -> temporary session
"""

import hashlib
import json
import os
import re
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB = "w18"
SERVICE = "grid-maze"
VERSION = "1.18.0"
START = time.time()

# The secret the service refuses to hand over directly. Read from the
# environment at boot so nothing is baked into the image layer.
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# Per-container seed. It is mixed into every session id AND published by
# /api/health, which is the whole point of the lab.
SESSION_SEED = "gm-" + secrets.token_hex(4)

# The counter is deliberately a small monotonic integer that resets on boot.
# Boot spends the first two values on the service's own accounts, so the
# numbering is known before a single player connects.
_counter = 0


def _next_counter() -> int:
    global _counter
    _counter += 1
    return _counter


# Sessions are kept in-process; the lab is single-container and the store only
# has to survive for the life of the container.
SESSIONS: dict = {}


def new_session_id(counter: int) -> str:
    """The id-generating code. counter + container-fixed seed, weak hash."""
    return "gs_" + hashlib.md5(f"{SESSION_SEED}:{counter}".encode()).hexdigest()[:20]


def create_session(user: str, role: str = "player", pending_role: str | None = None) -> tuple:
    counter = _next_counter()
    sid = new_session_id(counter)
    SESSIONS[sid] = {
        "user": user,
        "role": role,
        "counter": counter,
        "created": time.time(),
    }
    if pending_role is not None:
        # VULNERABLE: the requested role is stored on the temporary session,
        # then login copies it straight into the real session below.
        SESSIONS[sid]["pending_role"] = pending_role
    return sid, SESSIONS[sid]


def _boot_accounts():
    """Boot-time accounts. Both land at fixed counter values.

    `maze-bot-admin` is the service's own operator session and is created
    first, so its counter is 1 and its id is computable from the public seed.
    """
    create_session("maze-bot-admin", role="admin")
    create_session("maze-bot-guest", role="player")


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w18">
<title>GRID MAZE</title>
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
  .you {{ color:#ff2e97; }}
</style>
<h1>GRID MAZE</h1>
<div class="sub">{service} v{version} :: session mint</div>

<section>
  <p>A warehouse robot navigates a grid. Every visitor gets a <b>session</b>; the
  maze maps one grid per role, and the <code>admin</code> grid is the one that
  holds the way out.</p>

  <p>Your session right now:</p>
<pre>sid  <span class="you">{sid}</span>
user {user}
role {role}</pre>

  <table>
    <tr><th>method</th><th>path</th><th>body</th></tr>
    <tr><td>POST</td><td><code>/api/login</code></td><td><code>{{"user":"&lt;name&gt;"}}</code></td></tr>
    <tr><td>POST</td><td><code>/api/session/preauth</code></td><td><code>{{"pending_role":"&lt;role&gt;"}}</code></td></tr>
    <tr><td>GET</td><td><code>/api/me</code></td><td>who you are</td></tr>
    <tr><td>GET</td><td><code>/api/sessions</code></td><td>how many sessions exist</td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness</td></tr>
    <tr><td>GET</td><td><code>/api/flag</code></td><td><code>admin</code> only</td></tr>
  </table>

  <p>Sessions are addressed by the <code>sid</code> cookie, or by
  <code>?sid=</code> for clients that do not keep cookies. The id is derived
  from a boot counter and a container seed; <code>/api/health</code> reports
  the seed so operators can reproduce an id in a pinch.</p>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "gridmaze/" + VERSION

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
            from urllib.parse import parse_qs
            return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def _cookie(self, name):
        raw = self.headers.get("cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def _sid(self):
        """The session id this request presents, from cookie or ?sid=."""
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        for part in query.split("&"):
            k, _, v = part.partition("=")
            if k == "sid":
                from urllib.parse import unquote
                return unquote(v)
        return self._cookie("sid")

    def _current(self):
        sid = self._sid()
        if not sid:
            return None, None
        return sid, SESSIONS.get(sid)

    def log_message(self, fmt, *args):
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/":
            sid, sess = self._current()
            if not sess:
                sid, sess = create_session("guest-%d" % _next_counter(), role="player")
            return self._html(200, LANDING.format(
                service=SERVICE, version=VERSION, sid=sid,
                user=sess["user"], role=sess["role"],
            ))

        if path == "/api/health":
            # The leak. session_seed is the fixed half of every session id and
            # is reported to anyone with no authentication at all.
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "uptime": int(time.time() - START),
                "sessions": len(SESSIONS),
                "session_seed": SESSION_SEED,
                "id_scheme": "gs_ + md5(session_seed + ':' + counter)[:20]",
                "note": "seed reported so operators can reproduce a session id",
            })

        if path == "/api/me":
            sid, sess = self._current()
            if not sess:
                return self._json(401, {"error": "no session", "hint": "POST /api/login"})
            return self._json(200, {
                "sid": sid,
                "user": sess["user"],
                "role": sess["role"],
                "counter": sess["counter"],
            })

        if path == "/api/sessions":
            # Counts only: the admin id is deliberately not listed, and neither
            # is the counter it sits at.
            players = sum(1 for s in SESSIONS.values() if s["role"] != "admin")
            return self._json(200, {
                "total": len(SESSIONS),
                "admins": 1,
                "players": players,
                "note": "session ids are not listed; the admin session exists at boot",
            })

        if path == "/api/flag":
            sid, sess = self._current()
            if not sess:
                return self._json(401, {"error": "no session"})
            if sess["role"] != "admin":
                return self._json(403, {
                    "error": "the exit is on the admin grid",
                    "your_role": sess["role"],
                    "required_role": "admin",
                })
            return self._json(200, {
                "grid": "admin",
                "user": sess["user"],
                "flag": FLAG,
            })

        return self._json(404, {"error": "not found", "path": path})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        obj = self._body()

        if path == "/api/login":
            user = str(obj.get("user") or "").strip()
            if not user:
                user = "player-%d" % _next_counter()
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,40}", user):
                return self._json(400, {"error": "invalid user name"})

            # If the client opened a temporary session first, honour the role it
            # asked for. This is the bleed: a pre-auth request crosses the auth
            # boundary and becomes the authenticated role.
            pending = None
            sid, _ = self._current()
            if sid and sid in SESSIONS:
                pending = SESSIONS[sid].get("pending_role")
            if pending not in (None, "player", "admin"):
                return self._json(400, {"error": "invalid pending_role"})

            nsid, sess = create_session(user, role=pending or "player", pending_role=pending)
            body = json.dumps({
                "sid": nsid,
                "user": sess["user"],
                "role": sess["role"],
                "carried": pending is not None,
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("set-cookie", f"sid={nsid}; Path=/; HttpOnly")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/session/preauth":
            want = str(obj.get("pending_role") or "player")
            nsid, sess = create_session("preauth-%d" % _next_counter(), role="player",
                                        pending_role=want)
            body = json.dumps({
                "sid": nsid,
                "role": sess["role"],
                "pending_role": want,
                "note": "role preference recorded for the next /api/login",
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("set-cookie", f"sid={nsid}; Path=/; HttpOnly")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        return self._json(404, {"error": "not found", "path": path})


def _self_check():
    """The two claims the lab rests on: the admin id is derivable, and a
    pre-auth role survives into the real session."""
    global _counter
    _counter = 0
    SESSIONS.clear()
    _boot_accounts()
    admin_sid = new_session_id(1)
    assert SESSIONS[admin_sid]["role"] == "admin", "admin id not at counter 1"
    print(f"[self-check] admin session at counter 1 -> {admin_sid}")

    _counter = 0
    SESSIONS.clear()
    create_session("maze-bot-admin", role="admin")
    carrier = create_session("pre", role="player", pending_role="admin")[0]
    nsid, sess = create_session("p", role="admin", pending_role="admin")
    assert sess["role"] == "admin" and SESSIONS[carrier]["pending_role"] == "admin"
    print("[self-check] preauth pending_role survives into the real session")


def main():
    if os.environ.get("W0B_SELFCHECK") == "1":
        _self_check()
        return
    _boot_accounts()
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
