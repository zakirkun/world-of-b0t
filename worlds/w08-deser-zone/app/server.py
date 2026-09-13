"""DESER ZONE :: player-preference store for the zone dashboard.

World Of B0t challenge 08
Category: Pwn | Difficulty: hard | Vuln: Insecure deserialization

The dashboard keeps your player profile in the `dz_profile` cookie. The cookie
is the session: the server url-safe-base64-decodes it and hands the bytes to
json.loads() *with an object_hook*, then rebuilds whatever class the document
names. The hook was added so profiles could round-trip typed objects without a
lookup table - it evaluates `__class__` and calls it with `args`.

--------------------------------------------------------------------------
profile = json.loads(raw, object_hook=_revive)          # <- the deserializer
...
    cls = eval(spec["__class__"], _ZONE_TYPES)          # <- and the gadget
    return cls(*spec.get("args", ()))                   # <- called at load time
--------------------------------------------------------------------------

The class namespace is private (`_ZONE_TYPES`) but the evaluator is not
sandboxed, so a document can reach past it with normal dunder crawling. A class
whose constructor runs a shell does the work the moment the profile is revived.

GET  /                     landing page (profile is public: no flag here)
GET  /api/health           liveness + serializer
GET  /api/profile          echoes your revived profile as JSON (dz_profile=...)
GET  /api/zone             zone status, intentionally opaque
"""

import base64
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LAB = "w08"
SERVICE = "deser-zone"
VERSION = "1.08.0"
COOKIE = "dz_profile"
START = time.time()

# The secret the zone refuses to hand over directly. Read from the environment
# at boot so nothing is baked into the image layer.
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")


class PlayerProfile:
    """The user's dashboard state.

    Anything the deserializer hands back is treated like one of these, which is
    how a payload's constructor output reaches the response body.
    """

    def __init__(self, user="guest", theme="cyberpunk", messages=None):
        self.user = user
        self.theme = theme
        self.messages = list(messages or ["zone: sealed"])


# The class namespace the profile deserializer resolves names against. Private,
# but only private by convention.
_ZONE_TYPES = {"PlayerProfile": PlayerProfile}

DEFAULT_PROFILE = PlayerProfile(user="guest", messages=["zone: sealed"])


def _revive(spec):
    """object_hook: rebuild the class this JSON object names.

    This is the interesting part of the profile format. The dashboard was
    written to accept typed objects, so a document can name its own class and
    carry constructor arguments - and the hook runs during json.loads(), as
    each object is completed.
    """
    if not isinstance(spec, dict) or "__class__" not in spec:
        return spec
    name = spec["__class__"]
    try:
        # --- the bug ------------------------------------------------------
        # ponytail: eval over the type table "keeps the format flexible"; a
        # dict lookup (_ZONE_TYPES.get) is the ceiling-free fix, plus signing
        # the cookie. Ship the hook as-is only for the lab.
        cls = eval(str(name), _ZONE_TYPES)
        return cls(*spec.get("args", ()))
        # ------------------------------------------------------------------
    except Exception as exc:  # unknown class -> leave the raw document
        return {"__class__": name, "error": f"{type(exc).__name__}: {exc}",
                "doc": spec}


def _encode(profile):
    """Cookie form: urlsafe-base64(json(profile))."""
    doc = {"__class__": "PlayerProfile",
           "args": [profile.user, profile.theme, list(profile.messages)]}
    raw = json.dumps(doc).encode()
    return base64.urlsafe_b64encode(raw).decode()


# A real, valid cookie minted at boot so the service demonstrably works.
DEFAULT_COOKIE = _encode(DEFAULT_PROFILE)


def _describe(profile):
    """Render the revived profile back to the caller.

    Duck-typed on purpose: whatever object the deserializer produced is
    reflected here, so a payload that runs a command and returns its output
    sees that output in the response.
    """
    def field(name, default):
        if isinstance(profile, dict):
            return profile.get(name, default)
        return getattr(profile, name, default)

    messages = field("messages", [])
    # A payload that returns a bare string (exec, subprocess output...) has no
    # `messages`, so surface it directly rather than dropping it.
    if isinstance(profile, (str, bytes)):
        messages = [profile]
    elif hasattr(profile, "read"):  # file objects, e.g. os.popen
        messages = [profile.read()]
    return {
        "user": field("user", "guest"),
        "theme": field("theme", "cyberpunk"),
        "messages": [str(m) for m in messages],
    }


def _shows_flag(strings):
    """Sanity guard for the self-check only - never used on the request path."""
    return any("hex4b0t{" in s for s in strings)


def _self_check():
    """Import-time proof that the lab works end to end.

    A benign cookie must revive, and a hostile one must execute. If either half
    breaks, the container refuses to start rather than shipping a lab that
    cannot be solved (or cannot be used).
    """
    # 1. Benign round-trip (the boot-minted cookie shown on the landing page).
    profile = json.loads(base64.urlsafe_b64decode(DEFAULT_COOKIE), object_hook=_revive)
    assert isinstance(profile, PlayerProfile), type(profile)
    assert profile.messages == ["zone: sealed"], profile.messages

    # 1b. A plain wire-format dict also renders - the handler duck-types it.
    plain = json.loads('{"user":"guest","messages":["zone: sealed"]}', object_hook=_revive)
    assert _describe(plain)["messages"] == ["zone: sealed"]

    # 2. The gadget: a document names its own class and eval resolves the
    #    callable, which is called with `args` during json.loads().
    evil = json.dumps({"__class__": "__import__('os').popen",
                       "args": ["echo hex4b0t{selfcheck}"]})
    obj = json.loads(evil, object_hook=_revive)
    assert _shows_flag([obj.read()]), "object_hook gadget did not execute"

    # 3. The flag is present in the process (the only way it was ever reachable).
    assert FLAG, "W0B_FLAG was not injected"
    return True


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w08">
<title>DESER ZONE</title>
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
  .sealed {{ color:#ff2e97; }}
</style>
<h1>DESER ZONE</h1>
<div class="sub">{service} v{version} :: stateless profile store</div>

<section>
  <p>The zone dashboard keeps your player profile in the
  <code>{cookie}</code> cookie, so the box stays stateless. The server decodes
  the cookie and rebuilds your profile from it - typed objects included, so a
  document may name its own <code>__class__</code> and hand it
  <code>args</code>.</p>

<pre>profile = json.loads(b64decode(cookie["{cookie}"]), object_hook=_revive)
# _revive: cls = eval(doc["__class__"], _ZONE_TYPES)
#          return cls(*doc.get("args", ()))</pre>

  <p>A freshly minted profile, so you can see the shape of the thing:</p>
<pre>{default_cookie}</pre>

  <table>
    <tr><th>method</th><th>path</th><th>returns</th></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness</td></tr>
    <tr><td>GET</td><td><code>/api/profile</code></td><td>your revived profile</td></tr>
    <tr><td>GET</td><td><code>/api/zone</code></td><td>zone status: <span class="sealed">sealed</span></td></tr>
  </table>

  <p>The zone itself is sealed independently of your profile. There is no route
  that opens it - <code>GET /api/zone</code> only ever reports
  <span class="sealed">zone: sealed</span>.</p>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "deserzone/" + VERSION

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

    def _profile(self):
        """Rebuild the caller's profile from the cookie.

        The cookie is the profile: it is decoded and deserialized with no
        integrity check of any kind, because the original author thought a
        class name in a JSON document was just a class name.
        """
        cookie = self._cookie(COOKIE)
        if not cookie:
            return PlayerProfile(), False
        try:
            raw = base64.urlsafe_b64decode(cookie + "=" * (-len(cookie) % 4))
        except Exception:
            return PlayerProfile(), False
        # --- the bug -----------------------------------------------------
        profile = json.loads(raw, object_hook=_revive)
        # -----------------------------------------------------------------
        return profile, True

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
                "profile_cookie": COOKIE,
                "serializer": "json+object_hook",
                "uptime": int(time.time() - START),
            })

        if path == "/api/zone":
            # Deliberately opaque: the zone never leaves this process.
            return self._json(200, {
                "zone": "sealed",
                "note": "the zone is not a profile field and no route opens it",
            })

        if path == "/api/profile":
            profile, provided = self._profile()
            try:
                described = _describe(profile)
            except Exception as exc:
                described = {"error": f"{type(exc).__name__}: {exc}"}
            return self._json(200, {"cookie_present": provided, "profile": described})

        return self._json(404, {"error": "not found", "path": path})


def main():
    if os.environ.get("W0B_SELFCHECK") == "1":
        _self_check()
        print("[self-check] benign profile revives, gadget executes")
        return
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
