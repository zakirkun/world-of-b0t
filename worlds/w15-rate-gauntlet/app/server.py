"""RATE GAUNTLET :: a coupon redemption desk.

World Of B0t challenge 15
Category: DevOpsSec | Difficulty: easy | Vuln: TOCTOU race on a redemption limit

The service redeems coupons for an account. The business rule is simple: each
account may redeem a coupon at most LIMIT times. The implementation is the
classic check-then-act:

    count = SELECT COUNT(*) FROM redemptions WHERE account = ?   <-- check
    time.sleep(0.4)                                             <-- window
    INSERT INTO redemptions ...                                  <-- act

The check and the act are two separate statements on two separate connections,
with no transaction and no constraint holding them together. Every concurrent
request reads the same pre-insert count and concludes it is still under the
limit, so N parallel requests all pass the check and all insert. The limit is
enforced nowhere except in that one racy read.

Rediscovering a count *after* the insert is the only thing that notices, and it
is what hands out the flag once the account exceeds LIMIT.

--------------------------------------------------------------------------
GET  /                landing page + redeem form
POST /api/redeem      {"account": "..."} or form field account=...
GET  /api/state       ?account=... -> current redemption count
GET  /api/health      liveness
--------------------------------------------------------------------------
"""

import json
import os
import sqlite3
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LAB = "w15"
SERVICE = "rate-gauntlet"
VERSION = "1.15.0"
START = time.time()

# The secret, read from the environment at boot so nothing is baked into the
# image layer.
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

# Per-boot scratch database. tmpfs-ish: it lives for the container's lifetime.
DB_PATH = "/tmp/gauntlet.db"

# Business rule: at most this many redemptions per account.
LIMIT = 3

# ponytail: the deliberate TOCTOU window. It exists so the race is
# deterministic regardless of core count - the loser of the race has to still
# be inside the window when the winner commits, which a sleep guarantees and a
# scheduler-dependent instruction gap does not. See the writeup.
WINDOW_MS = 400


def _db():
    """A fresh connection every call.

    isolation_level=None means autocommit: no implicit transaction is opened,
    so the absent BEGIN IMMEDIATE below really is absent. A stale connection
    must never be reused across requests.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5.0, check_same_thread=False)
    conn.isolation_level = None  # autocommit - no BEGIN IMMEDIATE anywhere
    return conn


def _init():
    conn = _db()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS redemptions ("
            "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  account TEXT NOT NULL,"
            "  coupon TEXT NOT NULL,"
            "  ts REAL NOT NULL)"
        )
    finally:
        conn.close()


def _redemption(account, coupon):
    """The redeem flow. This function is the vulnerability.

    There is a SELECT, a sleep, and an INSERT, and nothing binds them.
    """
    conn = _db()
    try:
        # --- check -----------------------------------------------------------
        row = conn.execute(
            "SELECT COUNT(*) FROM redemptions WHERE account = ?", (account,)
        ).fetchone()
        count = row[0]

        if count >= LIMIT:
            return {"ok": False, "status": "denied", "account": account,
                    "used": count, "limit": LIMIT,
                    "message": f"coupon limit reached ({count}/{LIMIT})"}

        # ponytail: deliberate TOCTOU window, makes the race deterministic.
        # The count above is already stale by the time we come back, and no
        # lock or transaction covers the gap, so every concurrent caller sees
        # the same pre-insert count.
        time.sleep(WINDOW_MS / 1000.0)

        # --- act -------------------------------------------------------------
        conn.execute(
            "INSERT INTO redemptions (account, coupon, ts) VALUES (?, ?, ?)",
            (account, coupon, time.time()),
        )

        # Count AFTER the insert. This is the only place the overrun is
        # observable, and where the prize is handed out.
        after = conn.execute(
            "SELECT COUNT(*) FROM redemptions WHERE account = ?", (account,)
        ).fetchone()[0]
    finally:
        conn.close()

    resp = {
        "ok": True,
        "status": "redeemed",
        "account": account,
        "coupon": coupon,
        "used": after,
        "limit": LIMIT,
    }
    if after > LIMIT:
        # The limit was blown: someone raced. Pay out.
        resp["status"] = "limit_exceeded"
        resp["message"] = (
            f"{after} redemptions on an account limited to {LIMIT} - "
            "the check-then-act race won"
        )
        resp["flag"] = FLAG
    return resp


def _count(account):
    conn = _db()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM redemptions WHERE account = ?", (account,)
        ).fetchone()[0]
    finally:
        conn.close()


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w15">
<title>RATE GAUNTLET</title>
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
  input,button {{ background:#05050c; color:#c8d6e5; border:1px solid #1b2340; font:inherit; padding:6px 8px; }}
  button {{ color:#00f0ff; border-color:#00f0ff; cursor:pointer; }}
  .warn {{ color:#ff2e97; }}
</style>
<h1>RATE GAUNTLET</h1>
<div class="sub">{service} v{version} :: coupon redemption desk</div>

<section>
  <p>Every account gets <code>{limit}</code> coupon redemptions. The desk checks
  how many you have used, then records the redemption. It is honest about the
  policy and it will not let you past it &mdash; one request at a time.</p>

  <form method="POST" action="/api/redeem" accept-charset="utf-8">
    <input name="account" value="alice" size="20" aria-label="account">
    <button type="submit">redeem coupon</button>
  </form>

  <table>
    <tr><th>method</th><th>path</th><th>body</th></tr>
    <tr><td>POST</td><td><code>/api/redeem</code></td><td><code>{{"account":"&lt;name&gt;"}}</code> or <code>account=&lt;name&gt;</code></td></tr>
    <tr><td>GET</td><td><code>/api/state?account=&lt;name&gt;</code></td><td>current redemption count</td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness + limit</td></tr>
  </table>

  <p>The desk is single-minded: it counts, it pauses, it writes. Ask it the same
  question more than once at the same time and it will answer every one of them
  with the same stale count.</p>

  <p class="warn">Any account that ends up over the limit is flagged for review,
  and the review endpoint pays out.</p>
</section>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "rategauntlet/" + VERSION

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
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else {}
        except ValueError:
            # Accept form encoding too, so the lab is usable from a browser.
            return {k: v[0] for k, v in
                    parse_qs(raw.decode("utf-8", "replace")).items()}

    @staticmethod
    def _account(obj):
        acct = str(obj.get("account", "")).strip()
        if not acct or len(acct) > 64:
            return None
        return "".join(c for c in acct if c.isalnum() or c in "-_.")

    def log_message(self, fmt, *args):
        # Keep the container log quiet; the launcher owns the interesting output.
        pass

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path

        if path == "/":
            return self._html(200, LANDING.format(
                service=SERVICE, version=VERSION, limit=LIMIT))

        if path == "/api/health":
            return self._json(200, {
                "service": SERVICE,
                "lab": LAB,
                "version": VERSION,
                "limit": LIMIT,
                "window_ms": WINDOW_MS,
                "concurrency": "ThreadingHTTPServer",
                "uptime": int(time.time() - START),
            })

        if path == "/api/state":
            account = (parse_qs(u.query).get("account") or [""])[0].strip()
            if not account:
                return self._json(400, {"error": "missing query param: account"})
            used = _count(account)
            return self._json(200, {
                "account": account,
                "used": used,
                "limit": LIMIT,
                "remaining": max(0, LIMIT - used),
                "over_limit": used > LIMIT,
            })

        return self._json(404, {"error": "not found", "path": path})

    def do_POST(self):
        path = urlparse(self.path).path
        obj = self._body()

        if path == "/api/redeem":
            account = self._account(obj)
            if not account:
                return self._json(400, {"error": "missing or invalid field: account"})
            result = _redemption(account, uuid.uuid4().hex[:8])
            code = 200 if result.get("ok") else 429
            return self._json(code, result)

        return self._json(404, {"error": "not found", "path": path})


def main():
    _init()
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"{SERVICE} v{VERSION} listening on :{port} (lab {LAB}, limit {LIMIT})",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
