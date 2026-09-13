"""RATE LIMIT GHOST :: a distributed request throttle that does not count.

World Of B0t challenge 09
Category: DevOpsSec | Difficulty: hard | Vuln: Race condition / limit bypass

Every client gets LIMIT requests per WINDOW. The limiter lives in Redis so that
"any number of app replicas" share one counter - which is the correct design,
and the reason the lab exists. The counter is shared. The *decision* is not.

The guard reads the counter and writes it back as two separate round trips:

    used = int(r.get(key) or 0)          <-- check   (one round trip)
    time.sleep(WINDOW_MS / 1000.0)       <-- window
    r.incrby(key, 1)                     <-- act     (another round trip)

Nothing sits between them. `GET` returns a snapshot, `INCRBY` is atomic but
only against other `INCRBY`s - it cannot retroactively invalidate a check that
already read the old value. Send N requests at once and every one of them reads
the same pre-increment number: the app checks `0 < 5` N times and increments N
times, so N requests are served for a budget of 5.

The only request that "sees" the overrun is the one whose increment lands last.
That request re-reads the counter, finds it over the window budget, and pays
out the flag. One flag per window; reset the window (or use a new client id)
to try again.

--------------------------------------------------------------------------
GET  /                 landing page + live counter
POST /api/request      {"client": "..."} -> metered request
GET  /api/quota        ?client=... -> current window state
POST /api/reset        ?client=... -> clear one client's window (probe aid)
GET  /api/health       liveness, limit, window
--------------------------------------------------------------------------
"""

import json
import os
import time
import uuid

import redis
from flask import Flask, jsonify, request

LAB = "w09"
SERVICE = "rate-limit-ghost"
VERSION = "1.9.0"
START = time.time()

# Flag is injected at runtime as an env var; never baked into a layer.
FLAG = os.environ.get("W0B_FLAG", "hex4b0t{REPLACED_AT_RUNTIME}")

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

# Business rule: LIMIT metered requests per client per WINDOW.
LIMIT = 5
WINDOW_MS = 500

# ponytail: the deliberate check-then-act window. It exists so the race is
# deterministic regardless of core count - the loser has to still be inside the
# window when the winner commits, which a sleep guarantees and a
# scheduler-dependent instruction gap does not. See the writeup.
SLEEP_MS = 400

app = Flask(__name__)

# The pool is shared by every request thread; Flask's dev server threads
# requests, and redis-py's client is thread-safe.
R = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    socket_timeout=5,
    socket_connect_timeout=5,
    health_check_interval=30,
    decode_responses=True,
)


def _key(client: str) -> str:
    return f"rlghost:{client}"


def _expire(key: str) -> None:
    # ponytail: PEXPIRE, not EXPIRE - the window is sub-second, and EXPIRE only
    # takes whole seconds, so it was rounding 500ms up to 1s and letting the
    # counter die between sequential requests.
    R.pexpire(key, WINDOW_MS)


def _metered(client: str):
    """The guard. This function is the vulnerability.

    A read, a sleep, and a write, with nothing binding them into one decision.
    """
    key = _key(client)

    # --- check ---------------------------------------------------------------
    # A snapshot of the counter, taken on its own round trip to Redis.
    used = int(R.get(key) or 0)

    if used >= LIMIT:
        # Honest path. Sequential clients are refused here, every time.
        _expire(key)
        return {
            "ok": False,
            "status": "rate_limited",
            "client": client,
            "used_in_window": used,
            "limit": LIMIT,
            "window_ms": WINDOW_MS,
            "message": f"rate limit reached ({used}/{LIMIT} in the current window)",
        }

    # ponytail: deliberate check-then-act window, makes the race deterministic.
    # The `used` above is already stale when we come back, and no lock or
    # transaction covers the gap, so every concurrent caller sees the same
    # pre-increment count.
    time.sleep(SLEEP_MS / 1000.0)

    # --- act ----------------------------------------------------------------
    # Atomic on its own - but atomic against other INCRBYs only. It cannot
    # retroactively invalidate the check that already read the old value.
    after = R.incrby(key, 1)
    _expire(key)

    resp = {
        "ok": True,
        "status": "served",
        "client": client,
        "used_in_window": after,
        "limit": LIMIT,
        "window_ms": WINDOW_MS,
    }
    if after > LIMIT:
        # The window budget was blown: someone raced. Pay out, once per window.
        resp["status"] = "limit_exceeded"
        resp["message"] = (
            f"{after} requests served on a {LIMIT}-per-window budget - "
            "the check-then-increment race won"
        )
        resp["flag"] = FLAG
    return resp


def _quota(client: str):
    key = _key(client)
    used = int(R.get(key) or 0)
    return {
        "client": client,
        "used_in_window": used,
        "limit": LIMIT,
        "remaining": max(0, LIMIT - used),
        "over_limit": used > LIMIT,
        "window_ms": WINDOW_MS,
        "ttl_ms": max(0, R.pttl(key) or 0),
    }


def _client_name(raw) -> str | None:
    name = str(raw or "").strip()
    if not name or len(name) > 64:
        return None
    return "".join(c for c in name if c.isalnum() or c in "-_.") or None


LANDING = """<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w09">
<title>RATE LIMIT GHOST</title>
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
  .warn {{ color:#ff2e97; }}
</style>
<h1>RATE LIMIT GHOST</h1>
<div class="sub">{service} v{version} :: distributed request throttle</div>

<section>
  <p>The throttle is <b>shared state</b>: the counter lives in Redis, so every
  replica of this service counts into the same budget. The policy is
  <code>{limit}</code> requests per client per <code>{window_ms} ms</code> window.
  One request at a time, it is airtight.</p>

  <p>Live counter for <code>{client}</code>:
  <code>{used}</code> / <code>{limit}</code> this window.</p>

  <table>
    <tr><th>method</th><th>path</th><th>body</th></tr>
    <tr><td>POST</td><td><code>/api/request</code></td><td><code>{{"client":"&lt;id&gt;"}}</code> or <code>client=&lt;id&gt;</code></td></tr>
    <tr><td>POST</td><td><code>/api/request?reset=1</code></td><td>same, but clear the window first</td></tr>
    <tr><td>GET</td><td><code>/api/quota?client=&lt;id&gt;</code></td><td>current window state</td></tr>
    <tr><td>POST</td><td><code>/api/reset</code></td><td><code>client=&lt;id&gt;</code> - clear one window</td></tr>
    <tr><td>GET</td><td><code>/api/health</code></td><td>liveness + policy</td></tr>
  </table>

  <p>The guard reads the counter and then writes it. Between those two round
  trips there is a pause - short, but real, and the same pause lands in the same
  place for every request in flight.</p>

  <p class="warn">Any client that ends a window above its budget gets the
  throttling report, and the report is where the prize is hidden.</p>
</section>
"""


@app.get("/")
def index():
    client = "guest"
    try:
        used = int(R.get(_key(client)) or 0)
    except redis.RedisError:
        used = -1
    return LANDING.format(
        service=SERVICE, version=VERSION, limit=LIMIT,
        window_ms=WINDOW_MS, client=client, used=used,
    ), 200, {"content-type": "text/html; charset=utf-8"}


@app.get("/api/health")
def health():
    try:
        R.ping()
        store = "up"
    except redis.RedisError:
        store = "down"
    return jsonify({
        "service": SERVICE,
        "lab": LAB,
        "version": VERSION,
        "limit": LIMIT,
        "window_ms": WINDOW_MS,
        "store": f"redis://{REDIS_HOST}:{REDIS_PORT} ({store})",
        "concurrency": "flask threaded",
        "uptime": int(time.time() - START),
    })


@app.get("/api/quota")
def quota():
    client = _client_name(request.args.get("client"))
    if not client:
        return jsonify({"error": "missing query param: client"}), 400
    return jsonify(_quota(client))


@app.post("/api/reset")
def reset():
    obj = request.get_json(silent=True) or request.form.to_dict() or {}
    client = _client_name(obj.get("client") or request.args.get("client"))
    if not client:
        return jsonify({"error": "missing or invalid field: client"}), 400
    R.delete(_key(client))
    return jsonify({"ok": True, "client": client, "cleared": True})


@app.post("/api/request")
def metered():
    obj = request.get_json(silent=True) or request.form.to_dict() or {}
    client = _client_name(obj.get("client"))
    if not client:
        return jsonify({"error": "missing or invalid field: client"}), 400
    if request.args.get("reset") in ("1", "true", "yes"):
        # Probe aid: start this client's window from zero.
        R.delete(_key(client))
    result = _metered(client)
    return jsonify(result), (200 if result.get("ok") else 429)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    print(f"{SERVICE} v{VERSION} listening on :{port} "
          f"(lab {LAB}, limit {LIMIT}/{WINDOW_MS}ms, redis {REDIS_HOST}:{REDIS_PORT})",
          flush=True)
    # ponytail: threads=16 is enough for a 12-wide burst; raise it if you raise
    # the burst size past the thread pool. The sleep, not the pool, is the bug.
    app.run(host="0.0.0.0", port=port, threaded=True)
