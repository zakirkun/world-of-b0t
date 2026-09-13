# w09 :: Rate Limit Ghost

- **Category:** DevOpsSec
- **Difficulty:** hard
- **Stack:** Python 3.12 / Flask + Redis
- **URL:** http://localhost:30009

## Brief

RATE LIMIT GHOST is a request throttle. The policy is printed on the front
page: **each client gets 5 requests per 500 ms window**. The counter lives in
Redis, which is the correct design — any number of app replicas share one
budget, and the service can tell you it is reaching a live store.

The enforcement is a check-then-act in the guard: it **reads** the counter from
Redis, then a moment later **increments** it. Those are two separate round
trips. Nothing binds the read to the write — no Lua script, no transaction, no
lock, no `INCR`-then-compare.

The app is served by Flask's threaded server, so requests are handled in
parallel.

## Goal

Beat the per-window budget. Any client whose window ends above the limit is
paid out with the flag.

## Hint

The counter you are checked against is read *before* your increment lands. Ask
the throttle for several requests at once and every request is told the same
pre-increment number.

`GET /api/health` gives the limit and window. `GET /api/quota?client=...` shows
the counter. `POST /api/reset` clears one client's window, so runs are
repeatable.

<details>
<summary>Spoiler</summary>

One request at a time, the limiter holds:

```bash
for i in 1 2 3 4 5 6; do
  curl -s -X POST http://localhost:30009/api/request \
    -H 'content-type: application/json' -d '{"client":"alice"}'
  echo
done
# ... served x5, then {"ok":false,"status":"rate_limited","used_in_window":5,...}
```

Fire them all at once instead. Each handler does `GET` then `time.sleep(0.4)`
then `INCRBY` — so every member of the burst reads the same pre-increment count
inside the same window and every one of them passes the check:

```bash
python solution/exploit.py
# [*] results: 14 over-limit, 0 refused by the check
# [+] FLAG: hex4b0t{...}
```

Whichever handler's `INCRBY` lands last observes a post-increment count above
the limit and returns the flag.

`solution/probe.sh` asserts all of it: the landing page, that the sequential
path is still refused (so the limiter is genuinely enforced and not just
absent), and that the burst wins.

</details>
