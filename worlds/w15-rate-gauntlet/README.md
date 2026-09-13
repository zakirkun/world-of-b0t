# w15 :: Rate Gauntlet

- **Category:** DevOpsSec
- **Difficulty:** easy
- **Stack:** Python 3.12 / stdlib only (http.server + sqlite3)
- **URL:** http://localhost:30015

## Brief

RATE GAUNTLET is a coupon redemption desk. The policy is printed on the front
page: **every account may redeem at most 3 coupons**. The service is honest
about it, enforces it on every sequential request, and refuses cleanly once the
counter is spent.

The enforcement is a check-then-act in the redeem handler: it counts your
existing redemptions, then a moment later writes a new one. Between the count
and the write there is nothing holding the two together — no transaction, no
constraint, no lock.

The server is a `ThreadingHTTPServer`, so requests are handled in parallel.

## Goal

Blow past the 3-per-account limit. Any account that ends up over the limit is
paid out with the flag.

## Hint

The count you are checked against was read *before* your write. Ask the desk the
same question several times at once and every request is told the same number.

`GET /api/health` tells you the limit and how long the window is open. `GET
/api/state?account=...` shows the count.

<details>
<summary>Spoiler</summary>

One request at a time, the limit holds:

```bash
for i in 1 2 3 4; do
  curl -s -X POST http://localhost:30015/api/redeem \
    -H 'content-type: application/json' -d '{"account":"alice"}'
  echo
done
# ... redeemed x3, then {"ok":false,"status":"denied","used":3,"limit":3}
```

Fire them all at once instead. Each handler does `SELECT COUNT(*)`, then
`time.sleep(0.4)`, then `INSERT` — so every member of the burst reads the same
pre-insert count inside the same window and every one of them passes the check:

```bash
python solution/exploit.py
# [*] results: 12 over-limit, 0 denied by the check
# [+] FLAG: hex4b0t{...}
```

Whichever handler inserts last observes a post-insert count above the limit and
returns the flag.

`solution/probe.sh` asserts all of it: the landing page, that the sequential
path is still denied (so the limit is genuinely enforced and not just absent),
and that the burst wins.

</details>
