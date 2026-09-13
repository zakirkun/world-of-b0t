#!/usr/bin/env bash
# w09 rate-limit-ghost :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30009
#   ./probe.sh http://host:port
#
# Asserts three things, in order:
#   1. the landing page serves and the stack reports a reachable Redis store;
#   2. a SINGLE client sending LIMIT+1 sequential requests is refused on the
#      request past the limit - i.e. the limiter is real and not simply absent;
#   3. a concurrent burst blows past the limit and returns the flag.
# Step 2 is what makes this a race lab instead of a "limit absent" lab: the same
# client is refused sequentially and granted concurrently.
#
# Idempotent: every stage resets its own client's key first (POST /api/reset),
# so re-running never depends on a leftover window.
set -uo pipefail

BASE="${1:-http://localhost:30009}"
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

post() { curl -s -X POST "$BASE$1" -H 'content-type: application/json' -d "$2"; }

printf '[*] target %s\n' "$BASE"

# 1. Landing serves and the stack is wired to Redis.
check "landing serves the lab"     'w09'   "$(curl -s "$BASE/")"
check "health reports the policy"  '"limit":5' "$(curl -s "$BASE/api/health")"
check "health sees redis"          '(up)'  "$(curl -s "$BASE/api/health")"

# 2. Sequential requests: the first LIMIT are served, the next is REFUSED.
#    Proves the limiter is enforced on the honest path.
#
#    The batch must come from ONE client process: the window is 500 ms and the
#    handler parks ~400 ms of it, so the gap between one request's INCRBY and
#    the next request's GET has to stay small. Spawning a separate curl per
#    request costs more than the whole window on Windows and the counter would
#    expire between calls - that is a probe artifact, not a limiter pass.
SEQ_CLIENT="seq-$$"
post /api/reset "{\"client\":\"$SEQ_CLIENT\"}" >/dev/null
SEQOUT="$(python - "$BASE" "$SEQ_CLIENT" <<'PY'
import json, sys, urllib.error, urllib.request
base, client = sys.argv[1], sys.argv[2]
for i in range(1, 7):
    req = urllib.request.Request(
        base + "/api/request",
        data=json.dumps({"client": client}).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.load(r)
    except urllib.error.HTTPError as e:
        # 429 IS the refusal we may be looking for - read it, don't raise.
        body = json.load(e)
    print(f"request {i}: {body.get('status')} flag={'flag' in body}")
PY
)"
printf '%s\n' "$SEQOUT" | sed 's/^/       /'
if printf '%s' "$SEQOUT" | grep -q 'request 6: rate_limited'; then
  printf '  ok   sequential request #6 refused (limiter is real)\n'
else
  printf '  FAIL a sequential request past the limit was never refused\n'
  fail=1
fi
if printf '%s' "$SEQOUT" | grep -q 'flag=True'; then
  printf '  FAIL the honest sequential path returned the flag\n'
  fail=1
else
  printf '  ok   sequential responses carry no flag\n'
fi

# 3. Concurrent burst: same client, many parallel requests -> flag.
BURST=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null)
FLAG=$(printf '%s' "$BURST" | grep -o 'hex4b0t{[^}]*}' | head -1)
check "burst beats the limiter" 'hex4b0t{' "$FLAG"
check "burst reports over-limit" 'over-limit' "$BURST"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w09 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w09 probe FAILED\n'
fi
exit $fail
