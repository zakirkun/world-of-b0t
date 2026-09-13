#!/usr/bin/env bash
# w15 rate-gauntlet :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30015
#   ./probe.sh http://host:port
#
# Asserts three things, in order:
#   1. the landing page serves and advertises the limit;
#   2. a SINGLE sequential redeem is denied once the limit is reached - i.e.
#      the limit is real and the app is not simply missing one;
#   3. a concurrent burst blows past the limit and returns the flag.
# Step 2 is what makes this a race lab instead of a "limit absent" lab: the
# same account is refused sequentially and granted concurrently.
set -uo pipefail

BASE="${1:-http://localhost:30015}"
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

printf '[*] target %s\n' "$BASE"

# 1. Landing serves and names the lab.
LANDING=$(curl -s "$BASE/")
check "landing serves the lab" 'w15' "$LANDING"
check "health reports limit + window" '"limit": 3' "$(curl -s "$BASE/api/health")"

# 2. Sequential redemptions: the first LIMIT succeed, the next is DENIED.
#    Proves the limit is enforced on the honest path.
SEQ_ACCOUNT="seq-$$"
DENIED=""
for i in 1 2 3 4; do
  RESP=$(curl -s -X POST "$BASE/api/redeem" \
         -H 'content-type: application/json' \
         -d "{\"account\":\"$SEQ_ACCOUNT\"}")
  if [[ "$RESP" == *'"denied"'* ]]; then
    DENIED="$RESP"
    printf '  ok   sequential request #%d refused (limit is real)\n' "$i"
    break
  fi
done
if [[ -z "$DENIED" ]]; then
  printf '  FAIL a sequential request past the limit was never denied\n'
  fail=1
fi
if [[ "$DENIED" == *'"flag"'* ]]; then
  printf '  FAIL the honest sequential path returned the flag\n'
  fail=1
else
  printf '  ok   sequential response carries no flag\n'
fi

# 3. Concurrent burst: same account, many parallel requests -> flag.
BURST=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null)
FLAG=$(printf '%s' "$BURST" | grep -o 'hex4b0t{[^}]*}' | head -1)
check "burst wins the race"  'hex4b0t{' "$FLAG"
check "burst reports over-limit" 'over-limit' "$BURST"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w15 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w15 probe FAILED\n'
fi
exit $fail
