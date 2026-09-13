#!/usr/bin/env bash
# w18 grid-maze :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30018
#   ./probe.sh http://host:port
#
# Asserts the lab is solvable AND that the guard is still doing something: a
# plain player session must be refused at /api/flag, or a broken role check
# would silently make the lab trivial.
set -uo pipefail

BASE="${1:-http://localhost:30018}"
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

get() { curl -s "$BASE$1"; }

printf '[*] target %s\n' "$BASE"

check "landing page serves"        "GRID MAZE"  "$(get /)"
check "health leaks the seed"      "session_seed" "$(get /api/health)"
check "health names the id scheme" "md5"        "$(get /api/health)"

# The guard must be real: an ordinary player session is refused the flag.
PLAYER_SID=$(curl -s -X POST "$BASE/api/login" -H 'content-type: application/json' \
             -d '{"user":"probe"}' | python -c 'import json,sys;print(json.load(sys.stdin)["sid"])')
check "player session is refused"  "admin grid" \
  "$(curl -s "$BASE/api/flag?sid=$PLAYER_SID")"

# The derivation: the admin account is at counter 1, seeded from the public
# session_seed. No brute force - the counter is computable.
FLAG=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null | grep -o 'hex4b0t{[^}]*}' | head -1)
check "derived admin id reads the flag" 'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w18 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w18 probe FAILED\n'
fi
exit $fail
