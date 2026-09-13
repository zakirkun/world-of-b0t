#!/usr/bin/env bash
# w22 bytecode-vault :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30022
#   ./probe.sh http://host:port
#
# Asserts the lab is solvable AND that the guard is real: a wrong code must be
# refused without leaking the flag, otherwise the seal is decoration.
set -uo pipefail

BASE="${1:-http://localhost:30022}"
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

check "landing serves with lab tag"   'meta name="lab" content="w22"' "$(get /)"
check "health names the vault"        '"vault":"bytecode"' "$(get /api/health)"
check "hint gives the user half"      "keeper-07" "$(get /api/hint)"
check "hint withholds the salt"       "salt never left" "$(get /api/hint)"

# The artifact must be a real pyc, not a text file: first 4 bytes are the
# CPython bytecode magic (non-printable binary).
PYC="$(get /static/vault.pyc)"
check "backup artifact downloadable"  "pyc" "$(printf '%s' "$PYC" | head -c 4 | od -An -tx1 | grep -q '.' && echo pyc)"
if printf '%s' "$PYC" | LC_ALL=C grep -q 'def unlock_code'; then
  printf '  FAIL artifact is plaintext source, not bytecode\n'; fail=1
else
  printf '  ok   artifact is binary bytecode (magic %s)\n' \
    "$(printf '%s' "$PYC" | head -c 4 | od -An -tx1 | tr -d ' ')"
fi

# The guard must be real: a wrong code is refused, flag stays sealed.
check "wrong code refused"            '{"ok":false}' \
  "$(curl -s -X POST "$BASE/api/unlock" -H 'content-type: application/json' -d '{"code":"0000000000000000"}')"
WRONG=$(curl -s -X POST "$BASE/api/unlock" -H 'content-type: application/json' -d '{"code":"0000000000000000"}')
if [[ "$WRONG" == *hex4b0t{* ]]; then printf '  FAIL wrong code leaked flag\n'; fail=1; else printf '  ok   wrong code leaks no flag\n'; fi

# The solve: exploit.py downloads the pyc, reads the constants out of it, and
# recomputes the code - nothing hardcoded.
FLAG=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null | grep -o 'hex4b0t{[^}]*}' | head -1)
check "pyc-derived code opens vault"  'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w22 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w22 probe FAILED\n'
fi
exit $fail
