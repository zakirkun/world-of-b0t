#!/usr/bin/env bash
# w11 edge-shift :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30011
#   ./probe.sh http://host:port
#
# Asserts the bypass works AND that the gateway's own rules still do their job.
# An over-broad guard would silently make the lab unsolvable, so both directions
# are checked.
set -uo pipefail

BASE="${1:-http://localhost:30011}"
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

g() { curl -s --path-as-is "$BASE$1"; }

printf '[*] target %s\n' "$BASE"

# 1. The gateway is up and forwards.
check "landing page serves"           "EDGE SHIFT"  "$(g /)"
check "health names the public prefix" '/api/v1'    "$(g /api/health)"
check "legit versioned route forwards" 'nominal'    "$(g /api/v1/status)"

# 2. The guards the gateway advertises must genuinely fire - otherwise the lab
#    would be solvable by the trivial payload and there would be nothing to find.
check  "gateway blocks a .. segment"      'contains a .. path segment' "$(g '/api/v1/../admin/secret')"
check  "gateway blocks an encoded dot"    'contains %2e'              "$(g '/api/v1/%2e%2e%2fadmin%2fsecret')"

# 3. The admin route must NOT be reachable by its plain name through the edge,
#    and the flat-resource rule must genuinely refuse it.
refute "plain admin route is not exposed" 'hex4b0t{' "$(g '/api/v1/admin/secret')"
check  "flat-resource rule refuses nested paths" 'flat' "$(g '/api/v1/admin/secret')"
check  "flat-resource rule refuses deeper nesting" 'flat' "$(g '/api/v1/x/y/z')"

# 4. The bypass.
check "encoded-slash traversal reaches the flag" 'hex4b0t{' "$(g '/api/v1/..%2fadmin%2fsecret')"

# 5. The origin holds the flag and is not published to the host - the gateway is
#    the only route in.
if curl -s -m 3 -o /dev/null "http://localhost:9000/status" 2>/dev/null; then
  printf '  FAIL origin is reachable from the host directly (no host port expected)\n'
  fail=1
else
  printf '  ok   origin has no host port (gateway is the only route)\n'
fi

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w11 solvable and gateway rules intact\n'
else
  printf '\n[!] w11 probe FAILED\n'
fi
exit $fail
