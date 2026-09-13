#!/usr/bin/env bash
# w14 pickle-vault :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30014
#   ./probe.sh http://host:port
#
# Asserts the service is up, that a *benign* cookie still deserializes (so the
# env is genuinely a pickle store and not a false positive), and that the
# malicious cookie executes code and puts the flag in the HTTP response.
set -uo pipefail

BASE="${1:-http://localhost:30014}"
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

# 1. Landing page and liveness.
check "landing page serves"       "PICKLE VAULT" "$(get /)"
check "health advertises the lab" '"lab": "w14"' "$(get /api/health)"
check "health names pickle"       '"serializer": "pickle"' "$(get /api/health)"

# 2. The obvious route must NOT hand over the flag - it is a locked vault.
check "vault reports locked"      '"vault": "locked"' "$(get /api/vault)"
if get /api/vault | grep -q 'hex4b0t{'; then
  printf '  FAIL /api/vault leaks the flag directly\n'
  fail=1
else
  printf '  ok   /api/vault does not leak the flag\n'
fi

# 3. No false positive: a plain, honest session must still deserialize.
#    If this fails the service is broken, not "secure". A dict is used so the
#    payload resolves without a helper module.
BENIGN=$(python - "$BASE" <<'PY'
import base64, json, pickle, sys, urllib.request
base = sys.argv[1]
cookie = base64.b64encode(pickle.dumps(
    {"user": "guest", "theme": "cyberpunk", "messages": ["vault: locked"]})).decode()
req = urllib.request.Request(base + "/api/session",
                             headers={"cookie": "vault_session=" + cookie})
print(json.load(urllib.request.urlopen(req, timeout=10))["session"]["messages"][0])
PY
)
check "benign cookie still deserializes" 'vault: locked' "$BENIGN"

# 4. The malicious cookie must execute. exploit.py prints the flag.
FLAG=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null | grep -o 'hex4b0t{[^}]*}' | head -1)
check "REDUCE gadget recovers the flag" 'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w14 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w14 probe FAILED\n'
fi
exit $fail
