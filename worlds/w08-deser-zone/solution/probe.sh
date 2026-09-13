#!/usr/bin/env bash
# w08 deser-zone :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30008
#   ./probe.sh http://host:port
#
# Asserts BOTH directions: a *benign* profile still deserializes and never
# leaks the flag (so the env is genuinely a deserializer, not a false
# positive), and the malicious profile executes code and yields the flag.
set -uo pipefail

BASE="${1:-http://localhost:30008}"
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

# 0. Wait for the listener: a fresh `up -d` binds the port a beat after the
#    container reports started, and a race here reads as a broken lab.
for _ in $(seq 1 20); do
  curl -s --max-time 2 "$BASE/api/health" | grep -q '"lab"' && break
  sleep 1
done

# 1. Landing page and liveness.
check "landing page serves"        "DESER ZONE"           "$(get /)"
check "health advertises the lab"  '"lab": "w08"'         "$(get /api/health)"
check "health names the serializer" '"json+object_hook"'  "$(get /api/health)"

# 2. The obvious route must NOT hand over the flag - the zone is sealed.
check "zone reports sealed" '"zone": "sealed"' "$(get /api/zone)"
if get /api/zone | grep -q 'hex4b0t{'; then
  printf '  FAIL /api/zone leaks the flag directly\n'
  fail=1
else
  printf '  ok   /api/zone does not leak the flag\n'
fi

# 3. No false positive: a plain, honest profile must still deserialize and must
#    come back *without* the flag. If this fails the service is broken, not
#    "secure".
BENIGN=$(python - "$BASE" <<'PY'
import base64, json, sys, urllib.request
base = sys.argv[1]
doc = {"__class__": "PlayerProfile",
       "args": ["guest", "cyberpunk", ["zone: sealed"]]}
cookie = base64.urlsafe_b64encode(json.dumps(doc).encode()).decode()
req = urllib.request.Request(base + "/api/profile",
                             headers={"cookie": "dz_profile=" + cookie})
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=10))))
PY
)
check "benign profile still deserializes" '"zone: sealed"' "$BENIGN"
if [[ "$BENIGN" == *'hex4b0t{'* ]]; then
  printf '  FAIL benign profile leaked the flag\n'
  fail=1
else
  printf '  ok   benign profile does not leak the flag\n'
fi

# 4. The malicious profile must execute. exploit.py prints the flag.
FLAG=$(python "$HERE/exploit.py" "$BASE" 2>/dev/null | grep -o 'hex4b0t{[^}]*}' | head -1)
check "object_hook gadget recovers the flag" 'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w08 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w08 probe FAILED\n'
fi
exit $fail
