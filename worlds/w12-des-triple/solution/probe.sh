#!/usr/bin/env bash
# w12 des-triple :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30012
#   ./probe.sh http://host:port
#
# Asserts the crypto primitives behave (the lab's own correctness guarantee),
# that the v2 construction really collapses under a semi-weak pair, and that the
# flag comes out. A wrong DES implementation would make the lab unsolvable while
# looking fine, so the primitive check runs first.
set -uo pipefail

BASE="${1:-http://localhost:30012}"
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE/../app"
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

# 1. Primitive correctness: NIST vector + all six semi-weak pairs.
if python "$APP/des.py" >/dev/null 2>&1; then
  printf '  ok   des.py self-check (NIST KAT + 6 semi-weak pairs)\n'
else
  printf '  FAIL des.py self-check failed\n'
  fail=1
fi

# 2. Service is up and advertises the published key material.
check "health reports ECB / 8-byte blocks" '"mode": "ECB"' "$(curl -s "$BASE/api/health")"
check "keys endpoint ships semi-weak pairs" 'semi_weak_pairs' "$(curl -s "$BASE/api/keys")"

# 3. The collapse: v2 must equal v1 when the supplied pair is semi-weak.
COLLAPSE=$(python - "$BASE" <<'PY'
import json, sys, urllib.request
base = sys.argv[1]
def post(p, b):
    r = urllib.request.Request(base + p, data=json.dumps(b).encode(),
                               headers={"content-type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=10))
pair = json.load(urllib.request.urlopen(base + "/api/keys", timeout=10))["semi_weak_pairs"][0]
x = "41" * 8
v1 = post("/api/v1/encrypt", {"data": x})["ciphertext"]
v2 = post("/api/v2/encrypt", {"data": x, "k2": pair["a"], "k3": pair["b"]})["ciphertext"]
print("COLLAPSED" if v1 == v2 else "DIVERGED")
PY
)
check "v2 collapses to v1 under a semi-weak pair" 'COLLAPSED' "$COLLAPSE"

# 4. The vault is actually sealed and reachable as ciphertext.
check "vault exposes ciphertext" '"vault": "sealed"' "$(curl -s "$BASE/api/vault")"
check "vault open route is refused"  'master key'          "$(curl -s -X POST "$BASE/api/vault/open" -d '{}')"

# 5. End to end: recover the flag.
FLAG=$(python "$HERE/recover.py" "$BASE" 2>/dev/null | grep -o 'hex4b0t{[^}]*}' | head -1)
check "oracle recovers the flag" 'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w12 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w12 probe FAILED\n'
fi
exit $fail
