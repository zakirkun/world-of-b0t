#!/usr/bin/env bash
# w21 re-vault :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30021
#   ./probe.sh http://host:port
#
# Asserts BOTH directions: the exploit path works (binary downloadable, blob
# extractable, inversion accepted) AND the reject paths hold (wrong key -> 403,
# malformed key -> 400). If a wrong key were ever accepted the lab would be
# broken, so that direction is checked explicitly.
set -uo pipefail

BASE="${1:-http://localhost:30021}"
fail=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

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

check "landing page serves"       "RE VAULT" "$(curl -s "$BASE/")"
check "meta lab tag present"      'content="w21"' "$(curl -s "$BASE/")"
check "health names the lab"      '"lab":"w21"' "$(curl -s "$BASE/api/health")"

# The RE artifact is downloadable and carries the blob.
http=$(curl -s -o "$work/re-vault" -w '%{http_code}' "$BASE/re-vault-linux")
if [[ "$http" == "200" && -s "$work/re-vault" ]]; then
  printf '  ok   binary downloadable (%s bytes)\n' "$(wc -c < "$work/re-vault")"
else
  printf '  FAIL binary not downloadable (http %s)\n' "$http"
  fail=1
fi

blob=$(strings "$work/re-vault" 2>/dev/null | grep -Eo '[a-f]{32}' | head -1)
if [[ -n "$blob" ]]; then
  printf '  ok   blob extractable via strings: %s\n' "$blob"
else
  printf '  FAIL no 32-hex blob in the shipped binary\n'
  fail=1
fi

# Symbols intact (-w, not -s): main.* names must be readable, so the
# objdump path the writeup documents actually works.
check "symbols intact in shipped binary" 'main.checkLicense' "$(strings "$work/re-vault" | grep -E '^main\.')"

# Reject path 1: well-formed but wrong key.
check "wrong key rejected with 403" 'invalid license' "$(curl -s "$BASE/api/validate?key=00000000000000000000000000000000")"
refute "wrong key leaks no flag" 'hex4b0t{' "$(curl -s "$BASE/api/validate?key=00000000000000000000000000000000")"

# Reject path 2: malformed key (wrong length).
check "malformed key rejected with 400" '32 hex' "$(curl -s "$BASE/api/validate?key=deadbeef")"

# Exploit path: invert the blob back to the license.
key=""
for ((i=0;i<16;i++)); do
  b=$(( 16#${blob:i*2:2} ))
  b=$(( ((b - i) & 0xFF) ^ 0x5A ))
  key+=$(printf '%02x' "$b")
done
check "derived key accepted" '"ok":true' "$(curl -s "$BASE/api/validate?key=$key")"
check "derived key yields the flag" 'hex4b0t{' "$(curl -s "$BASE/api/validate?key=$key")"

# The key itself must not ship in the binary. grep -a: the ELF is binary data
# and grep must not bail or mangle it; a plain substring test on the raw bytes.
if grep -aqF "$key" "$work/re-vault"; then
  printf '  FAIL license key present in shipped binary\n'
  fail=1
else
  printf '  ok   license key absent from binary\n'
fi

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w21 solvable and reject paths intact\n'
else
  printf '\n[!] w21 probe FAILED\n'
fi
exit $fail
