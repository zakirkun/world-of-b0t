#!/usr/bin/env bash
# w23 dossier-trace :: self-verifying probe.
#
#   ./probe.sh                       # http://localhost:30023
#   ./probe.sh http://host:port
#
# Asserts BOTH directions:
#   vuln side  — every artifact serves, the derivation from public data yields
#                the glyph code, and the glyph route returns the flag;
#   guard side — the flag appears nowhere on the plain surface, unknown
#                boards/glyphs are 404, and there is no shortcut route.
#
# Idempotent: every request is a GET; nothing mutates; re-running always green.
set -uo pipefail

BASE="${1:-http://localhost:30023}"
fail=0

check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected to contain: %s\n       got: %s\n' "$1" "$2" "$3"
    fail=1
  fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$BASE$1"; }

printf '[*] target %s\n' "$BASE"

# --- vuln side -------------------------------------------------------------

# 1. Classic OSINT surface is real.
check "landing serves the lab"        'w23'          "$(curl -s "$BASE/")"
check "robots disallows /archive/"    'Disallow: /archive/'  "$(curl -s "$BASE/robots.txt")"
check "robots disallows /hr/"         'Disallow: /hr/'       "$(curl -s "$BASE/robots.txt")"
check "security.txt present"          'Contact:'     "$(curl -s "$BASE/.well-known/security.txt")"
check "archive snapshot header"       '2019-11-02'   "$(curl -s -D - -o /dev/null "$BASE/archive/")"

# 2. The chain artifacts each hold their breadcrumb.
ARCHIVE=$(curl -s "$BASE/archive/")
check "archive names a departed badge" 'NP4471'     "$ARCHIVE"
MEMO=$(curl -s "$BASE/hr/offboarding.txt")
check "memo explains board addressing" '/board/'    "$MEMO"
BOARD=$(curl -s "$BASE/board/NP4471")
check "board post gives the derivation" 'sha256'    "$BOARD"

# 3. Derivation from PUBLIC data alone (same logic the writeup teaches) and
#    the glyph route answers.
GLYPH=$(printf '%s' 'NP4471' | sha256sum | cut -c1-8)
FLAG=$(curl -s "$BASE/glyph/$GLYPH" | grep -o 'hex4b0t{[^}]*}')
check "derived glyph returns the flag" 'hex4b0t{'  "$FLAG"

# --- guard side ------------------------------------------------------------

# 4. No page on the plain surface leaks the flag directly.
SURFACE=$(curl -s "$BASE/" ; curl -s "$BASE/robots.txt"; curl -s "$BASE/archive/"; \
          curl -s "$BASE/hr/offboarding.txt"; curl -s "$BASE/board/NP4471")
if [[ "$SURFACE" == *'hex4b0t{'* ]]; then
  printf '  FAIL a plain artifact already contains the flag\n'
  fail=1
else
  printf '  ok   no plain artifact leaks the flag\n'
fi

# 5. Unknown boards and glyphs are refused; empty badge is not the answer.
check "unknown board 404"        '404' "$(code /board/NP9999)"
check "empty board ref"          '404' "$(code /board/)"
check "unknown glyph 404"        '404' "$(code /glyph/deadbeef)"
check "bare /glyph/ 404"         '404' "$(code /glyph/)"

# 6. No shortcut: /flag and /admin style guesses stay closed.
check "no /flag shortcut"        '404' "$(code /flag)"
check "no /admin shortcut"       '404' "$(code /admin)"

# 7. Health.
check "health ok"                '"lab": "w23"' "$(curl -s "$BASE/api/health")"

if [[ $fail -eq 0 ]]; then
  printf '\n[+] w23 solvable :: %s\n' "$FLAG"
else
  printf '\n[!] w23 probe FAILED\n'
fi
exit $fail
