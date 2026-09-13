# w17 :: Concat Walk

- **Category:** Web
- **Difficulty:** easy
- **Stack:** Go (stdlib)
- **URL:** http://localhost:30017

## Brief

CONCAT WALK is a static file drop. You name a file, it hands you the bytes:

```
GET /dl?f=manifest.txt
```

The drop volume also holds the operator vault, one directory above the served
root. Traversal is checked before every read.

## Goal

Read `/srv/private/flag.txt`, which lives outside the served directory.

## Hint

Two things are worth reading closely in the handler:

- how the path is **assembled** from the root and your filename, and
- exactly what shape the traversal guard rejects.

Test the guard. There is a traversal it does not consider.

<details>
<summary>Spoiler</summary>

The path is built by **concatenation**, not `filepath.Join` — so `..` segments
are never cleaned. The guard is a substring test for `/../`, which only matches
a traversal with a segment on *both* sides of the dots. A **leading** `../` has
nothing before it, so it passes:

```bash
curl --path-as-is 'http://localhost:30017/dl?f=../private/flag.txt'
# hex4b0t{...}
```

Compare against the guarded shape, which is correctly blocked:

```bash
curl --path-as-is 'http://localhost:30017/dl?f=a/../private/flag.txt'
# {"error":"traversal blocked"}
```

The payload must have **no segment before the dots** — `x/../../private/flag.txt`
is caught, because it contains the literal `/../`. URL-encoding the slash on a
leading traversal still works:

```bash
curl --path-as-is 'http://localhost:30017/dl?f=..%2fprivate%2fflag.txt'
```

Full walkthrough in `solution/writeup.md`; `solution/probe.sh` verifies both the
exploit and that the guard still blocks what it is supposed to.

</details>
