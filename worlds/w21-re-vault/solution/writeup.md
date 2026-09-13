# w21 RE Vault :: solution

## Root cause

The license check compares the submitted key against a constant derived from
the real key with a fixed, per-position transform - and that constant ships in
the binary, which the service itself offers for download.

`app/main.go`:

```go
// licenseBlobHex is the ONLY artifact of the real license key that ships
// in the binary. blob[i] = ((key[i] ^ 0x5A) + i) & 0xFF for i in 0..15.
// ponytail: the key itself is nowhere in the image, but the transform is
// fixed and one-byte-per-position, so the blob inverts key[i] =
// ((blob[i] - i) & 0xFF) ^ 0x5A. Any constant check embedded in a
// shipped binary has this ceiling; hashing would only move the target.
licenseBlobHex = "aaddcebadafbdacddbbbbcadeabcffef"
```

and the comparison that consumes it:

```go
// VULNERABLE: the check is a plain equality against a constant derived
// from the real key with a per-position transform. The blob is a string
// constant in this binary, so the license is recoverable offline.
blob, err := hex.DecodeString(licenseBlobHex)
if err != nil {
    return false
}
for i, b := range key {
    if ((b^0x5A)+i)&0xFF != blob[i] {
        return false
    }
}
```

The design intent is a familiar one: do not store the secret, store something
derived from it. Storing a hash is the standard move, and a hash would have
held. What was stored instead is a **bijective transform of the key itself**.
The transform XORs each byte with `0x5A` and adds the byte's index, mod 256.
Both operations are trivially invertible: XOR by un-XORing, the index addition
by subtracting the index. One byte of blob determines exactly one byte of key,
so the whole 16-byte license falls out of the 16-byte blob with no search at
all.

The second half of the problem is distribution. The landing page offers the
binary for "offline audits" - and the build is honest about what it is:

```dockerfile
# -w drops DWARF debug info; -s would also drop the symbol table. We keep the
# symbols so `go tool objdump -s 'main\.'` works on the shipped binary - the
# challenge is recovering the derivation, not fighting symbol stripping.
RUN CGO_ENABLED=0 go build -ldflags="-w" -o /re-vault .
```

`-w` strips DWARF debug info only. The Go symbol table is intact, so
`go tool objdump -s` can list and disassemble `main.checkLicense` directly.
That is the artifact's real shape: symbols intact, debug info stripped - a
normal production Go build, not an obfuscated one.

## Recon

The landing page states the validation syntax and, unusually helpfully, hands
you the audit binary:

```bash
curl -s http://localhost:30021/
# ... GET /api/validate?key=<32 hex chars> ...
# ... GET /re-vault-linux ...
```

Confirm the service is up and the reject path works:

```bash
curl -s "http://localhost:30021/api/validate?key=00000000000000000000000000000000"
# {"ok":false,"error":"invalid license"}
```

Pull the binary. This is the RE artifact and the whole challenge lives in it:

```bash
curl -s -o re-vault http://localhost:30021/re-vault-linux
file re-vault
# re-vault: ELF 64-bit LSB executable, x86-64, ..., statically linked,
# Go BuildID=..., not stripped
```

`file` says "not stripped", and that is precise: the `-w` flag dropped the
DWARF debug info (there is no DWARF section to strip, so `file` sees a
complete ELF), while the Go symbol table (`pclntab`) is intact. `strings`
immediately shows the function names:

```bash
strings re-vault | grep -E '^main\.'
# main.checkLicense
# main.handleValidate
# main.main
# ...
```

The symbol table is exactly what makes `go tool objdump` usable:

```bash
go tool objdump re-vault | grep -E '^TEXT main\.'
# TEXT main.checkLicense(SB) ...
# TEXT main.handleValidate(SB) ...
# TEXT main.main(SB) ...
```

Disassemble the check itself:

```bash
go tool objdump -s 'main\.checkLicense' re-vault
```

Among the loads you can see the XOR with a constant `0x5a`, the loop index
being added (`ADDQ CX, DI`), and the wrap - the whole derivation is visible in
a few instructions:

```text
main.go:55  0x65bef6  83f75a     XORL $0x5a, DI
main.go:55  0x65befd  4801cf     ADDQ CX, DI
```

But you do not even need the disassembly to find the blob. It is a plain
ASCII string constant, so `strings` finds it - with one catch. A bare
`[0-9a-f]{32}` match is noisy: the Go runtime ships ~100 32-character hex-ish
decoys (P-256 curve parameters, float literals) that all match. The blob is
the only candidate made entirely of the letters `a`-`f`:

```bash
strings re-vault | grep -Eo '[a-f]{32}'
# aaddcebadafbdacddbbbbcadeabcffef
```

One line, one hit. That is the blob.

## Exploit

Invert the transform. The check computed, for each position `i`:

```
blob[i] = ((key[i] ^ 0x5A) + i) & 0xFF
```

so the key is:

```
key[i] = ((blob[i] - i) & 0xFF) ^ 0x5A
```

Sixteen independent byte inversions - no search, no constraint solving:

```bash
blob=aaddcebadafbdacddbbbbcadeabcffef
key=""
for ((i=0;i<16;i++)); do
  b=$(( 16#${blob:i*2:2} ))
  b=$(( ((b - i) & 0xFF) ^ 0x5A ))
  key+=$(printf '%02x' "$b")
done
echo "$key"
# f08696ed8cac8e9c89e8e8f884f5abba
```

Submit it:

```bash
curl -s "http://localhost:30021/api/validate?key=f08696ed8cac8e9c89e8e8f884f5abba"
```

```json
{"flag":"hex4b0t{...}","ok":true}
```

`solution/exploit.sh` runs all of it - download, `strings` extraction,
inversion, submission - and prints the flag.

## The fix

There are two independent things wrong, and fixing either alone closes the
lab.

**1. Do not store an invertible transform of the secret - store a hash.** The
service never needs to recover the key; it only needs to answer "is this the
key?". A keyed or unkeyed hash does that without carrying the key anywhere:

```go
// Store this instead of the transform output:
sum := sha256.Sum256(key)
if !bytes.Equal(sum[:], licenseHash) {
    return false
}
```

SHA-256 is one-way, so the stored 32 bytes no longer determine the key.
Prefer HMAC with a server-side pepper (`hmac.New(sha256.New, pepper)`) so an
offline brute-force of weak keys is also off the table. The comparison stays
`bytes.Equal`/`hmac.Equal` - constant-time - rather than `string ==`.

**2. Do not ship the checking binary with the constant in it.** "Offline
audits" is the joke, but the serious version of the fix is the same rule
password systems learned decades ago: the verifier either runs where the
secret lives, or carries a one-way commitment to it - never a
transform-reversal of it. If the binary must ship, ship the hash, not the
blob.

The general lesson: **XOR and index arithmetic are encoding, not
cryptography.** Any transform where each output byte depends on exactly one
input byte through an invertible function is a substitution table, and a
substitution table plus the ciphertext is the plaintext. If the stored
constant lets you reconstruct the secret with a 16-iteration loop, it is the
secret.

## Flag

Injected at runtime via `W0B_FLAG`. The binary embeds only the blob; the flag
never appears in it (`strings re-vault | grep hex4b0t` shows the fallback
placeholder only).

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
