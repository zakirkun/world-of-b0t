# w21 :: RE Vault

- **Category:** Reverse
- **Difficulty:** medium
- **Stack:** Go (stripped binary)
- **URL:** http://localhost:30021

## Brief

RE VAULT is a license attestation service. Submit your 32-hex-character license
key and the node tells you whether it attests:

```
GET /api/validate?key=<32 hex chars>
```

The validator binary itself is downloadable for offline audits:

```
GET /re-vault-linux
```

## Goal

There is no license key. Recover a valid one and claim the flag from the
validator.

## Hint

The binary checks your key against a constant it carries. It is not the key
itself - it is one fixed transform away from it. The build keeps the symbol
table (debug info is stripped, symbols are intact), so `go tool objdump -s
'main\.checkLicense'` reads like documentation.

<details>
<summary>Spoiler</summary>

The comparison constant is a 32-hex blob visible with `strings` on the
downloaded binary:

```bash
curl -s -o re-vault http://localhost:30021/re-vault-linux
strings re-vault | grep -Eo '[a-f]{32}'
# aaddcebadafbdacddbbbbcadeabcffef
```

The derivation (recoverable from the disassembly or the string layout) is, per
byte position `i` in 0..15:

```
blob[i] = ((key[i] ^ 0x5A) + i) & 0xFF
```

Invert it per position:

```bash
blob=aaddcebadafbdacddbbbbcadeabcffef
key=""
for ((i=0;i<16;i++)); do
  b=$(( 16#${blob:i*2:2} ))
  b=$(( ((b - i) & 0xFF) ^ 0x5A ))
  key+=$(printf '%02x' "$b")
done
curl -s "http://localhost:30021/api/validate?key=$key"
# {"flag":"hex4b0t{...}","ok":true}
```

Full walkthrough in `solution/writeup.md`; `solution/probe.sh` verifies both
the exploit path and that wrong/malformed keys are rejected.

</details>
