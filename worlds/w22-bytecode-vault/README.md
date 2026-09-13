# w22 :: Bytecode Vault

- **Category:** Graybox
- **Difficulty:** hard
- **Stack:** Python 3.12 (.pyc)
- **URL:** http://localhost:30022

## Brief

A vault holds the flag and opens for exactly one thing: the **access code**.
Present it at `POST /api/unlock` and the seal breaks.

The module that computes the code is sealed. Its source never left the build
machine — only the interpreter has ever read those lines. What did survive is
a **backup artifact**: the compiled module, mirrored at `/static/vault.pyc`
for disaster recovery. Bytecode is not source, the operators say.

## Goal

Recover the access code and read the flag from `/api/unlock`.

## Hint

`GET /api/hint` hands you one component of the input for free — the rest
"never left the build machine". But the backup artifact did. A `.pyc` is not
encrypted; it is Python's own dinner, pre-chewed. Everything the interpreter
needs to run the derivation, it keeps.

<details>
<summary>Spoiler</summary>

Download the artifact and disassemble it. The access code is
`sha256((VAULT_SALT + VAULT_USER).encode()).hexdigest()[:16]`, and both
constants ride along in the code object:

```bash
curl -s http://localhost:30022/static/vault.pyc -o vault.pyc
python - <<'EOF'
import dis, marshal
co = marshal.loads(open("vault.pyc","rb").read()[16:])
for c in co.co_consts:
    if isinstance(c, str): print(repr(c))     # salt + user, verbatim
dis.dis(co)                                    # the derivation, in opcodes
EOF
```

Recompute and present:

```bash
python -c "import hashlib; print(hashlib.sha256(('<salt>'+'keeper-07').encode()).hexdigest()[:16])"
curl -s -X POST http://localhost:30022/api/unlock \
  -H 'content-type: application/json' -d '{"code":"<16 hex>"}'
# {"ok":true,"flag":"hex4b0t{...}"}
```

`solution/exploit.py` does the whole chain — downloads the pyc, reads the
constants out of *it* (nothing hardcoded), recomputes, unlocks.
`solution/probe.sh` also asserts a wrong code is still refused, so the guard
is demonstrably real.

</details>
