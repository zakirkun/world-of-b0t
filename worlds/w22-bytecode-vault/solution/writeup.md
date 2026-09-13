# w22 Bytecode Vault :: solution

## Root cause

The vault's secret is an *algorithm*, not a stored secret, and the algorithm
ships. `app/vault.py` (source removed from the image, but present at build
time) holds:

```python
VAULT_USER = "keeper-07"
VAULT_SALT = "6f1c9d2b48e75a03"

def unlock_code():
    return hashlib.sha256((VAULT_SALT + VAULT_USER).encode()).hexdigest()[:16]

def check(code):
    return hmac.compare_digest(code, unlock_code())
```

`server.py` compiles this module at build time and ships only the bytecode:

```dockerfile
RUN cd /app && python3 -m py_compile vault.py \
    && mv __pycache__/vault.cpython-312.pyc /app/vault.pyc \
    && rm -rf __pycache__ vault.py \
    && python3 -c "import sys; sys.path.insert(0,'/app'); import vault; print('bytecode import ok')"
```

Deleting `vault.py` removes the *text* of the secret. It does not remove the
secret. A `.pyc` is a marshal-serialized `code` object, and a code object
must carry everything the interpreter needs to execute the derivation: the
string constants `VAULT_SALT` and `VAULT_USER` sit verbatim in `co_consts`,
and the call structure (`sha256`, the concatenation, the `[:16]` slice) is
spelled out in opcodes. `hmac.compare_digest` in `check()` is constant-time
and irrelevant — the comparison input is fully computable offline.

The design mistake, precisely: **the secret was made static and derivable,
then the derivation was shipped in executable form.** A secret that must be
recomputable by the running service with no external input cannot be hidden
by deleting its source text; bytecode *is* the source, at one level lower.

The graybox grant: `GET /static/vault.pyc` serves the compiled artifact
(`application/octet-stream`) from disk. No auth, no trick — the artifact is
the challenge, and it is handed over by design.

## Recon

Landing page names the deal: an access code at `POST /api/unlock`, and a
"backup artifact" mirrored at `/static/vault.pyc`. Health confirms the lab:

```bash
curl -s http://localhost:30022/api/health
# {"ok":true,"lab":"w22","vault":"bytecode"}
```

The hint gives the username half and volunteers that the salt "never left
the build machine":

```bash
curl -s http://localhost:30022/api/hint
# {"user":"keeper-07","note":"salt never left the build machine"}
```

That claim is the tell. The salt *is* on the box — it runs on every unlock —
it just never left as text. Confirm the artifact is real bytecode, not a
stall:

```bash
curl -s http://localhost:30022/static/vault.pyc -o vault.pyc
file vault.pyc            # data (binary, not text)
xxd vault.pyc | head -1   # starts with the CPython 3.12 magic:  cb 0d 0d 0a
```

Also confirm the guard is a real gate before working for the key:

```bash
curl -s -X POST http://localhost:30022/api/unlock \
  -H 'content-type: application/json' -d '{"code":"0000000000000000"}'
# {"ok":false}
```

## Exploit

**Disassembly path.** Strip the 16-byte pyc header (4-byte magic, 4-byte
flags, 4-byte mtime, 4-byte source size) and unmarshal the module code
object:

```bash
python - <<'EOF'
import dis, marshal
co = marshal.loads(open("vault.pyc","rb").read()[16:])
for c in co.co_consts:
    if isinstance(c, str):
        print(repr(c))
# 'keeper-07'
# '6f1c9d2b48e75a03'      <- the salt that "never left the build machine"
dis.dis(co)                # sha256 call, concat, [:16] slice - all in opcodes
EOF
```

`python3 -m dis vault.pyc` works too on a Python matching the pyc's version.

**Recompute.** The bytecode shows `unlock_code` concatenates the two
constants and hashes with sha256:

```bash
python -c "import hashlib; print(hashlib.sha256(('6f1c9d2b48e75a03'+'keeper-07').encode()).hexdigest()[:16])"
# <16 hex chars>
```

**Unlock:**

```bash
curl -s -X POST http://localhost:30022/api/unlock \
  -H 'content-type: application/json' -d '{"code":"<16 hex>"}'
# {"ok":true,"flag":"hex4b0t{...}"}
```

`solution/exploit.py` runs the whole chain. It hardcodes nothing: it
downloads the pyc, walks the code object with `marshal` reading `co_consts` /
`co_names` only — plain data, no `dis()`, so the script works even when the
local interpreter is a different version than the pyc's — identifies
the salt by shape (16 hex chars) and the user by matching `/api/hint`,
confirms `sha256` appears in `co_names` before trusting the derivation,
then recomputes and presents the code. Rotate the salt in a rebuild and the
script still solves it.

## Dead ends worth recording

**Brute force** — 2^64 for a 16-hex-char code. Not a path; the point of the
lab is that no brute force is needed.

**Guessing around the salt** — `/api/hint` gives only `keeper-07`. Any code
built from the username alone fails; the salt genuinely lives in the
artifact.

**Looking for the source** — there is none on the box. `docker exec
w0b-w22 ls /app` shows only `server.py` and `vault.pyc`. The artifact is the
source; that is the lesson.

## The fix

The bug is not that the pyc leaked — it is that a *derivable* secret was
treated as a *hidden* one. Two independent repairs:

**1. Never derive the secret inside the service.** The access code should be
generated once (at deploy or enrolment time), stored only as a verifier, and
handed to whoever legitimately needs it — not recomputed from constants on
every request. If the service must verify a code, it should hold a hash or
HMAC key of that code, not the ingredients to bake it:

```python
# the service stores only a verifier, configured out of band
import hmac
def check(code):
    return hmac.compare_digest(code, os.environ["VAULT_CODE"])
```

**2. Ship no secret-bearing bytecode at all.** Bytecode obfuscation is not a
boundary — `marshal` + `dis` (or `decompyle`-class tools for the versions
they support) reads any `.pyc` a player can download. If a module must stay
closed, it runs server-side behind an API, full stop; the moment its
compiled form leaves the build machine, assume the logic is public. A
"backup artifact" of a secret-bearing module has no business being served by
the very service it protects.

The general lesson: **deleting source is redaction for humans, not for
interpreters.** Whatever the interpreter needs to run, the artifact carries,
and anything the artifact carries is recoverable by anyone holding the
artifact.

## Flag

Injected at runtime via the `W0B_FLAG` environment variable. Never present in
any image layer; `flag.txt.example` and the Dockerfile's empty `ENV` keep it
that way.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
