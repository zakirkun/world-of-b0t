# w12 Token Crypt :: solution

## Root cause

`app/server.py`, `_seal_v2()`:

```python
def _seal_v2(data: bytes, k2: bytes, k3: bytes) -> bytes:
    """v2: E_k1( E_k3( E_k2( data ) ) ) - the "triple" upgrade."""
    inner = des.ecb_encrypt(k2, des.pad(data))
    middle = des.ecb_encrypt(k3, inner)
    return des.ecb_encrypt(K1, middle)
```

Two of the three key applications take their key from the **request body**:

```python
k2, err = self._hexfield(obj, "k2", des.BLOCK)   # caller-supplied
k3, err = self._hexfield(obj, "k3", des.BLOCK)   # caller-supplied
```

The design intent was "3DES", where the point is that knowing two of the three
keys should still leave the third safe. That guarantee holds for *full* triple
DES over a large key space. It does not hold once two of the three keys are
attacker-chosen **and** the cipher is DES, because DES has a small published set
of degenerate keys — including the six **semi-weak pairs**, for which

```
E_a( E_b( x ) ) == x      for all x
```

Substitute such a pair for `{k2, k3}` and the inner two applications cancel:

```
v2(x) = E_k1( E_k3( E_k2( x ) ) ) = E_k1( x ) = v1(x)
```

The construction collapses to single DES. Nothing about `k1` needs to be known
to take a **v1** ciphertext and read it.

The service even ships the pairs, because someone decided the legacy verifier
needs them for "interoperability":

```python
if path == "/api/keys":
    return self._json(200, {
        "semi_weak_pairs": [{"a": a, "b": b} for a, b in des.SEMI_WEAK_PAIRS],
        "publishable_k2": des.SEMI_WEAK_PAIRS[0][0],
        "publishable_k3": des.SEMI_WEAK_PAIRS[0][1],
    })
```

## Recon

The landing page states the construction. Confirm the service is alive and note
it tells you the mode matters:

```bash
curl -s http://localhost:30012/api/health
# {"service":"token-crypt","lab":"w12","mode":"ECB","block_bytes":8,...}
```

`"mode":"ECB"` is the second half of the exploit (see *Why ECB matters*).

Pull the published key material:

```bash
curl -s http://localhost:30012/api/keys
# {"note":"DES has keys that are weaker than they look...",
#  "semi_weak_pairs":[{"a":"01FE01FE01FE01FE","b":"FE01FE01FE01FE01"}, ...],
#  "publishable_k2":"01FE01FE01FE01FE","publishable_k3":"FE01FE01FE01FE01"}
```

Six pairs, all of them the textbook DES semi-weak set.

## Exploit

Confirm the collapse before trusting it. `v2(x)` and `v1(x)` must agree exactly
when the pair is supplied:

```bash
X=4141414141414141
V1=$(curl -s -X POST http://localhost:30012/api/v1/encrypt \
      -H 'content-type: application/json' -d "{\"data\":\"$X\"}" \
      | python -c 'import json,sys;print(json.load(sys.stdin)["ciphertext"])')
V2=$(curl -s -X POST http://localhost:30012/api/v2/encrypt \
      -H 'content-type: application/json' \
      -d "{\"data\":\"$X\",\"k2\":\"01FE01FE01FE01FE\",\"k3\":\"FE01FE01FE01FE01\"}" \
      | python -c 'import json,sys;print(json.load(sys.stdin)["ciphertext"])')
echo "$V1"; echo "$V2"    # identical -> the pair collapses the construction
```

Now take the sealed vault and unwrap it block by block:

```bash
curl -s http://localhost:30012/api/vault
# {"vault":"sealed","ciphertext":"10af603acfc1a3c2a00bb50e...","blocks":4}
```

Feed each 8-byte block to the v1 decrypt path:

```bash
BLK=10af603acfc1a3c2
curl -s -X POST http://localhost:30012/api/v1/decrypt \
  -H 'content-type: application/json' -d "{\"data\":\"$BLK\"}"
# {"plaintext":"686578346230747b"}   -> "hex4b0t{"
```

or just run the bundled script:

```bash
python solution/recover.py
# [*] using semi-weak pair  k2=01FE01FE01FE01FE  k3=FE01FE01FE01FE01
# [*] verified: v2(x) == v1(x) under this pair (construct collapses to single DES)
# [*] vault ciphertext: 32 bytes = 4 DES blocks
#     block 0: 10af603acfc1a3c2 -> 686578346230747b
#     block 1: a00bb50e65efbf89 -> 7665726966797465
#     block 2: 8e50b707b3364db6 -> 7374313233343536
#     block 3: 1bd376bac0c515e5 -> 7d
# [+] FLAG: hex4b0t{verifytest123456}
```

## Why ECB matters

This is the one part of the challenge that is easy to get half-right and then
believe is broken.

The flag here is 25 bytes. PKCS#7 pads it to 32 = exactly **4 DES blocks**. The
oracle is per-block: ECB has no chaining, so each 8-byte block decrypts
independently of its neighbours. Recovering them one call at a time is the
natural way to see the structure, and it is why the service is ECB and not CBC.

> If the service had used CBC, decrypting block *n* would require block *n-1*'s
> ciphertext, and a naive "decrypt the whole vault with the collapsed v1 path"
> would still work — but a *partial* oracle call would leak no usable bytes. The
> per-block property is what makes the block-granularity recovery clean.

Note the v1 decrypt path does accept a whole multi-block buffer, so a single
call returns the entire plaintext at once. The loop exists to *show* the block
structure, not because the server forces it. If you only ever look at the first
8 bytes and stop, you will wrongly conclude the lab is short an oracle.

## Described but not required: the padding oracle that is not here

There is no padding oracle to exploit and none is needed. The oracle is a
*decryption* oracle over the collapsed construction, which is strictly stronger
than a padding oracle. If the service had validated padding and exposed a
"bad padding" error, PKCS#7 would give a second, independent path to the same
plaintext; it does not, and adding it would turn a clean crypto lab into a
padding-oracle lab by accident.

## The fix

Do not let the caller choose any part of the key schedule, and do not run DES at
all:

1. **Key material must never come from the request.** If a verifier needs to
   check tokens, ship it a derived MAC key or a public-key verification path,
   not two thirds of your encryption key.
2. **3DES over DES does not rescue a weak primitive.** The collapse here is a
   property of the underlying DES key space, not of the composition. AES-GCM (or
   any modern AEAD) removes the whole class: no semi-weak keys, authenticated,
   and no ECB block oracle.
3. **If you must interoperate with 3DES**, at minimum forbid the published
   degenerate key sets (`weak`, `semi-weak`, `possibly-weak` — 64 keys in total)
   as *all three* K1/K2/K3 components. The check is a lookup against four tiny
   published tables; it costs nothing and closes exactly this bug.

## Flag

Injected at runtime into `W0B_FLAG`. There is no static value to hardcode, and
`k1` is re-randomised every boot, so the vault ciphertext changes each restart
while the flag does not.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
