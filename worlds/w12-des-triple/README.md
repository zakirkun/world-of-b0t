# w12 :: Token Crypt

- **Category:** Crypto
- **Difficulty:** hard
- **Stack:** Python 3.12 / stdlib only (hand-rolled DES)
- **URL:** http://localhost:30012

## Brief

TOKEN CRYPT seals a vault with DES. The first version was plain single DES; the
review said that was too weak, so **v2** applies the cipher three times:

```
v1(data) = E_k1(data)
v2(data) = E_k1( E_k3( E_k2( data ) ) )
```

The master key `k1` never leaves the process. But so that downstream verifiers
can check tokens without holding it, the two *other* keys travel in the request.
The service also publishes some key material it considers safe.

The vault is sealed with `v1`. `/api/v1/decrypt` refuses to open it, and
`/api/vault/open` is closed.

## Goal

Recover the vault plaintext and submit the flag.

## Hint

DES is older than you think, and it has a small, published set of keys that are
*more* degenerate than the "weak key" folklore. `GET /api/keys` hands you the
list.

What happens to `E_k3( E_k2( data ) )` when `{k2, k3}` is one of those pairs?

<details>
<summary>Spoiler</summary>

`GET /api/keys` returns the six DES **semi-weak key pairs**, plus a
`publishable_k2` / `publishable_k3` that form one of them. For a semi-weak pair
`{a, b}`, `E_a(E_b(x)) == x` — the two inner applications of v2 cancel out.

So with `k2, k3` set to a published pair, `v2(x) == v1(x)`. The "triple"
construction is single DES wearing a coat. Grab the sealed vault:

```bash
curl -s http://localhost:30012/api/vault
# {"vault":"sealed","ciphertext":"10af603a...","blocks":4,...}
```

and push its ciphertext back through the v1 decrypt path one 8-byte block at a
time:

```bash
python solution/recover.py
# [+] FLAG: hex4b0t{...}
```

`solution/probe.sh` asserts the primitives against the NIST vector, that the
collapse is real, and that the flag falls out.

</details>
