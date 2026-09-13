#!/usr/bin/env python3
"""w12 TOKEN CRYPT :: recover the vault plaintext.

    ./recover.py                       # http://localhost:30012
    ./recover.py http://host:port

Chain of reasoning:

  * v1(x) = E_k1(x)
  * v2(x) = E_k1( E_k3( E_k2(x) ) )

  If (k2, k3) is a DES semi-weak pair then E_k3(E_k2(x)) == x for every x, so

      v2(x) == E_k1(x) == v1(x)

  The "triple" construction collapses to single DES and the master key k1 never
  has to be known: we simply take the vault ciphertext, hand it back through the
  v1 decrypt path, and read the plaintext.

  The only wrinkle is ECB block granularity - see solve() below.
"""

import json
import sys
import urllib.request

BLOCK = 8


def _post(base, path, payload):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=15) as r:
        return json.load(r)


def solve(base, verbose=True):
    def say(msg):
        if verbose:
            print(msg)

    # 1. Discover the published key material.
    keys = _get(base, "/api/keys")
    pair = keys["semi_weak_pairs"][0]
    k2, k3 = bytes.fromhex(pair["a"]), bytes.fromhex(pair["b"])
    say(f"[*] using semi-weak pair  k2={pair['a']}  k3={pair['b']}")

    # 2. Confirm the collapse before relying on it: v2(v1(x)) must equal x
    #    (modulo the final block's padding) for a probe plaintext.
    probe = b"A" * BLOCK
    v1_ct = bytes.fromhex(_post(base, "/api/v1/encrypt", {"data": probe.hex()})["ciphertext"])
    v2_ct = bytes.fromhex(_post(base, "/api/v2/encrypt",
                                {"data": probe.hex(), "k2": pair["a"], "k3": pair["b"]})["ciphertext"])
    if v1_ct != v2_ct:
        raise SystemExit("[!] v2 did not collapse to v1 - key pair wrong for this build")
    say("[*] verified: v2(x) == v1(x) under this pair (construct collapses to single DES)")

    # 3. Grab the sealed vault.
    vault = _get(base, "/api/vault")
    ct = bytes.fromhex(vault["ciphertext"])
    say(f"[*] vault ciphertext: {len(ct)} bytes = {len(ct)//BLOCK} DES blocks")

    # 4. The oracle. v1 decrypt with the raw vault ciphertext would need k1, so
    #    we feed it one block at a time: the v1 decrypt path strips the outer
    #    E_k1 and returns the block. ECB means the blocks are independent, so
    #    recovering them one per call loses nothing.
    #
    #    Worth knowing: the service accepts a multi-block buffer here and returns
    #    the whole plaintext, so a single call would also do. The per-block loop
    #    is the honest demonstration of the block granularity and shows why ECB
    #    (rather than CBC) is what makes the oracle work at all.
    plaintext = bytearray()
    for i in range(0, len(ct), BLOCK):
        chunk = ct[i:i + BLOCK]
        resp = _post(base, "/api/v1/decrypt", {"data": chunk.hex()})
        pt = bytes.fromhex(resp["plaintext"])
        plaintext += pt[:BLOCK]
        say(f"    block {i//BLOCK}: {chunk.hex()} -> {pt.hex()}")

    text = plaintext.rstrip(b"\x00").decode("utf-8", "replace")
    # Strip PKCS#7 padding if present.
    if text and ord(text[-1]) <= BLOCK and text.endswith(text[-1] * ord(text[-1])):
        text = text[:-ord(text[-1])]
    return text


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:30012"
    print(f"[*] target {base}")
    text = solve(base)
    print(f"\n[+] vault plaintext: {text}")
    if "hex4b0t{" in text:
        start = text.index("hex4b0t{")
        end = text.index("}", start) + 1
        print(f"[+] FLAG: {text[start:end]}")
        return 0
    print("[!] no flag found in plaintext")
    return 1


if __name__ == "__main__":
    sys.exit(main())
