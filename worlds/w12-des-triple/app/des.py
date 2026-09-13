"""DES / triple-DES primitives for TOKEN CRYPT.

Hand-rolled, stdlib-only, table-driven. The service needs DES in ECB mode and,
crucially, it must honour the *semi-weak key pairs*: for those pairs
``{a, b}``, ``E_a(E_b(x)) == x``. That property is a genuine feature of DES and
it is what this challenge turns on, so the implementation is verified against a
published known-answer vector rather than trusted.

    python3 des.py     # runs the self-check
"""

# --- standard DES permutation tables -----------------------------------------
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

# The six DES semi-weak key pairs: E_a(E_b(x)) == x and E_b(E_a(x)) == x.
# Note this is an ENCRYPT-ENCRYPT cancellation; it is not about decryption.
SEMI_WEAK_PAIRS = [
    ("01FE01FE01FE01FE", "FE01FE01FE01FE01"),
    ("1FE01FE00EF10EF1", "E01FE01FF10EF10E"),
    ("01E001E001F101F1", "E001E001F101F101"),
    ("1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E"),
    ("011F011F010E010E", "1F011F010E010E01"),
    ("E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1"),
]

BLOCK = 8


def _bits(data):
    return [int(b) for byte in data for b in f"{byte:08b}"]


def _bytes(bits):
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


def _perm(bits, table):
    return [bits[i - 1] for i in table]


def _subkeys(key):
    k = _perm(_bits(key), PC1)
    c, d = k[:28], k[28:]
    out = []
    for s in SHIFTS:
        c, d = c[s:] + c[:s], d[s:] + d[:s]
        out.append(_perm(c + d, PC2))
    return out


def _f(r, k):
    x = [a ^ b for a, b in zip(_perm(r, E), k)]
    o = []
    for i in range(8):
        blk = x[i * 6:i * 6 + 6]
        row = blk[0] * 2 + blk[5]
        col = blk[1] * 8 + blk[2] * 4 + blk[3] * 2 + blk[4]
        for bit in f"{SBOX[i][row * 16 + col]:04b}":
            o.append(int(bit))
    return _perm(o, P)


def _block(block, keys):
    b = _perm(_bits(block), IP)
    l, r = b[:32], b[32:]
    for k in keys:
        l, r = r, [a ^ b for a, b in zip(l, _f(r, k))]
    return _bytes(_perm(r + l, FP))


def encrypt_block(key: bytes, block: bytes) -> bytes:
    """Single DES block encryption (ECB)."""
    return _block(block, _subkeys(key))


def decrypt_block(key: bytes, block: bytes) -> bytes:
    """Single DES block decryption (ECB)."""
    return _block(block, _subkeys(key)[::-1])


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """DES in ECB mode. ``data`` must be a whole number of blocks."""
    if len(data) % BLOCK:
        raise ValueError("data must be a multiple of 8 bytes")
    return b"".join(encrypt_block(key, data[i:i + BLOCK]) for i in range(0, len(data), BLOCK))


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """DES in ECB mode. ``data`` must be a whole number of blocks."""
    if len(data) % BLOCK:
        raise ValueError("data must be a multiple of 8 bytes")
    return b"".join(decrypt_block(key, data[i:i + BLOCK]) for i in range(0, len(data), BLOCK))


def pad(data: bytes) -> bytes:
    """PKCS#7 padding."""
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    """Strip PKCS#7 padding, tolerating unpadded input."""
    if data and 1 <= data[-1] <= BLOCK and data.endswith(bytes([data[-1]]) * data[-1]):
        return data[:-data[-1]]
    return data


def _self_check() -> None:
    # FIPS/known-answer vector: key 133457799BBCDFF1 encrypts 0123456789ABCDEF
    # to 85E813540F0AB405.
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")
    ct = encrypt_block(key, pt)
    assert ct.hex().upper() == "85E813540F0AB405", f"KAT failed: {ct.hex().upper()}"
    assert decrypt_block(key, ct) == pt, "KAT decrypt failed"

    # Round-trips on random data.
    import os
    for _ in range(64):
        k, b = os.urandom(BLOCK), os.urandom(BLOCK)
        assert decrypt_block(k, encrypt_block(k, b)) == b, "round-trip failed"

    # ECB over a multi-block message.
    k = os.urandom(BLOCK)
    msg = os.urandom(BLOCK * 3)
    assert ecb_decrypt(k, ecb_encrypt(k, msg)) == msg, "ECB round-trip failed"

    # The property the whole challenge rests on.
    for a_hex, b_hex in SEMI_WEAK_PAIRS:
        a, b = bytes.fromhex(a_hex), bytes.fromhex(b_hex)
        for _ in range(16):
            x = os.urandom(BLOCK)
            assert encrypt_block(a, encrypt_block(b, x)) == x, f"semi-weak collapse failed for {a_hex}"
            assert encrypt_block(b, encrypt_block(a, x)) == x, f"semi-weak collapse failed for {b_hex}"

    print("des.py self-check: OK (KAT, round-trip, ECB, 6 semi-weak pairs)")


if __name__ == "__main__":
    _self_check()
