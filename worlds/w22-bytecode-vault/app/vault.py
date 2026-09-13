import hashlib
import hmac

# The vault's two secrets. Both are static module constants by design: the
# compiled bytecode ships them in co_consts, so a player who disassembles
# vault.pyc can recompute the access code. That is the entire lab.

VAULT_USER = "keeper-07"
VAULT_SALT = "6f1c9d2b48e75a03"


def unlock_code():
    return hashlib.sha256((VAULT_SALT + VAULT_USER).encode()).hexdigest()[:16]


def check(code):
    return hmac.compare_digest(code, unlock_code())
