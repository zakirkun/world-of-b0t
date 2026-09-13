# w04 :: Token Crypt

- **Category:** Crypto
- **Difficulty:** medium
- **Stack:** Go
- **URL:** http://localhost:30004

## Brief

TOKEN CRYPT is the clearance authority for the grid. Sessions are stateless:
after login you get a signed JWT and present it as a Bearer token. The vault at
`/api/admin` only answers to a token whose `role` claim is `admin`.

## Goal

Forge a valid `admin` token and read the flag from `/api/admin`.

## Hint

The service signs with HS256, and the signing secret is a **single, common
dictionary word** — the kind that lives in rockyou. Get a token from
`/api/login`, then take the secret offline against a wordlist. Only `HS256` is
accepted (`alg:none` is refused), so this is a secret-guessing exercise, not a
header trick.

<details>
<summary>Spoiler</summary>

The secret is `nightwatch`. See `solution/writeup.md` for the exact crack and
forge commands.

</details>
