# w03 :: Chrome Idor

- **Category:** Web
- **Difficulty:** easy
- **Stack:** PHP 8 / Apache
- **URL:** http://localhost:30003

## Brief

The Chrome Vault indexes every citizen's identity record by a plain numeric id.
The profile endpoint only asks whether you are logged in — never whether the
record you asked for is yours. Credentials from the last breach are public
knowledge.

## Goal

Log in as the low-privilege operator and read the admin's identity record to
recover the flag.

## Hint

Your profile lives at `/profile.php?id=1001`. The admin's id is `9001`.
Nothing stops you from asking for a different id.

<details>
<summary>Spoiler</summary>

Log in with the seeded low-privilege account:

```
k4i / chromes4life
```

After login you land on `/profile.php?id=1001`. Change the id to the admin's
record — the app never verifies ownership:

```
http://localhost:30003/profile.php?id=9001
```

The admin record renders the flag from its `note` field.

</details>
