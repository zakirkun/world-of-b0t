# w05 :: Data Jack

- **Category:** Web
- **Difficulty:** medium
- **Stack:** Node.js / Express
- **URL:** http://localhost:30005

## Brief

`DATA JACK :: archives index` exposes a public tag lookup over the archive
`records` table. It answers with exactly one bit per request — `{"found":true}`
or `{"found":false}` — and nothing else: no rows, no errors, no counts.

The flag lives in a separate `vault` table that the search endpoint was never
wired to list.

## Goal

Extract the full flag from the `vault` table through the blind search endpoint.

## Hint

The response only ever says true or false — ask the database one yes/no
question at a time.

<details>
<summary>Spoiler</summary>

`/search?q=` is interpolated straight into:

```sql
SELECT id FROM records WHERE tag = '<q>'
```

`found` is only "did a row come back". You can append a `UNION SELECT` arm
that returns a row only when your condition holds — a boolean oracle. Feed it
`substr(secret,n,1)='x'` and binary-search each character position.

Working payload for position `n` and candidate char `c`:

```
' UNION SELECT 1 WHERE (SELECT substr(secret,n,1) FROM vault)='c' /*
```

Terminate with `/*` rather than `--`: the whole query is one line, and SQLite
only treats `--` as a comment at a token boundary, so the trailing `%'`/`'`
survives and turns the tail into an alias. `/*` truncates reliably.

`found:true` means the character matched. A full recovery script is in
`solution/writeup.md`.

</details>
