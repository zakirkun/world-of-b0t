# w02 :: Static Ghost

- **Category:** Web
- **Difficulty:** easy
- **Stack:** Nginx
- **URL:** http://localhost:30002

## Brief

STATIC GRID is an edge delivery network that serves its marketing site from a
bare nginx. Ops left the legacy release mirror mounted "just in case". Nobody
cleaned it up.

## Goal

Recover the vault token committed by mistake and read the flag.

## Hint

Servers publish an index for crawlers. Check what STATIC GRID asked not to be
indexed, then look at what the ops mirror kept around.

<details>
<summary>Spoiler</summary>

1. `GET /robots.txt` -> `Disallow: /backup/`
2. `GET /backup/` is autoindexed -> read `app.py.bak`, which leaks
   `VAULT_TOKEN = "sg_vault_9f3a1c0d"`
3. The startup script plants the flag at `/backup/vault/<TOKEN>.txt`. That
   subdirectory is not indexed, so the token is required.

```
curl http://localhost:30002/backup/vault/sg_vault_9f3a1c0d.txt
```

</details>
