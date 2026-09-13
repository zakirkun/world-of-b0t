# w10 :: Ghost Shell

- **Category:** Infra
- **Difficulty:** hard
- **Stack:** Go / PostgreSQL 16 / nginx edge (3 containers)
- **URL:** http://localhost:30010

## Brief

GHOST SHELL is an ops console in front of a datastore you cannot reach. The
edge is the only published surface; the database has no host port, and the
console's reporting API is the sanctioned way in.

Four surfaces:

| surface | purpose |
|---|---|
| `/api/status` | what the service is and what backs it |
| `/api/export?table=` | row counts, with a debug block on failure |
| `/api/ops/query?q=` | ad-hoc reporting query |
| `/admin/diag?probe=` | host diagnostics |

The datastore holds decoy rows. The thing you are looking for was never in it.

## Goal

Walk the chain: learn what backs the console, get its credentials, reach the
datastore through the app, and end with code execution on the console itself.

## Hint

An error message that prints its connection string is a leak. A "diagnostic"
that runs a probe name through a shell is a command. The flag is in the
console's environment — a database you own completely is still not enough.

<details>
<summary>Spoiler</summary>

`/api/export?table=does_not_exist` fails and reflects its debug block, which
includes the DSN: `postgresql://ghost:ghost_ops_2024@w0b-w10-db:5432/ghostshell`.
The database is internal-only, so those credentials are only useful *through*
the console — `/api/ops/query` forwards your SQL to `psql`.

The flag is not in the database (check — the seed rows are decoys). It is in the
console process's environment, and the diag endpoint runs its `probe` parameter
through `/bin/sh -c`:

```bash
curl -s 'http://localhost:30010/admin/diag?probe=printenv%20W0B_FLAG'
# {"output":"[diag] \nhex4b0t{...}","probe":"printenv W0B_FLAG"}
```

`solution/exploit.sh` walks all four stages; `solution/probe.sh` asserts each
stage is individually insufficient and the chain is intact.

</details>
