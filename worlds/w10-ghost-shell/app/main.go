// GHOST SHELL :: ops console with a shell where a query planner should be
// World Of B0t challenge 10
// Category: Infra | Difficulty: hard | Vuln: Recon -> cred leak -> RCE
//
// The chain the player has to walk:
//   1. recon    - /api/status names the backing services
//   2. leak     - /api/export dumps a connection string in a debug block
//   3. reach    - the DB is only reachable from inside w0b; the app is the proxy
//   4. RCE      - /admin/diag shells out with that connection string
//
// Every stage is individually unremarkable. The lab is the chain.
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// The app never talks SQL over a driver - it shells out to psql. That keeps the
// image free of cgo and third-party modules, and it is also the RCE surface.
//
// ponytail: shelling to psql instead of vendoring a driver. A driver would mean
// a dependency and a cgo build; psql is already in the image and is what an
// operator would actually use from a container.
const (
	listenAddr = ":8080"
	flagText   = "hex4b0t{REPLACED_AT_RUNTIME}"
)

var (
	// Connection string is assembled from env so the compose file owns it. It is
	// handed to psql as a single -d argument.
	dbHost = env("W0B_DB_HOST", "w0b-w10-db")
	dbPort = env("W0B_DB_PORT", "5432")
	dbUser = env("W0B_DB_USER", "ghost")
	dbPass = env("W0B_DB_PASS", "ghost_ops_2024")
	dbName = env("W0B_DB_NAME", "ghostshell")
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// dsn is the string the leak stage reveals.
func dsn() string {
	return fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", dbUser, dbPass, dbHost, dbPort, dbName)
}

func flag() string {
	if v := os.Getenv("W0B_FLAG"); v != "" {
		return v
	}
	return flagText
}

// runPSQL executes a query and returns combined output. The caller is trusted
// here because this helper is only supposed to be reached by the fixed queries
// below - a fact the app does not enforce.
//
// ponytail: one helper for every query. The vulnerable call site passes an
// operator-supplied filter straight through; the safe ones pass constants.
func runPSQL(query string) (string, error) {
	// VULNERABLE: the connection string and the query are both interpolated into
	// a shell command line. psql supports `\!` and meta-commands, and the
	// surrounding shell does not care that we meant "a query".
	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("psql '%s' -tAc \"%s\" 2>&1", dsn(), query))
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Stage 1 - recon
// ---------------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, landingPage)
}

// handleStatus is informational but load-bearing: it names the datastore, so a
// player who reads it learns there is something to reach behind the app.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "ghost-shell",
		"lab":     "w10",
		"surfaces": []string{
			"/api/status",
			"/api/export",
			"/api/ops/query",
			"/admin/diag",
		},
		"backends": map[string]string{
			"database": fmt.Sprintf("%s:%s", dbHost, dbPort),
			"note":     "datastore is not published to the host; query it through this API",
		},
	})
}

// ---------------------------------------------------------------------------
// Stage 2 - the leak
// ---------------------------------------------------------------------------

// handleExport looks like a backup/export helper. When the datastore cannot be
// reached it helpfully prints how it tried to reach it - including credentials.
//
// VULNERABLE: an error path that reflects the connection string. This is the
// "cred leak" half of the lab. The DB is up in the compose stack, so to see the
// leak the player requests an export of a table they are not allowed to read, or
// simply triggers the failure branch.
func handleExport(w http.ResponseWriter, r *http.Request) {
	table := r.URL.Query().Get("table")
	if table == "" {
		table = "sessions"
	}
	out, err := runPSQL(fmt.Sprintf("SELECT count(*) FROM %s", table))
	if err != nil {
		// Debug trace on failure. Handy in dev, fatal in ops.
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":    false,
			"stage": "export",
			"error": out,
			"debug": map[string]string{
				"dsn":     dsn(),
				"psql":    "psql -d <dsn> -tAc \"SELECT count(*) FROM <table>\"",
				"retried": "false",
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "table": table, "rows": out})
}

// ---------------------------------------------------------------------------
// Stage 3 - operator query surface
// ---------------------------------------------------------------------------

// handleOpsQuery is the "read-only reporting" endpoint. It forwards a filter to
// the datastore. The intent is read-only; nothing enforces that.
func handleOpsQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ?q="})
		return
	}
	out, _ := runPSQL(q)
	writeJSON(w, http.StatusOK, map[string]string{"query": q, "result": out})
}

// ---------------------------------------------------------------------------
// Stage 4 - RCE
// ---------------------------------------------------------------------------

// handleDiag is the diagnostic console. It takes a "probe" and runs it to check
// the host. This is where the chain lands: anything that reaches this handler
// runs as the container user.
//
// VULNERABLE: operator input reaches /bin/sh with no separation between "a
// diagnostic name" and "a command line".
func handleDiag(w http.ResponseWriter, r *http.Request) {
	probe := r.URL.Query().Get("probe")
	if probe == "" {
		probe = "uptime"
	}
	// VULNERABLE: interpolated into a shell line.
	cmd := exec.Command("/bin/sh", "-c", "echo '[diag] '; "+probe)
	out, _ := cmd.CombinedOutput()
	writeJSON(w, http.StatusOK, map[string]string{
		"probe":  probe,
		"output": strings.TrimSpace(string(out)),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lab": "w10", "service": "ghost-shell"})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/export", handleExport)
	mux.HandleFunc("/api/ops/query", handleOpsQuery)
	mux.HandleFunc("/admin/diag", handleDiag)
	mux.HandleFunc("/api/health", handleHealth)

	fmt.Printf("[ghost-shell] listening on %s\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// escape is unused by the vulnerable paths on purpose - it exists so the
// contrast is visible in review: the fixed handlers would use it, the
// vulnerable ones do not.
func escape(s string) string { return html.EscapeString(s) }

const landingPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="lab" content="w10">
<title>GHOST SHELL // ops console</title>
<style>
  body { margin:0; background:#05050c; color:#d9faff;
         font:14px/1.5 "SF Mono","JetBrains Mono",Consolas,monospace; }
  .wrap { max-width:820px; margin:0 auto; padding:40px 20px 80px; }
  h1 { color:#00f0ff; letter-spacing:3px; font-size:30px; margin:0 0 4px;
       text-shadow:0 0 12px rgba(0,240,255,.55); }
  h1 span { color:#ff2e97; text-shadow:0 0 12px rgba(255,46,151,.55); }
  .sub { color:#6c7a8a; letter-spacing:1px; margin-bottom:28px; }
  h2 { font-size:12px; letter-spacing:2px; text-transform:uppercase;
       color:#6c7a8a; margin:26px 0 8px; }
  code { color:#39ff88; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid #1c2438; }
  th { color:#6c7a8a; font-size:11px; letter-spacing:1.4px; text-transform:uppercase; }
  .warn { color:#ffe600; }
  footer { margin-top:40px; color:#6c7a8a; font-size:12px; border-top:1px solid #1c2438; padding-top:14px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>GHOST <span>SHELL</span></h1>
  <div class="sub">// ops console &mdash; datastore-backed reporting</div>

  <h2>Surfaces</h2>
  <table>
    <tr><th>Method</th><th>Path</th><th>Purpose</th></tr>
    <tr><td>GET</td><td><code>/api/status</code></td><td>service + backend description</td></tr>
    <tr><td>GET</td><td><code>/api/export?table=</code></td><td>row count for a table</td></tr>
    <tr><td>GET</td><td><code>/api/ops/query?q=</code></td><td>ad-hoc reporting query</td></tr>
    <tr><td>GET</td><td><code>/admin/diag?probe=</code></td><td>host diagnostics</td></tr>
  </table>

  <h2>Note</h2>
  <div class="warn">The datastore is not reachable from the host. Everything goes
  through this console.</div>

  <footer>Ghost Shell &middot; World Of B0t challenge 10 &middot; local use only</footer>
</div>
</body>
</html>
`
