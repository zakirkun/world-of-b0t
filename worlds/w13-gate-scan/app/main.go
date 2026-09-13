// GATE SCAN :: uptime prober
// World Of B0t challenge 13
// Category: Web | Difficulty: medium | Vuln: SSRF hostname-blocklist bypass
//
// The prober fetches a URL you supply and reports what came back. A blocklist
// rejects any host containing "internal", which looks like it keeps you off the
// status farm. It does not: the farm answers to a second network alias the
// blocklist has never heard of.

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	errUnsupportedScheme = errors.New("only http and https are supported")
	errNoHost            = errors.New("missing host")
)

const (
	// The farm's canonical container name. This is what the blocklist knows.
	farmHost = "w0b-w13-internal:9000"
	// A second name for the same container, added by ops for a migration that
	// never finished. The blocklist was written before it existed.
	farmAlias = "statusfarm:9000"
)

var start = time.Now()

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func parseTarget(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, &url.Error{Op: "parse", URL: raw, Err: errUnsupportedScheme}
	}
	if u.Host == "" {
		return nil, &url.Error{Op: "parse", URL: raw, Err: errNoHost}
	}
	return u, nil
}

// ---------------------------------------------------------------------------
// THE GUARD
//
// A string blocklist over the host the USER typed. It knows exactly one name
// for the status farm. Two honest observations about why this is the wrong
// shape of control:
//
//  1. It screens a name, not an address. The farm is reachable under every
//     alias it advertises, and the blocklist only lists one of them.
//  2. Loopback and the metadata IP are single literals; anything that resolves
//     to a private address without spelling itself "internal" passes.
//
// ponytail: blocklist because "deny the internal host" shipped faster than an
// allowlist. The fix is an allowlist plus a dialer-level private-range deny
// (net.Dialer.Control), not a longer string list.
// ---------------------------------------------------------------------------
func blocked(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "internal") || strings.Contains(h, "169.254.169.254")
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))

	// Accept both JSON and form posts so the landing page form works.
	var raw string
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var in struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
			return
		}
		raw = in.URL
	} else {
		vals, _ := url.ParseQuery(string(body))
		raw = vals.Get("url")
	}

	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing url"})
		return
	}

	u, err := parseTarget(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unparseable url: " + err.Error()})
		return
	}

	if blocked(u.Host) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "blocked: internal range", "host": u.Host})
		return
	}

	// VULNERABLE: the host string was screened, but nothing checked the address
	// it resolves to, and no allowlist constrains the destination.
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"target": u.String(), "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	writeJSON(w, http.StatusOK, map[string]any{
		"target": u.String(),
		"status": resp.StatusCode,
		"body":   string(b),
	})
}

const landing = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w13">
<title>GATE SCAN :: uptime prober</title>
<style>
  :root{--bg:#05050c;--cy:#00f0ff;--mg:#ff2e97;--dim:#5b6b8a;--fg:#c8faff}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);
    font:14px/1.6 "JetBrains Mono",ui-monospace,monospace;padding:48px 20px}
  .wrap{max-width:800px;margin:0 auto}
  h1{margin:0 0 4px;font-size:28px;letter-spacing:4px;color:var(--cy);
    text-shadow:0 0 12px rgba(0,240,255,.55)}
  h1 span{color:var(--mg);text-shadow:0 0 12px rgba(255,46,151,.55)}
  .sub{color:var(--dim);font-size:12px;letter-spacing:2px;margin-bottom:30px}
  .card{border:1px solid #16233d;background:#080a14;padding:22px;border-radius:4px;margin-bottom:20px}
  .card h2{margin:0 0 14px;font-size:12px;letter-spacing:3px;color:var(--mg);font-weight:400}
  label{display:block;font-size:11px;color:var(--dim);letter-spacing:2px;margin-bottom:10px}
  input{width:100%;background:#05050c;border:1px solid #1d2c4a;color:var(--cy);
    padding:12px 14px;font:inherit;font-size:14px;outline:none}
  input:focus{border-color:var(--cy);box-shadow:0 0 10px rgba(0,240,255,.3)}
  button{margin-top:14px;background:transparent;border:1px solid var(--mg);color:var(--mg);
    padding:11px 26px;font:inherit;font-size:13px;letter-spacing:3px;cursor:pointer}
  button:hover{background:var(--mg);color:#05050c}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{text-align:left;color:var(--dim);font-weight:400;font-size:10px;
    letter-spacing:2px;padding:7px 9px;border-bottom:1px solid #16233d}
  td{padding:8px 9px;border-bottom:1px solid #0d1a24}
  code{color:#ffe600}
  pre{background:#040409;border:1px solid #16233d;padding:14px;overflow:auto;
    max-height:360px;font-size:12px;color:#8fe9ff;white-space:pre-wrap;word-break:break-all}
  .note{color:var(--dim);font-size:11px;line-height:1.9}
</style>
</head>
<body>
<div class="wrap">
  <h1>GATE <span>SCAN</span></h1>
  <div class="sub">// UPTIME PROBER :: v0.13</div>

  <div class="card">
    <h2>&gt; PROBE A TARGET</h2>
    <label>URL</label>
    <form method="POST" action="/scan">
      <input type="text" name="url" placeholder="https://example.com/health" autocomplete="off">
      <button type="submit">SCAN</button>
    </form>
  </div>

  <div class="card">
    <h2>&gt; POLICY</h2>
    <table>
      <thead><tr><th>RULE</th><th>DETAIL</th></tr></thead>
      <tbody>
        <tr><td>BLOCKED</td><td>any host containing <code>internal</code></td></tr>
        <tr><td>BLOCKED</td><td>any host containing <code>169.254.169.254</code></td></tr>
        <tr><td>ALLOWED</td><td>everything else</td></tr>
      </tbody>
    </table>
    <div class="note">
      GATE SCAN runs beside the <b>status farm</b>, which is reachable only on the
      internal network. The blocklist keeps you away from it &mdash; it matches the
      host string before fetching.<br>
      The farm has been through a couple of naming migrations since this policy
      was written.
    </div>
  </div>
</div>
</body>
</html>`

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			handleScan(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, landing)
	})

	mux.HandleFunc("/scan", handleScan)

	// Ops convenience. Reports the farm's CURRENT alias - the migration-flavoured
	// name the blocklist does not know. Says nothing about the blocklist's gap;
	// a player still has to notice the name is not the one that gets denied.
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service":         "gate-scan",
			"version":         "0.13.2",
			"uptime":          int(time.Since(start).Seconds()),
			"statusfarm_host": farmAlias,
		})
	})

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	_ = http.ListenAndServe(addr, mux)
}
