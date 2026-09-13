// CONCAT WALK :: static drop server
// World Of B0t challenge 17
// Category: Web | Difficulty: easy | Vuln: path traversal via string concatenation
//
// The drop server serves files out of /srv/files by concatenating the caller's
// filename onto the root. A guard rejects the textbook traversal shape, but the
// guard is a substring test and the concatenation is never cleaned, so a
// leading "../" walks out of the root unrejected.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	root = "/srv/files"
	addr = ":8080"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func listFiles() []string {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range ents {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// VULNERABLE ENDPOINT
//
//	GET /dl?f=<name>   ->  os.Open(root + "/" + name)
//
// Two mistakes stack:
//
//  1. The path is built by concatenation. `filepath.Join` would have cleaned
//     the ".." segments; this does not.
//  2. The guard is `strings.Contains(name, "/../")`, which only matches a
//     traversal that has a segment on BOTH sides of the "..". A leading
//     "../" has nothing before the slashes, so it slips straight through.
//
// Result: `f=../private/flag.txt` reads a file one level above the drop root.
// ---------------------------------------------------------------------------
func handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ?f= filename"})
		return
	}

	// The guard. Catches "a/../b", misses "../b".
	//
	// ponytail: substring guard, intentionally the wrong shape. The traversal
	// that matters has no leading segment.
	if strings.Contains(name, "/../") {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "traversal blocked"})
		return
	}

	// Concatenation, not filepath.Join. That difference is the bug.
	target := root + "/" + name

	f, err := os.Open(filepath.Clean(target))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such file"})
		return
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(b)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "concat-walk",
		"drop":    "public",
		"files":   len(listFiles()),
	})
}

const landing = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w17">
<title>CONCAT WALK :: static drop server</title>
<style>
  :root{--bg:#05050c;--cy:#00f0ff;--mg:#ff2e97;--dim:#5d7285;--fg:#cfefff}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;background:var(--bg);color:var(--fg);
    font:14px/1.6 "SF Mono",ui-monospace,Menlo,Consolas,monospace;
    padding:48px 20px;
    background-image:linear-gradient(rgba(0,240,255,.03) 1px,transparent 1px),
                     linear-gradient(90deg,rgba(0,240,255,.03) 1px,transparent 1px);
    background-size:44px 44px}
  .wrap{max-width:780px;margin:0 auto}
  h1{margin:0 0 6px;font-size:30px;letter-spacing:6px;color:var(--cy);
    text-shadow:0 0 14px rgba(0,240,255,.6)}
  h1 span{color:var(--mg);text-shadow:0 0 14px rgba(255,46,151,.6)}
  .sub{color:var(--dim);font-size:11px;letter-spacing:3px;margin-bottom:30px}
  .card{border:1px solid #10384a;background:#080810;padding:22px;margin-bottom:20px}
  .card h2{margin:0 0 14px;font-size:12px;letter-spacing:3px;color:var(--mg);font-weight:400}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{text-align:left;color:var(--dim);font-weight:400;font-size:10px;
    letter-spacing:2px;padding:7px 9px;border-bottom:1px solid #10384a}
  td{padding:8px 9px;border-bottom:1px solid #0d1a24}
  code{color:#ffe600}
  pre{background:#040409;border:1px solid #10384a;padding:14px;overflow-x:auto;
    font-size:12px;color:#8fe9ff}
  .note{color:var(--dim);font-size:11px;line-height:1.9}
  footer{color:#2b3a47;font-size:10px;letter-spacing:2px;text-align:center;margin-top:26px}
</style>
</head>
<body>
<div class="wrap">
  <h1>CONCAT <span>WALK</span></h1>
  <div class="sub">// STATIC DROP SERVER :: NODE W17</div>

  <div class="card">
    <h2>&gt; DOWNLOAD</h2>
    <table>
      <thead><tr><th>ENDPOINT</th><th>NOTES</th></tr></thead>
      <tbody>
        <tr><td><code>GET /dl?f=&lt;name&gt;</code></td><td>fetch a file from the drop</td></tr>
        <tr><td><code>GET /api/health</code></td><td>node status</td></tr>
        <tr><td><code>GET /?f=manifest.txt</code></td><td>see the drop manifest</td></tr>
      </tbody>
    </table>
    <pre>curl 'http://localhost:30017/dl?f=manifest.txt'</pre>
  </div>

  <div class="card">
    <h2>&gt; NODE NOTE</h2>
    <div class="note">
      Files are served straight off the drop volume, which also holds the
      operator vault one directory up.<br>
      Traversal is checked before every read &mdash; the check covers the
      <code>segment/../segment</code> shape.<br>
      The path itself is assembled by hand.
    </div>
  </div>

  <footer>c0nc4t_w4lk :: go :: drop v0.17</footer>
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
		// The landing page doubles as a manifest view when ?f= is present, so a
		// player can see the drop contents without guessing names.
		if f := r.URL.Query().Get("f"); f != "" {
			handleDownload(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, landing)
	})

	mux.HandleFunc("/dl", handleDownload)
	mux.HandleFunc("/api/health", handleHealth)

	if err := http.ListenAndServe(addr, mux); err != nil {
		panic(err)
	}
}
