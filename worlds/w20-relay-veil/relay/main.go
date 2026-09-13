// RELAY VEIL :: config-driven edge relay (World Of B0t challenge 20)
// Category: Infra | Difficulty: hard | Vuln: config-path traversal -> admin route
//
// The relay owns no routes of its own. It reads route tables from conf.d/ and
// dispatches accordingly. Operators reload tables at runtime so they can ship a
// config change without a restart.
//
// Two tables ship with the image:
//
//   conf.d/public.conf   the routes the world may see; loaded at boot
//   private/admin.conf   the management plane; lives OUTSIDE conf.d/
//
// The management table is not secret - it is right there on disk, and the
// landing page says so. It is *unreachable* because the boot scan only reads
// conf.d/ and the reload endpoint is supposed to only ever name files inside it.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	listenAddr  = ":8080"
	confDir     = "/srv/relay/conf.d"
	internalURL = "http://w0b-w20-internal:9000"
)

var (
	start = time.Now()

	mu     sync.RWMutex
	routes = map[string]route{} // public path -> route
	tables = []string{}         // config files currently loaded
)

type route struct {
	Path     string `json:"path"`
	Upstream string `json:"upstream"`
	Auth     string `json:"auth"`
}

func upstreamBase(name string) string {
	switch {
	case strings.HasPrefix(name, "control:"):
		// The control plane lives behind the same internal service.
		return internalURL + "/_control"
	default:
		return internalURL
	}
}

// parseTable reads a config file's route lines:
//
//	route <public-path> <upstream> <auth>
func parseTable(body string) []route {
	var out []route
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "route" {
			continue
		}
		out = append(out, route{Path: fields[1], Upstream: fields[2], Auth: fields[3]})
	}
	return out
}

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

func applyTable(rt []route) {
	mu.Lock()
	defer mu.Unlock()
	for _, r := range rt {
		routes[r.Path] = r
	}
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	b, _ := json.Marshal(payload)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

func landing(w http.ResponseWriter) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w20">
<title>RELAY VEIL</title>
<style>
  :root { color-scheme: dark; }
  body { background:#05050c; color:#c8d6e5; font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
         margin:0; padding:32px; }
  h1 { color:#00f0ff; letter-spacing:.22em; margin:0 0 4px; font-size:22px; }
  .sub { color:#ff2e97; letter-spacing:.14em; font-size:11px; text-transform:uppercase; }
  section { max-width:860px; margin:26px auto 0; border:1px solid #1b2340; background:#0a0a16; padding:18px 20px; }
  code { color:#00f0ff; }
  pre { background:#05050c; border-left:2px solid #ff2e97; padding:12px 14px; overflow-x:auto; color:#9fb3c8; }
  table { border-collapse:collapse; width:100%; }
  td,th { text-align:left; padding:4px 10px 4px 0; border-bottom:1px solid #131a30; vertical-align:top; }
  th { color:#00f0ff; font-weight:400; }
</style>
<h1>RELAY VEIL</h1>
<div class="sub">config-driven relay v1.20.0 :: tables under <code>conf.d/</code></div>

<section>
  <p>The relay has no routes of its own; it loads route tables. Ship a table,
  reload, done &mdash; no restart.</p>

<pre>route &lt;public-path&gt; &lt;upstream&gt; &lt;auth&gt;</pre>

  <table>
    <tr><th>shipped table</th><th>purpose</th></tr>
    <tr><td><code>conf.d/public.conf</code></td><td>loaded at boot; the world's routes</td></tr>
    <tr><td><code>private/admin.conf</code></td><td>management plane; outside the loadable set</td></tr>
  </table>

  <p>Reload a table at runtime:</p>
  <pre>POST /api/reload?config=public.conf</pre>

  <p>The management table is readable by anyone with a shell on this box. It is
  not hidden &mdash; it is simply outside <code>conf.d/</code>, so the boot scan
  never sees it and nothing routes to it. The reload endpoint only names files
  inside <code>conf.d/</code>.</p>
</section>
`)
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("config")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ?config="})
		return
	}

	rt, full, err := loadTable(name)
	if err != nil {
		// The full path is echoed so operators can see what was attempted.
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":      "cannot load table",
			"attempted":  full,
			"detail":     err.Error(),
		})
		return
	}
	applyTable(rt)

	mu.Lock()
	tables = append(tables, full)
	mu.Unlock()

	paths := make([]string, 0, len(rt))
	for _, x := range rt {
		paths = append(paths, x.Path)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":  full,
		"routes":  paths,
		"count":   len(rt),
	})
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		landing(w)
		return
	}

	if r.URL.Path == "/api/reload" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		handleReload(w, r)
		return
	}

	if r.URL.Path == "/api/health" {
		mu.RLock()
		loaded := append([]string(nil), tables...)
		mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"service":     "relay-veil",
			"lab":         "w20",
			"version":     "1.20.0",
			"conf_dir":    confDir,
			"tables":      loaded,
			"route_count": routeCount(),
			"uptime":      int(time.Since(start).Seconds()),
		})
		return
	}

	mu.RLock()
	rt, ok := routes[r.URL.Path]
	mu.RUnlock()

	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no route",
			"path":  r.URL.Path,
		})
		return
	}

	// A token-authenticated route requires a header the edge strips.
	if rt.Auth == "token" && r.Header.Get("X-Relay-Token") == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "route requires X-Relay-Token"})
		return
	}

	// Upstream is expressed symbolically; resolve to a real target.
	upath := strings.TrimPrefix(rt.Upstream, "control:")
	upath = strings.TrimPrefix(upath, "internal:")
	if upath == "health" || upath == "status" || upath == "echo" {
		upath = "/" + upath
	} else {
		upath = "/_control/" + upath
	}

	target := internalURL + upath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bad upstream request"})
		return
	}
	req.Header.Set("x-relay-hop", "1")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unreachable", "target": target})
		return
	}
	defer resp.Body.Close()

	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		if n > 0 {
			buf.Write(b[:n])
		}
		if err != nil {
			break
		}
	}
	w.Header().Set("content-type", resp.Header.Get("content-type"))
	w.WriteHeader(resp.StatusCode)
	w.Write([]byte(buf.String()))
}

func routeCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(routes)
}

func boot() error {
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		// Only public.conf is in the boot set. admin.conf ships on disk but is
		// deliberately excluded here.
		if e.Name() != "public.conf" {
			continue
		}
		rt, full, err := loadTable(e.Name())
		if err != nil {
			return err
		}
		applyTable(rt)
		mu.Lock()
		tables = append(tables, full)
		mu.Unlock()
	}
	return nil
}

func main() {
	if err := boot(); err != nil {
		log.Fatalf("boot: %v", err)
	}
	log.Printf("relay-veil listening on %s, conf.d %s, %d routes", listenAddr, confDir, routeCount())

	// No ServeMux: its path cleaning and redirects are irrelevant here and
	// would only obscure the request as received.
	srv := &http.Server{Addr: listenAddr, Handler: http.HandlerFunc(handle), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
