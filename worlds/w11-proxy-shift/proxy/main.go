// EDGE SHIFT :: api gateway (World Of B0t challenge 11)
// Category: Web | Difficulty: hard | Vuln: reverse-proxy path-normalization bypass
//
// The gateway publishes a versioned API under /api/v1 and forwards everything
// beneath it to an internal origin that speaks unversioned paths. The version
// prefix is stripped from the *decoded* path, but the *raw* remainder is what
// gets forwarded, and the origin does its own unquoting and dot-segment
// resolution. Those two views of the same URL do not agree, and the gap between
// them is reachable.
//
// The origin owns the flag and is not published to the host: the gateway is the
// only route in.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	listenAddr = ":8080"
	origin     = "http://w0b-w11-internal:9000"
	prefix     = "/api/v1"
)

var start = time.Now()

// originURL is overridable for local testing only.
func originBase() string {
	if v := os.Getenv("ORIGIN_URL"); v != "" {
		return v
	}
	return origin
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	b, _ := json.Marshal(payload)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}

// edgeReject screens the RAW request target, before any decoding.
//
// It is written in terms of what the edge can see on the wire, which is the
// encoded form. The author's mental model was "a traversal is a dot-dot
// *segment*", so it rejects exactly that: a `..` that stands alone as a path
// segment (`/../`, or a trailing `..`), plus any encoded dot.
//
// ponytail: this is a denylist over spellings. It catches `/../`, `%2e`, and
// the double-encoded form. It does not catch a `..` that is glued to an encoded
// slash, because that never looks like a segment here - see the writeup.
func edgeReject(rawTarget string) (string, bool) {
	lower := strings.ToLower(rawTarget)

	// An encoded dot anywhere is always refused.
	if strings.Contains(lower, "%2e") {
		return "raw request target contains %2e", true
	}

	// A dot-dot SEGMENT: preceded by the start or a slash, followed by a slash,
	// a query/separator, or the end of the target.
	for i := 0; i+1 < len(lower); i++ {
		if lower[i] != '.' || lower[i+1] != '.' {
			continue
		}
		before := i == 0 || lower[i-1] == '/'
		after := i+2 == len(lower) || lower[i+2] == '/' || lower[i+2] == '?' || lower[i+2] == '&' || lower[i+2] == ';' || lower[i+2] == '#'
		if before && after {
			return "raw request target contains a .. path segment", true
		}
	}
	return "", false
}

func handle(w http.ResponseWriter, r *http.Request) {
	rawTarget := r.RequestURI // exactly as received; no decoding, no cleaning

	if reason, bad := edgeReject(rawTarget); bad {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":  "request rejected by gateway",
			"reason": reason,
		})
		return
	}

	u, err := url.ParseRequestURI(rawTarget)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unparseable request target"})
		return
	}

	// The gateway's own routes.
	if u.Path == "/" || u.Path == "" {
		landing(w)
		return
	}
	if u.Path == "/api/health" {
		writeJSON(w, http.StatusOK, map[string]any{
			"service":   "edge-shift",
			"lab":       "w11",
			"version":   "2.11.0",
			"origin":    originBase(),
			"published": prefix,
			"uptime":    int(time.Since(start).Seconds()),
		})
		return
	}

	if !strings.HasPrefix(u.Path, prefix) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not found",
			"hint":  "the public API lives under " + prefix,
		})
		return
	}

	// The published surface is flat: /api/v1/<resource>. A resource with a
	// nested path is not part of the public API, so it is refused.
	//
	// ponytail: the check counts LITERAL slashes in the still-encoded
	// remainder. An encoded slash is not a slash to this test - which is the
	// whole gap the traversal below walks through.
	rawRemainder := strings.TrimPrefix(u.EscapedPath(), prefix)
	if strings.Count(rawRemainder, "/") > 1 {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error":     "not found",
			"reason":    "the public API is flat: one resource segment per path",
			"requested": u.Path,
		})
		return
	}

	// VULNERABLE: the prefix is removed from the decoded path, but the raw
	// (still-encoded) remainder is what is forwarded. The origin decodes again
	// and resolves dot-segments against its own routing table, so a traversal
	// that survives this trim is honoured one hop later.
	//
	// ponytail: EscapedPath() keeps the encoding intact so we do not double-encode
	// on the way out; the mistake is pairing it with a decoded-path decision.
	remainder := strings.TrimPrefix(u.EscapedPath(), prefix)
	if remainder == "" {
		remainder = "/"
	}

	target := originBase() + remainder
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "bad upstream request"})
		return
	}
	// Do not forward the client's own headers beyond what the origin needs; the
	// gateway is supposed to be the only thing the origin trusts.
	req.Header.Set("x-edge-hop", "1")

	resp, err := client.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "upstream unreachable", "target": target,
		})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	w.Header().Set("content-type", resp.Header.Get("content-type"))
	w.Header().Set("x-edge-target", target)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func landing(w http.ResponseWriter) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<meta charset="utf-8">
<meta name="lab" content="w11">
<title>EDGE SHIFT</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#05050c; color:#c8d6e5; font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
         margin:0; padding:32px; }}
  h1 {{ color:#00f0ff; letter-spacing:.22em; margin:0 0 4px; font-size:22px; }}
  .sub {{ color:#ff2e97; letter-spacing:.14em; font-size:11px; text-transform:uppercase; }}
  section {{ max-width:860px; margin:26px auto 0; border:1px solid #1b2340; background:#0a0a16; padding:18px 20px; }}
  code {{ color:#00f0ff; }}
  pre {{ background:#05050c; border-left:2px solid #ff2e97; padding:12px 14px; overflow-x:auto; color:#9fb3c8; }}
  table {{ border-collapse:collapse; width:100%%; }}
  td,th {{ text-align:left; padding:4px 10px 4px 0; border-bottom:1px solid #131a30; vertical-align:top; }}
  th {{ color:#00f0ff; font-weight:400; }}
</style>
<h1>EDGE SHIFT</h1>
<div class="sub">api gateway v2.11.0 :: public surface <code>%s</code></div>

<section>
  <p>This gateway terminates public traffic and forwards it to an internal
  origin. The origin speaks <em>unversioned</em> paths; the version prefix is
  stripped here, at the edge.</p>

<pre>GET %s/&lt;resource&gt;   -&gt;   GET origin:/&lt;resource&gt;</pre>

  <table>
    <tr><th>edge rule</th><th>effect</th></tr>
    <tr><td>reject a <code>..</code> path segment</td><td>400</td></tr>
    <tr><td>reject an encoded dot <code>%%2e</code></td><td>400</td></tr>
    <tr><td>reject a nested resource path</td><td>404</td></tr>
    <tr><td>anything else under <code>%s</code></td><td>forwarded to origin</td></tr>
  </table>

  <p>Available to the public:</p>
  <pre>GET %s/status
GET %s/echo?msg=hi
GET /api/health</pre>

  <p>The origin also exposes an administrative surface. It is not advertised
  here, and the gateway has no rule that reaches it.</p>
</section>
`, prefix, prefix, prefix, prefix, prefix)
}

func main() {
	// Deliberately NOT http.ServeMux: ServeMux cleans the request path (and
	// 301-redirects ".."-bearing targets) before any handler sees it, which
	// would destroy the raw target this gateway exists to inspect.
	log.Printf("edge-shift listening on %s, origin %s", listenAddr, originBase())
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           http.HandlerFunc(handle),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
