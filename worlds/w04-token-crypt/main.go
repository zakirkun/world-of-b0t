package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var users = map[string]string{
	"guest": "guest",
	// role for admin is admin, but the password is not shipped to the player.
}

func flag() string {
	f := os.Getenv("W0B_FLAG")
	if f == "" {
		return "hex4b0t{flag_not_injected}"
	}
	return f
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	pw, ok := users[in.Username]
	if !ok || pw != in.Password {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	role := "user"
	if in.Username == "admin" {
		role = "admin"
	}
	now := time.Now().Unix()
	tok, err := issue(claims{Sub: in.Username, Role: role, Iat: now, Exp: now + 3600})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func me(w http.ResponseWriter, r *http.Request) {
	c, err := verify(bearer(r))
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": c.Sub, "role": c.Role, "iat": c.Iat, "exp": c.Exp})
}

func admin(w http.ResponseWriter, r *http.Request) {
	c, err := verify(bearer(r))
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid token"})
		return
	}
	if c.Role != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "clearance denied"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"flag": flag()})
}

const landing = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="lab" content="w04">
<title>TOKEN CRYPT :: clearance authority</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;background:#05010d;color:#c8ffe8;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:min(760px,100%);border:1px solid #ff2bd6;
  box-shadow:0 0 24px #ff2bd655, inset 0 0 40px #00ffd511;
  background:linear-gradient(180deg,#0b0220,#05010d);padding:28px 30px}
h1{margin:0 0 4px;font-size:1.5rem;letter-spacing:.18em;color:#ff2bd6;
  text-shadow:0 0 10px #ff2bd6}
.sub{color:#00ffd5;letter-spacing:.28em;font-size:.7rem;margin-bottom:22px}
table{width:100%;border-collapse:collapse;font-size:.82rem}
td{padding:6px 8px;border-bottom:1px dashed #ff2bd633;vertical-align:top}
td.k{color:#00ffd5;white-space:nowrap;width:1%}
code,pre{color:#ffe066}
pre{background:#0d0322;border:1px solid #ff2bd633;padding:12px;overflow-x:auto;font-size:.78rem}
.badge{display:inline-block;border:1px solid #00ffd5;color:#00ffd5;padding:1px 7px;
  font-size:.62rem;letter-spacing:.15em;margin-left:8px}
</style></head><body>
<div class="card">
<h1>TOKEN CRYPT</h1>
<div class="sub">CLEARANCE AUTHORITY / NODE W04</div>
<p>Stateless session service. Identity is proven by a signed token you carry.
Clearance levels: <code>user</code> &rarr; <code>admin</code>.</p>
<table>
<tr><td class="k">POST</td><td><code>/api/login</code> &mdash; <code>{"username":"guest","password":"guest"}</code> &rarr; <code>{"token":"..."}</code></td></tr>
<tr><td class="k">GET</td><td><code>/api/me</code> &mdash; decode your claims (Bearer token)</td></tr>
<tr><td class="k">GET</td><td><code>/api/admin</code> &mdash; flagged vault, needs <code>role=admin</code><span class="badge">RESTRICTED</span></td></tr>
</table>
<pre>curl -s -X POST localhost:30004/api/login \
  -H 'content-type: application/json' \
  -d '{"username":"guest","password":"guest"}'</pre>
</div></body></html>`

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, landing)
	})
	mux.HandleFunc("/api/login", login)
	mux.HandleFunc("/api/me", me)
	mux.HandleFunc("/api/admin", admin)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("TOKEN CRYPT listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
