// RE VAULT :: license validator
// World Of B0t challenge 21
// Category: Reverse | Difficulty: medium | Vuln: license key recoverable from shipped binary
//
// The validator checks a submitted license key against a transformed blob
// embedded in the binary. The transform is symmetric and the blob ships with
// the binary (which is itself downloadable for "offline audits"), so the
// license is recoverable by anyone who runs `strings` on it.

package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
)

const (
	// licenseBlobHex is the ONLY artifact of the real license key that ships
	// in the binary. blob[i] = ((key[i] ^ 0x5A) + i) & 0xFF for i in 0..15.
	// ponytail: the key itself is nowhere in the image, but the transform is
	// fixed and one-byte-per-position, so the blob inverts key[i] =
	// ((blob[i] - i) & 0xFF) ^ 0x5A. Any constant check embedded in a
	// shipped binary has this ceiling; hashing would only move the target.
	licenseBlobHex = "aaddcebadafbdacddbbbbcadeabcffef"

	addr = ":8080"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func flag() string {
	if f := os.Getenv("W0B_FLAG"); f != "" {
		return f
	}
	return "hex4b0t{REPLACED_AT_RUNTIME}"
}

// checkLicense applies the derivation to the candidate key and compares the
// result against the embedded blob.
func checkLicense(key []byte) bool {
	// VULNERABLE: the check is a plain equality against a constant derived
	// from the real key with a per-position transform. The blob is a string
	// constant in this binary, so the license is recoverable offline.
	blob, err := hex.DecodeString(licenseBlobHex)
	if err != nil {
		return false
	}
	for i, b := range key {
		if byte(int(b^0x5A)+i)&0xFF != blob[i] {
			return false
		}
	}
	return true
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	keyHex := r.URL.Query().Get("key")
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 16 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "license must be 32 hex chars (16 bytes)"})
		return
	}
	if !checkLicense(key) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "invalid license"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "flag": flag()})
}

// handleBinary serves the running validator itself. The landing page calls
// this the "offline audit" copy; it is also the exploit artifact.
func handleBinary(w http.ResponseWriter, r *http.Request) {
	self, err := os.Executable()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot locate binary"})
		return
	}
	data, err := os.ReadFile(self)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot read binary"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "lab": "w21"})
}

const landing = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="lab" content="w21">
<title>RE VAULT</title>
<style>
  :root { color-scheme: dark; }
  body {
    background: #05050c; color: #c8d6e5;
    font-family: "Cascadia Mono", "Fira Code", Consolas, monospace;
    max-width: 46rem; margin: 0 auto; padding: 3rem 1.25rem;
    line-height: 1.6;
  }
  h1 { color: #00f0ff; font-size: 1.6rem; letter-spacing: .35em; margin: 0 0 .25rem; }
  .tag { color: #ff2e97; font-size: .8rem; letter-spacing: .2em; }
  h2 { color: #00f0ff; font-size: 1rem; margin-top: 2rem; letter-spacing: .15em; }
  code, pre { color: #00f0ff; }
  pre { background: #0a0a18; border: 1px solid #1b2340; padding: .8rem; overflow-x: auto; }
  a { color: #ff2e97; }
  .card { border: 1px solid #1b2340; padding: 1rem; margin: 1rem 0; }
</style>
</head>
<body>
<h1>RE VAULT</h1>
<p class="tag">LICENSE ATTESTATION TERMINAL // NODE 21</p>

<div class="card">
<h2>// validator</h2>
<p>Submit your 32-hex-character license key for attestation:</p>
<pre>GET /api/validate?key=&lt;32 hex chars&gt;</pre>
<p>Keys are attested locally. No network call leaves this node.</p>
</div>

<div class="card">
<h2>// offline audits</h2>
<p>Compliance teams may download the validator binary itself for offline
audit of the attestation routine:</p>
<pre>GET /re-vault-linux</pre>
<p>The shipped build is what production runs. Audit away.</p>
</div>

<div class="card">
<h2>// service</h2>
<pre>GET /api/health</pre>
</div>

<p class="tag">RE VAULT // your license is your access</p>
</body>
</html>`

func handleLanding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(landing))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleLanding)
	mux.HandleFunc("GET /api/validate", handleValidate)
	mux.HandleFunc("GET /re-vault-linux", handleBinary)
	mux.HandleFunc("GET /api/health", handleHealth)
	if err := http.ListenAndServe(addr, mux); err != nil {
		panic(err)
	}
}
