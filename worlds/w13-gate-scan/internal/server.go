// GATE SCAN :: status farm (internal service)
// World Of B0t challenge 13
//
// Network-isolated: no host port is published. The only way in is from another
// container on the w0b network - i.e. through GATE SCAN's SSRF.
//
// This service answers to TWO names on that network: its canonical container
// name (w0b-w13-internal) and the migration alias `statusfarm`. The prober's
// blocklist only knows the first.
package main

import (
	"encoding/json"
	"net/http"
	"os"
)

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

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"flag": flag()})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"service": "status-farm", "ok": true})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	addr := ":9000"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	_ = http.ListenAndServe(addr, mux)
}
