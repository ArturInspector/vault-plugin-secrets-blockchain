package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	addr := os.Getenv("VSIGNER_UI_ADDR")
	if addr == "" {
		// Avoid 8080: often "http-alt" (e.g. python -m http.server) conflicts with this UI.
		addr = "127.0.0.1:9880"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/config", handleConfig)
	// API proxy — Vault token stays server-side only
	mux.HandleFunc("/api/", handleVaultProxy)

	// Static assets
	stripped, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(stripped)))

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("vsigner-ui: cannot bind %s: %v\nhint: free the port or set VSIGNER_UI_ADDR=127.0.0.1:9881", addr, err)
	}
	log.Printf("vsigner-ui listening on http://%s", addr)
	log.Printf("Vault: %s  Mount: %s  Vault UI: %s", vaultAddr(), vaultMount(), vaultUIURL())
	log.Fatal(http.Serve(ln, mux))
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"vaultAddr":  vaultAddr(),
		"mount":      vaultMount(),
		"vaultUIUrl": vaultUIURL(),
	})
}

func vaultUIURL() string {
	if v := os.Getenv("VAULT_UI_URL"); v != "" {
		return strings.TrimRight(v, "/") + "/"
	}
	return vaultAddr() + "/ui/"
}

// handleVaultProxy rewrites /api/* → Vault HTTP API, injects VAULT_TOKEN.
// Browser never sees the token.
func handleVaultProxy(w http.ResponseWriter, r *http.Request) {
	token := os.Getenv("VAULT_TOKEN")

	// /api/sys/health → /v1/sys/health (Vault core, no mount prefix)
	// /api/chains/... → /v1/{mount}/chains/...
	suffix := strings.TrimPrefix(r.URL.Path, "/api/")
	vaultBase := strings.TrimRight(vaultAddr(), "/")
	var target string
	if strings.HasPrefix(suffix, "sys/") {
		target = fmt.Sprintf("%s/v1/%s", vaultBase, suffix)
	} else {
		if token == "" {
			http.Error(w, `{"error":"VAULT_TOKEN not set on server"}`, http.StatusServiceUnavailable)
			return
		}
		target = fmt.Sprintf("%s/v1/%s/%s", vaultBase, vaultMount(), suffix)
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	client := &http.Client{Timeout: 10 * time.Second}
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		log.Printf("vsigner-ui proxy: build request %s: %v", target, err)
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	if token != "" {
		proxyReq.Header.Set("X-Vault-Token", token)
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		proxyReq.Header.Set("Content-Type", "application/json")
	}
	// Vault uses LIST method for directory paths (trailing slash)
	if r.Method == http.MethodGet && strings.HasSuffix(suffix, "/") {
		proxyReq.Method = "LIST"
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Printf("vsigner-ui proxy: %s %s -> %v", proxyReq.Method, target, err)
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func vaultAddr() string {
	if v := os.Getenv("VAULT_ADDR"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:8200"
}

func vaultMount() string {
	if v := os.Getenv("VAULT_MOUNT"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "blockchain"
}
