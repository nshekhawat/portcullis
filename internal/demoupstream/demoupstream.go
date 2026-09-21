// Package demoupstream implements the toy application the demo stack protects.
//
// It exists so the demo and the end-to-end tests have a realistic upstream with
// successful routes, a login endpoint, a flaky endpoint and a bounded identifier
// space to scrape.
package demoupstream

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Demo credentials accepted by POST /login.
const (
	DemoUser     = "demo"
	DemoPassword = "demo"
)

// MaxProductID is the highest product identifier that exists. Higher ids return
// 404, which gives the scraper and enumeration scenarios something to walk into.
const MaxProductID = 1000

// Handler returns the demo application's routes.
func Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Serve "/" exactly; anything else falls through to the 404 below.
		if r.URL.Path != "/" {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"service": "demo-upstream"})
	})

	mux.HandleFunc("GET /products/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id < 0 || id > MaxProductID {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": fmt.Sprintf("product-%d", id)})
	})

	mux.HandleFunc("GET /api/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id < 0 || id > MaxProductID {
			notFound(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": "shipped"})
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
			return
		}
		if body.Username != DemoUser || body.Password != DemoPassword {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": "demo-token"})
	})

	// /flaky always fails, which is what the retry-storm scenario needs.
	mux.HandleFunc("GET /flaky", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "temporarily unavailable"})
	})

	// Catch-all for unmatched paths, including sensitive probes.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		notFound(w)
	})

	return mux
}

// LoginBody renders the JSON body for a login attempt.
func LoginBody(username, password string) string {
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		return `{"username":"","password":""}`
	}
	return string(body)
}

// SensitivePaths is the list of paths the scanner scenario probes. Every one of
// them 404s against the demo upstream.
func SensitivePaths() []string {
	return []string{
		"/.env",
		"/.git/config",
		"/wp-login.php",
		"/wp-admin/",
		"/phpmyadmin/",
		"/server-status",
		"/actuator/env",
		"/.aws/credentials",
		"/config.json",
		"/vendor/phpunit/phpunit.xml",
		"/cgi-bin/luci",
	}
}

// IsAuthPath reports whether a path belongs to the login flow.
func IsAuthPath(path string) bool {
	return strings.HasPrefix(path, "/login")
}

// notFound writes the standard 404 body.
func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
