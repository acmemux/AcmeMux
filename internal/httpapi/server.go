// Package httpapi defines the same-origin HTTP transport for AcmeMux.
package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// Readiness is the application-state capability required by readiness probes.
type Readiness interface {
	PingContext(context.Context) error
}

// New returns the foundation HTTP handler with health, readiness, and embedded
// same-origin browser routes.
func New(readiness Readiness, assets fs.FS) http.Handler {
	multiplexer := http.NewServeMux()
	multiplexer.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(response, http.StatusOK, map[string]string{"status": "healthy"})
	})
	multiplexer.HandleFunc("GET /readyz", func(response http.ResponseWriter, request *http.Request) {
		context, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		if err := readiness.PingContext(context); err != nil {
			writeJSON(response, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
	})
	multiplexer.Handle("/", browserHandler(assets))
	return securityHeaders(multiplexer)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func browserHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			response.Header().Set("Allow", "GET, HEAD")
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(request.URL.Path), "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		contents, err := fs.ReadFile(assets, name)
		if err != nil {
			name = "index.html"
			contents, err = fs.ReadFile(assets, name)
		}
		if err != nil {
			http.Error(response, "browser application unavailable", http.StatusServiceUnavailable)
			return
		}
		if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
			response.Header().Set("Content-Type", contentType)
		}
		if name == "index.html" {
			response.Header().Set("Cache-Control", "no-cache")
		}
		response.WriteHeader(http.StatusOK)
		if request.Method == http.MethodGet {
			_, _ = response.Write(contents)
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}
