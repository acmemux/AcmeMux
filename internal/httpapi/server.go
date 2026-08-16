// Package httpapi defines the same-origin HTTP transport for AcmeMux.
package httpapi

import (
	"context"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
)

// Readiness is the application-state capability required by readiness probes.
type Readiness interface {
	PingContext(context.Context) error
}

// New returns the foundation HTTP handler with health, readiness, and embedded
// same-origin browser routes.
func New(
	readiness Readiness,
	identityService *identity.Service,
	runtimeDependencies RuntimeDependencies,
	workspaceDependencies WorkspaceDependencies,
	configurationDependencies ConfigurationDependencies,
	operationDependencies OperationDependencies,
	assets fs.FS,
	config SecurityConfig,
) (http.Handler, error) {
	requestBoundary, err := newRequestSecurity(config)
	if err != nil {
		return nil, err
	}
	identityAPI, err := newIdentityEndpoints(identityService, requestBoundary.trustedProxies)
	if err != nil {
		return nil, err
	}
	runtimeAPI, err := newRuntimeEndpoints(identityAPI, runtimeDependencies)
	if err != nil {
		return nil, err
	}
	workspaceAPI, err := newWorkspaceEndpoints(identityAPI, workspaceDependencies)
	if err != nil {
		return nil, err
	}
	configurationAPI, err := newConfigurationEndpoints(identityAPI, configurationDependencies)
	if err != nil {
		return nil, err
	}
	operationAPI, err := newOperationEndpoints(identityAPI, operationDependencies)
	if err != nil {
		return nil, err
	}
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
	identityAPI.register(multiplexer)
	runtimeAPI.register(multiplexer)
	workspaceAPI.register(multiplexer)
	configurationAPI.register(multiplexer)
	operationAPI.register(multiplexer)
	multiplexer.HandleFunc("/api", apiNotFound)
	multiplexer.HandleFunc("/api/", apiNotFound)
	multiplexer.Handle("/", browserHandler(assets))
	return securityHeaders(requestBoundary.middleware(multiplexer)), nil
}

func apiNotFound(response http.ResponseWriter, _ *http.Request) {
	writeAPIError(response, http.StatusNotFound, "not_found", "The requested API resource was not found.")
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
