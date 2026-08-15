package main

import (
	"net/http"
	"testing"
	"time"

	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
)

func TestHTTPWriteBudgetCanReturnRuntimeInspectionTimeout(t *testing.T) {
	t.Parallel()
	server := newApplicationHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	minimum := acmeruntime.DefaultProbePolicy().InspectionTimeout + 10*time.Second
	if server.WriteTimeout < minimum {
		t.Fatalf("WriteTimeout = %s, want at least %s", server.WriteTimeout, minimum)
	}
}
