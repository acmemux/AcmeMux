package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
)

const testPublicOrigin = "https://acmemux.example"

type readinessStub struct {
	err error
}

func (stub readinessStub) PingContext(context.Context) error { return stub.err }

type unusedIdentityDatabase struct{}

func (unusedIdentityDatabase) BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error) {
	return nil, errors.New("unexpected identity transaction")
}

func (unusedIdentityDatabase) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errors.New("unexpected identity execution")
}

func (unusedIdentityDatabase) QueryRowContext(context.Context, string, ...any) *sql.Row {
	return &sql.Row{}
}

var (
	testIdentityOnce    sync.Once
	testIdentityService *identity.Service
	testIdentityError   error
)

func sharedTestIdentity(t *testing.T) *identity.Service {
	t.Helper()
	testIdentityOnce.Do(func() {
		testIdentityService, testIdentityError = identity.New(unusedIdentityDatabase{})
	})
	if testIdentityError != nil {
		t.Fatalf("identity.New() error = %v", testIdentityError)
	}
	return testIdentityService
}

func newTestHandler(t *testing.T, readiness Readiness, assets fstest.MapFS) http.Handler {
	t.Helper()
	handler, err := New(readiness, sharedTestIdentity(t), testRuntimeDependencies(), testWorkspaceDependencies(), testConfigurationDependencies(), testOperationDependencies(), assets, SecurityConfig{PublicOrigin: testPublicOrigin})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return handler
}

func TestHealthReadinessAndBrowserRoutes(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, readinessStub{}, fstest.MapFS{"index.html": {Data: []byte("<h1>AcmeMux</h1>")}})
	for _, test := range []struct {
		path       string
		host       string
		wantStatus int
	}{
		{path: "/healthz", host: "unconfigured.invalid", wantStatus: http.StatusOK},
		{path: "/readyz", host: "unconfigured.invalid", wantStatus: http.StatusOK},
		{path: "/", host: "acmemux.example", wantStatus: http.StatusOK},
		{path: "/client/route", host: "acmemux.example", wantStatus: http.StatusOK},
	} {
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.Host = test.host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Errorf("GET %s status = %d, want %d", test.path, response.Code, test.wantStatus)
			}
			if response.Header().Get("Content-Security-Policy") == "" {
				t.Errorf("GET %s missing Content-Security-Policy", test.path)
			}
			if response.Header().Get("Strict-Transport-Security") == "" {
				t.Errorf("GET %s missing Strict-Transport-Security", test.path)
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Errorf("GET %s unexpectedly enables CORS", test.path)
			}
		})
	}
}

func TestAPIPathsNeverFallThroughToBrowserApplication(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, readinessStub{}, fstest.MapFS{"index.html": {Data: []byte("browser application")}})
	for _, path := range []string{"/api", "/api/", "/api/v1/unknown"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "acmemux.example"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, response.Code)
		}
		if contentType := response.Header().Get("Content-Type"); contentType != "application/json; charset=utf-8" {
			t.Errorf("GET %s Content-Type = %q", path, contentType)
		}
		if body := response.Body.String(); body != "{\"error\":{\"code\":\"not_found\",\"message\":\"The requested API resource was not found.\"}}\n" {
			t.Errorf("GET %s body = %q", path, body)
		}
	}
}

func TestNotReadyDoesNotExposeDatabaseError(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, readinessStub{err: errors.New("sensitive database detail")}, fstest.MapFS{})
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if body := response.Body.String(); body != "{\"status\":\"not_ready\"}\n" {
		t.Fatalf("body = %q, want bounded readiness response", body)
	}
}

func TestNewRejectsInvalidSecurityConfiguration(t *testing.T) {
	t.Parallel()

	for _, origin := range []string{"", "http://acmemux.example", "https://AcmeMux.example", "https://acmemux.example/", "https://acmemux.example:443"} {
		if _, err := New(readinessStub{}, sharedTestIdentity(t), testRuntimeDependencies(), testWorkspaceDependencies(), testConfigurationDependencies(), testOperationDependencies(), fstest.MapFS{}, SecurityConfig{PublicOrigin: origin}); err == nil {
			t.Errorf("New(PublicOrigin=%q) error = nil", origin)
		}
	}
}
