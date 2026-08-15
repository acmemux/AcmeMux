package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

type readinessStub struct {
	err error
}

func (stub readinessStub) PingContext(context.Context) error { return stub.err }

func TestHealthAndReadiness(t *testing.T) {
	t.Parallel()

	assets := fstest.MapFS{"index.html": {Data: []byte("<h1>AcmeMux</h1>")}}
	handler := New(readinessStub{}, assets)
	for _, test := range []struct {
		path string
		want int
	}{
		{path: "/healthz", want: http.StatusOK},
		{path: "/readyz", want: http.StatusOK},
		{path: "/", want: http.StatusOK},
		{path: "/client/route", want: http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Errorf("GET %s status = %d, want %d", test.path, response.Code, test.want)
		}
		if response.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s missing Content-Security-Policy", test.path)
		}
	}
}

func TestNotReadyDoesNotExposeDatabaseError(t *testing.T) {
	t.Parallel()

	handler := New(readinessStub{err: errors.New("sensitive database detail")}, fstest.MapFS{})
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
