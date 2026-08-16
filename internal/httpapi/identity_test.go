package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

const (
	identityTestOrigin = "https://acmemux.example.test"
	testPassword       = "correct administrator password"
)

func TestIdentityHTTPFlow(t *testing.T) {
	database, service, handler := newIdentityHTTPTest(t)
	if err := service.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", login.Code, login.Body.String())
	}
	cookies := responseCookies(login)
	sessionCookie := namedCookie(t, cookies, sessionCookieName)
	csrfCookie := namedCookie(t, cookies, csrfCookieName)
	assertSessionCookie(t, sessionCookie, true)
	assertSessionCookie(t, csrfCookie, false)
	if strings.Contains(login.Body.String(), testPassword) || strings.Contains(login.Body.String(), sessionCookie.Value) {
		t.Fatal("sign-in response body contains credential or raw session material")
	}
	assertSnapshotState(t, login, "authenticated")

	status := identityRequest(t, handler, http.MethodGet, "/api/v1/session", "", cookies, false)
	if status.Code != http.StatusOK {
		t.Fatalf("session status = %d, body = %s", status.Code, status.Body.String())
	}
	assertSnapshotState(t, status, "authenticated")

	application := identityRequest(t, handler, http.MethodGet, "/api/v1/application", "", cookies, false)
	if application.Code != http.StatusOK || application.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("protected application response = %d %q", application.Code, application.Body.String())
	}

	missingCSRF := identityRequest(t, handler, http.MethodDelete, "/api/v1/session", "", cookies, true)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF status = %d, want 403", missingCSRF.Code)
	}

	logoutRequest := newIdentityRequest(http.MethodDelete, "/api/v1/session", "", cookies, true)
	logoutRequest.Header.Set(csrfHeaderName, csrfCookie.Value)
	logout := httptest.NewRecorder()
	handler.ServeHTTP(logout, logoutRequest)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, body = %s", logout.Code, logout.Body.String())
	}
	for _, cookie := range responseCookies(logout) {
		if cookie.MaxAge != -1 || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cleared cookie attributes = %+v", cookie)
		}
	}

	afterLogout := identityRequest(t, handler, http.MethodGet, "/api/v1/application", "", cookies, false)
	if afterLogout.Code != http.StatusUnauthorized {
		t.Fatalf("application after logout status = %d, want 401", afterLogout.Code)
	}

	var storedSessionTokens int
	if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM identity_sessions").Scan(&storedSessionTokens); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if storedSessionTokens != 0 {
		t.Fatalf("stored sessions after logout = %d, want 0", storedSessionTokens)
	}
}

func TestUninitializedAndWrongPasswordFailuresAreUniform(t *testing.T) {
	_, uninitializedService, uninitializedHandler := newIdentityHTTPTest(t)
	uninitializedStatus := identityRequest(t, uninitializedHandler, http.MethodGet, "/api/v1/session", "", nil, false)
	assertSnapshotState(t, uninitializedStatus, "uninitialized")
	uninitializedFailure := identityRequest(t, uninitializedHandler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)

	_, initializedService, initializedHandler := newIdentityHTTPTest(t)
	if err := initializedService.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	wrongFailure := identityRequest(t, initializedHandler, http.MethodPost, "/api/v1/session", `{"password":"wrong administrator password"}`, nil, true)

	if uninitializedFailure.Code != http.StatusUnauthorized || wrongFailure.Code != http.StatusUnauthorized {
		t.Fatalf("credential failure statuses = %d and %d, want 401", uninitializedFailure.Code, wrongFailure.Code)
	}
	if uninitializedFailure.Body.String() != wrongFailure.Body.String() {
		t.Fatalf("credential failure bodies differ: %q != %q", uninitializedFailure.Body.String(), wrongFailure.Body.String())
	}
	if len(responseCookies(uninitializedFailure)) != 0 || len(responseCookies(wrongFailure)) != 0 {
		t.Fatal("credential failure set a cookie")
	}
	_ = uninitializedService
}

func TestSignInAcceptsMaximumEscapedPassword(t *testing.T) {
	_, service, handler := newIdentityHTTPTest(t)
	password := strings.Repeat("\x01", 1024)
	if err := service.Bootstrap(context.Background(), []byte(password)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		t.Fatalf("marshal password: %v", err)
	}
	if len(body) <= 2048 || len(body) > maximumLoginBodyBytes {
		t.Fatalf("escaped login body length = %d, want within expanded bounded range", len(body))
	}

	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", string(body), nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", login.Code, login.Body.String())
	}
	assertSnapshotState(t, login, "authenticated")
}

func TestRefreshCookiesCannotRestorePreRotationToken(t *testing.T) {
	now := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	absoluteExpiry := now.Add(12 * time.Hour)
	newToken := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32)))
	csrf := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	endpoints := identityEndpoints{now: func() time.Time { return now }}

	preRotation := httptest.NewRecorder()
	if err := endpoints.refreshCookies(preRotation, csrf, identity.ActiveSession{
		AbsoluteExpiresAt: absoluteExpiry,
	}); err != nil {
		t.Fatalf("refresh pre-rotation cookies: %v", err)
	}
	if headers := preRotation.Header().Values("Set-Cookie"); len(headers) != 0 {
		t.Fatalf("pre-rotation response emitted cookies that could restore an old token: %v", headers)
	}

	rotation := httptest.NewRecorder()
	if err := endpoints.refreshCookies(rotation, csrf, identity.ActiveSession{
		ReplacementToken:  newToken,
		AbsoluteExpiresAt: absoluteExpiry,
	}); err != nil {
		t.Fatalf("refresh rotation cookies: %v", err)
	}
	cookies := responseCookies(rotation)
	if got := namedCookie(t, cookies, sessionCookieName).Value; got != newToken {
		t.Fatalf("rotation cookie token = %q, want replacement", got)
	}
	if len(cookies) != 2 {
		t.Fatalf("rotation cookie count = %d, want session and CSRF", len(cookies))
	}
}

func TestForgedSessionAndResetAreRejected(t *testing.T) {
	_, service, handler := newIdentityHTTPTest(t)
	if err := service.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	forged := []*http.Cookie{
		{Name: sessionCookieName, Value: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))), Path: "/", Secure: true},
		{Name: csrfCookieName, Value: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("y", 32))), Path: "/", Secure: true},
	}
	forgedStatus := identityRequest(t, handler, http.MethodGet, "/api/v1/session", "", forged, false)
	assertSnapshotState(t, forgedStatus, "expired")

	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	cookies := responseCookies(login)
	if err := service.ResetPassword(context.Background(), []byte("replacement administrator password")); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	protected := identityRequest(t, handler, http.MethodGet, "/api/v1/application", "", cookies, false)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("protected route after reset status = %d, want 401", protected.Code)
	}
}

func newIdentityHTTPTest(t *testing.T) (*state.DB, *identity.Service, http.Handler) {
	t.Helper()
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	service, err := identity.New(database)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	handler, err := New(
		database,
		service,
		testRuntimeDependencies(),
		testWorkspaceDependencies(),
		testConfigurationDependencies(),
		fstest.MapFS{"index.html": {Data: []byte("<h1>AcmeMux</h1>")}},
		SecurityConfig{PublicOrigin: identityTestOrigin},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return database, service, handler
}

func identityRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
	cookies []*http.Cookie,
	unsafe bool,
) *httptest.ResponseRecorder {
	t.Helper()
	request := newIdentityRequest(method, path, body, cookies, unsafe)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func newIdentityRequest(method, requestPath, body string, cookies []*http.Cookie, unsafe bool) *http.Request {
	request := httptest.NewRequest(method, identityTestOrigin+requestPath, strings.NewReader(body))
	request.Host = "acmemux.example.test"
	request.RemoteAddr = "127.0.0.2:41000"
	request.Header.Set("Accept", "application/json")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if unsafe {
		request.Header.Set("Origin", identityTestOrigin)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

func responseCookies(response *httptest.ResponseRecorder) []*http.Cookie {
	return response.Result().Cookies()
}

func namedCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.MaxAge > 0 {
			return cookie
		}
	}
	t.Fatalf("response did not contain active cookie %s", name)
	return nil
}

func assertSessionCookie(t *testing.T, cookie *http.Cookie, httpOnly bool) {
	t.Helper()
	if cookie.Path != "/" || !cookie.Secure || cookie.HttpOnly != httpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Domain != "" || cookie.MaxAge <= 0 {
		t.Fatalf("cookie attributes = %+v", cookie)
	}
}

func assertSnapshotState(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var snapshot sessionSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode session snapshot: %v", err)
	}
	if snapshot.State != want {
		t.Fatalf("session state = %q, want %q", snapshot.State, want)
	}
}
