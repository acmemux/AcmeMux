package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	testSessionToken = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	testCSRFToken    = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
)

func TestSetSessionCookiesUsesHostOnlySecureAttributes(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0).UTC()
	expires := now.Add(time.Hour)
	response := httptest.NewRecorder()
	if err := setSessionCookies(response, testSessionToken, testCSRFToken, now, expires); err != nil {
		t.Fatalf("setSessionCookies() error = %v", err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie %s attributes = %+v", cookie.Name, cookie)
		}
		if cookie.MaxAge != 3600 || !cookie.Expires.Equal(expires) {
			t.Errorf("cookie %s expiry = %v/%d, want %v/3600", cookie.Name, cookie.Expires, cookie.MaxAge, expires)
		}
		switch cookie.Name {
		case sessionCookieName:
			if !cookie.HttpOnly || cookie.Value != testSessionToken {
				t.Errorf("session cookie = %+v", cookie)
			}
		case csrfCookieName:
			if cookie.HttpOnly || cookie.Value != testCSRFToken {
				t.Errorf("CSRF cookie = %+v", cookie)
			}
		default:
			t.Errorf("unexpected cookie %q", cookie.Name)
		}
	}
	for _, header := range response.Header().Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(header), "domain=") {
			t.Errorf("Set-Cookie unexpectedly contains Domain: %q", header)
		}
	}
}

func TestSetSessionCookiesRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	for _, test := range []struct {
		session string
		csrf    string
		expires time.Time
	}{
		{session: "", csrf: testCSRFToken, expires: now.Add(time.Hour)},
		{session: "contains space", csrf: testCSRFToken, expires: now.Add(time.Hour)},
		{session: testSessionToken, csrf: "contains=padding", expires: now.Add(time.Hour)},
		{session: testSessionToken, csrf: testCSRFToken, expires: now},
	} {
		response := httptest.NewRecorder()
		if err := setSessionCookies(response, test.session, test.csrf, now, test.expires); err == nil {
			t.Errorf("setSessionCookies(%q, %q, %v) error = nil", test.session, test.csrf, test.expires)
		}
		if len(response.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("invalid cookie input emitted Set-Cookie")
		}
	}
}

func TestClearSessionCookiesPreservesSecurityAttributes(t *testing.T) {
	t.Parallel()

	response := httptest.NewRecorder()
	clearSessionCookies(response)
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookie count = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != -1 || cookie.Value != "" {
			t.Errorf("cleared cookie = %+v", cookie)
		}
		if cookie.Name == sessionCookieName && !cookie.HttpOnly {
			t.Error("cleared session cookie lost HttpOnly")
		}
		if cookie.Name == csrfCookieName && cookie.HttpOnly {
			t.Error("cleared CSRF cookie became HttpOnly")
		}
	}
}

func TestSessionTokenRequiresExactlyOneBoundedCookie(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		cookies []*http.Cookie
		want    bool
	}{
		{name: "missing"},
		{name: "valid", cookies: []*http.Cookie{{Name: sessionCookieName, Value: testSessionToken}}, want: true},
		{name: "duplicate", cookies: []*http.Cookie{{Name: sessionCookieName, Value: testSessionToken}, {Name: sessionCookieName, Value: testSessionToken}}},
		{name: "empty", cookies: []*http.Cookie{{Name: sessionCookieName, Value: ""}}},
		{name: "invalid character", cookies: []*http.Cookie{{Name: sessionCookieName, Value: "token.value"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodGet, testPublicOrigin, nil)
			for _, cookie := range test.cookies {
				request.AddCookie(cookie)
			}
			value, ok := sessionToken(request)
			if ok != test.want {
				t.Fatalf("sessionToken() = (%q, %v), want ok=%v", value, ok, test.want)
			}
			if ok && value != testSessionToken {
				t.Fatalf("sessionToken() value = %q", value)
			}
		})
	}
}

func TestCSRFTokenRequiresMatchingUniqueCookieAndHeader(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		cookieValues []string
		headerValues []string
		want         bool
	}{
		{name: "matching", cookieValues: []string{testCSRFToken}, headerValues: []string{testCSRFToken}, want: true},
		{name: "missing cookie", headerValues: []string{testCSRFToken}},
		{name: "missing header", cookieValues: []string{testCSRFToken}},
		{name: "mismatch", cookieValues: []string{testCSRFToken}, headerValues: []string{testSessionToken}},
		{name: "duplicate cookie", cookieValues: []string{testCSRFToken, testCSRFToken}, headerValues: []string{testCSRFToken}},
		{name: "duplicate header", cookieValues: []string{testCSRFToken}, headerValues: []string{testCSRFToken, testCSRFToken}},
		{name: "invalid header", cookieValues: []string{testCSRFToken}, headerValues: []string{"invalid.value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodDelete, testPublicOrigin+"/api/v1/session", nil)
			for _, value := range test.cookieValues {
				request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: value})
			}
			for _, value := range test.headerValues {
				request.Header.Add(csrfHeaderName, value)
			}
			value, ok := csrfToken(request)
			if ok != test.want {
				t.Fatalf("csrfToken() = (%q, %v), want ok=%v", value, ok, test.want)
			}
		})
	}
}
