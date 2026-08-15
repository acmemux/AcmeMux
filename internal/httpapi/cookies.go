package httpapi

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	sessionCookieName = "__Host-acmemux_session"
	csrfCookieName    = "__Host-acmemux_csrf"
	csrfHeaderName    = "X-AcmeMux-CSRF"
	tokenByteLength   = 32
)

func setSessionCookies(response http.ResponseWriter, sessionToken, csrfToken string, now, expiresAt time.Time) error {
	if !validOpaqueToken(sessionToken) || !validOpaqueToken(csrfToken) {
		return errors.New("session and CSRF tokens must be bounded URL-safe opaque values")
	}
	if !expiresAt.After(now) {
		return errors.New("session cookie expiry must be in the future")
	}
	duration := expiresAt.Sub(now)
	maxAge := int((duration + time.Second - 1) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	setSessionCookieValue(response, sessionToken, expiresAt, maxAge)
	setCSRFCookieValue(response, csrfToken, expiresAt, maxAge)
	return nil
}

func setSessionCookieValue(response http.ResponseWriter, value string, expiresAt time.Time, maxAge int) {
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func setCSRFCookieValue(response http.ResponseWriter, value string, expiresAt time.Time, maxAge int) {
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookies(response http.ResponseWriter) {
	expired := time.Unix(1, 0).UTC()
	http.SetCookie(response, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  expired,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		Expires:  expired,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

func sessionToken(request *http.Request) (string, bool) {
	return uniqueCookieValue(request, sessionCookieName)
}

func csrfToken(request *http.Request) (string, bool) {
	cookieValue, ok := uniqueCookieValue(request, csrfCookieName)
	if !ok {
		return "", false
	}
	headerValues := request.Header.Values(csrfHeaderName)
	if len(headerValues) != 1 || !validOpaqueToken(headerValues[0]) || subtle.ConstantTimeCompare([]byte(cookieValue), []byte(headerValues[0])) != 1 {
		return "", false
	}
	return cookieValue, true
}

func uniqueCookieValue(request *http.Request, name string) (string, bool) {
	var value string
	found := false
	for _, cookie := range request.Cookies() {
		if cookie.Name != name {
			continue
		}
		if found || !validOpaqueToken(cookie.Value) {
			return "", false
		}
		value = cookie.Value
		found = true
	}
	return value, found
}

func validOpaqueToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(tokenByteLength) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == tokenByteLength
}
