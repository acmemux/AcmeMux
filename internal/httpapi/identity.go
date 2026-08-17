package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/acmemux/AcmeMux/internal/identity"
)

// A 1024-byte accepted password can expand sixfold under JSON string escaping.
// Keep the request bounded while allowing every password accepted by identity.
const maximumLoginBodyBytes = 8 * 1024

type identityEndpoints struct {
	service *identity.Service
	limiter *LoginLimiter
	clients ClientIPResolver
	now     func() time.Time
}

type sessionSnapshot struct {
	State             string `json:"state"`
	IdleExpiresAt     string `json:"idleExpiresAt,omitempty"`
	AbsoluteExpiresAt string `json:"absoluteExpiresAt,omitempty"`
}

func newIdentityEndpoints(
	service *identity.Service,
	trustedProxies []netip.Prefix,
) (*identityEndpoints, error) {
	if service == nil {
		return nil, errors.New("identity service is required")
	}
	return &identityEndpoints{
		service: service,
		limiter: NewLoginLimiter(),
		clients: NewClientIPResolver(trustedProxies),
		now:     time.Now,
	}, nil
}

func (endpoints *identityEndpoints) register(multiplexer *http.ServeMux) {
	multiplexer.HandleFunc("GET /api/v1/session", endpoints.getSession)
	multiplexer.HandleFunc("POST /api/v1/session", endpoints.signIn)
	multiplexer.HandleFunc("DELETE /api/v1/session", endpoints.signOut)
	multiplexer.HandleFunc("GET /api/v1/application", endpoints.getApplication)
}

func (endpoints *identityEndpoints) getSession(response http.ResponseWriter, request *http.Request) {
	initialized, err := endpoints.service.Initialized(request.Context())
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	if !initialized {
		clearSessionCookies(response)
		writeJSON(response, http.StatusOK, sessionSnapshot{State: "uninitialized"})
		return
	}

	rawSession, present := sessionToken(request)
	if !present {
		if requestHasCookie(request, sessionCookieName) {
			clearSessionCookies(response)
			writeJSON(response, http.StatusOK, sessionSnapshot{State: "expired"})
			return
		}
		writeJSON(response, http.StatusOK, sessionSnapshot{State: "signed_out"})
		return
	}

	active, rawCSRF, err := endpoints.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeJSON(response, http.StatusOK, sessionSnapshot{State: "expired"})
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	if err := endpoints.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return
	}
	writeAuthenticatedSnapshot(response, active)
}

func (endpoints *identityEndpoints) signIn(response http.ResponseWriter, request *http.Request) {
	password, ok := readLoginPassword(response, request)
	if !ok {
		return
	}
	defer clear(password)

	allowed, retryAfter := endpoints.limiter.Allow(endpoints.clients.Resolve(request), endpoints.now().UTC())
	if !allowed {
		writeRateLimited(response, retryAfter)
		return
	}
	release, admitted := endpoints.limiter.TryAcquireKDF()
	if !admitted {
		writeRateLimited(response, time.Second)
		return
	}
	defer release()

	grant, err := endpoints.service.Authenticate(request.Context(), password)
	if errors.Is(err, identity.ErrInvalidCredentials) || errors.Is(err, identity.ErrUninitialized) {
		writeAPIError(response, http.StatusUnauthorized, "invalid_credentials", "Sign-in failed.")
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}

	for _, token := range cookieValues(request, sessionCookieName) {
		if err := endpoints.service.Logout(request.Context(), token); err != nil {
			_ = endpoints.service.Logout(request.Context(), grant.Token)
			writeServiceUnavailable(response)
			return
		}
	}
	now := endpoints.now().UTC()
	if err := setSessionCookies(response, grant.Token, grant.CSRFToken, now, grant.AbsoluteExpiresAt); err != nil {
		_ = endpoints.service.Logout(request.Context(), grant.Token)
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, authenticatedSnapshot(grant.IdleExpiresAt, grant.AbsoluteExpiresAt))
}

func (endpoints *identityEndpoints) signOut(response http.ResponseWriter, request *http.Request) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return
	}
	active, err := endpoints.service.ValidateSession(request.Context(), rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	rawCSRF, validPair := csrfToken(request)
	if !validPair || !active.ValidCSRF(rawCSRF) {
		writeAPIError(response, http.StatusForbidden, "request_not_allowed", "The request could not be verified.")
		return
	}
	if err := endpoints.service.Logout(request.Context(), rawSession); err != nil {
		writeServiceUnavailable(response)
		return
	}
	clearSessionCookies(response)
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusNoContent)
}

func (endpoints *identityEndpoints) getApplication(response http.ResponseWriter, request *http.Request) {
	rawSession, present := sessionToken(request)
	if !present {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return
	}
	active, rawCSRF, err := endpoints.validateBrowserSession(request, rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		clearSessionCookies(response)
		writeAuthenticationRequired(response)
		return
	}
	if err != nil {
		writeServiceUnavailable(response)
		return
	}
	if err := endpoints.refreshCookies(response, rawCSRF, active); err != nil {
		_ = endpoints.service.Logout(request.Context(), rawSession)
		clearSessionCookies(response)
		writeServiceUnavailable(response)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (endpoints *identityEndpoints) validateBrowserSession(
	request *http.Request,
	rawSession string,
) (identity.ActiveSession, string, error) {
	active, err := endpoints.service.ValidateSession(request.Context(), rawSession)
	if errors.Is(err, identity.ErrInvalidSession) || errors.Is(err, identity.ErrSessionExpired) {
		return identity.ActiveSession{}, "", err
	}
	if err != nil {
		return identity.ActiveSession{}, "", err
	}
	rawCSRF, present := uniqueCookieValue(request, csrfCookieName)
	if !present || !active.ValidCSRF(rawCSRF) {
		_ = endpoints.service.Logout(request.Context(), rawSession)
		return identity.ActiveSession{}, "", identity.ErrInvalidSession
	}
	return active, rawCSRF, nil
}

func (endpoints *identityEndpoints) refreshCookies(
	response http.ResponseWriter,
	rawCSRF string,
	active identity.ActiveSession,
) error {
	if active.ReplacementToken == "" {
		return nil
	}
	return setSessionCookies(response, active.ReplacementToken, rawCSRF, endpoints.now().UTC(), active.AbsoluteExpiresAt)
}

func readLoginPassword(response http.ResponseWriter, request *http.Request) ([]byte, bool) {
	if !requireJSON(request) {
		writeAPIError(response, http.StatusUnsupportedMediaType, "invalid_request", "A JSON request body is required.")
		return nil, false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumLoginBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var payload struct {
		Password string `json:"password"`
	}
	if err := decoder.Decode(&payload); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeAPIError(response, http.StatusRequestEntityTooLarge, "invalid_request", "The request body is too large.")
		} else {
			writeAPIError(response, http.StatusBadRequest, "invalid_request", "The request body is invalid.")
		}
		return nil, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeAPIError(response, http.StatusBadRequest, "invalid_request", "The request body is invalid.")
		return nil, false
	}
	password := []byte(payload.Password)
	payload.Password = ""
	return password, true
}

func writeAuthenticatedSnapshot(response http.ResponseWriter, active identity.ActiveSession) {
	writeJSON(response, http.StatusOK, authenticatedSnapshot(active.IdleExpiresAt, active.AbsoluteExpiresAt))
}

func authenticatedSnapshot(idle, absolute time.Time) sessionSnapshot {
	return sessionSnapshot{
		State:             "authenticated",
		IdleExpiresAt:     idle.UTC().Format(time.RFC3339),
		AbsoluteExpiresAt: absolute.UTC().Format(time.RFC3339),
	}
}

func writeAuthenticationRequired(response http.ResponseWriter) {
	writeAPIError(response, http.StatusUnauthorized, "authentication_required", "Administrator authentication is required.")
}

func writeServiceUnavailable(response http.ResponseWriter) {
	writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "The session service is unavailable.")
}

func writeRateLimited(response http.ResponseWriter, delay time.Duration) {
	seconds := int64((delay + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	if seconds > 3600 {
		seconds = 3600
	}
	response.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeAPIError(response, http.StatusTooManyRequests, "rate_limited", "Sign-in is temporarily limited.")
}

func requestHasCookie(request *http.Request, name string) bool {
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func cookieValues(request *http.Request, name string) []string {
	values := make([]string, 0, 1)
	for _, cookie := range request.Cookies() {
		if cookie.Name == name && validOpaqueToken(cookie.Value) {
			values = append(values, cookie.Value)
		}
	}
	return values
}
