package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
	"github.com/sgurden-certleap/AcmeMux/internal/operation"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

var operationReviewToken = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 32)))

type operationServiceStub struct {
	preview      operation.Preview
	previewErr   error
	previewCalls int

	enqueueResult jobs.Operation
	enqueueErr    error
	enqueueToken  string
	enqueueCalls  int
	beforeGuard   func(context.Context) error
	guardCalls    int

	status    jobs.Operation
	statusErr error
	latest    jobs.Operation
	latestErr error
	policy    operation.Policy
}

func (stub *operationServiceStub) Preview(context.Context) (operation.Preview, error) {
	stub.previewCalls++
	return stub.preview, stub.previewErr
}

func (stub *operationServiceStub) Enqueue(ctx context.Context, token string, guard workspace.CommitGuard) (jobs.Operation, error) {
	stub.enqueueCalls++
	stub.enqueueToken = token
	if stub.enqueueErr != nil {
		return jobs.Operation{}, stub.enqueueErr
	}
	if stub.beforeGuard != nil {
		if err := stub.beforeGuard(ctx); err != nil {
			return jobs.Operation{}, err
		}
	}
	stub.guardCalls++
	if err := guard(ctx); err != nil {
		return jobs.Operation{}, err
	}
	return stub.enqueueResult, nil
}

func (stub *operationServiceStub) Status(context.Context) (jobs.Operation, error) {
	return stub.status, stub.statusErr
}

func (stub *operationServiceStub) Latest(context.Context) (jobs.Operation, error) {
	return stub.latest, stub.latestErr
}

func (stub *operationServiceStub) Policy() operation.Policy { return stub.policy }

type operationHTTPHarness struct {
	handler  http.Handler
	cookies  []*http.Cookie
	csrf     string
	identity *identity.Service
	service  *operationServiceStub
}

func newOperationHTTPHarness(t *testing.T) *operationHTTPHarness {
	t.Helper()
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	identityService, err := identity.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := identityService.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	service := &operationServiceStub{
		preview: operationPreviewFixture(), policy: operation.DefaultPolicy(),
		enqueueResult: activeOperationFixture(), status: activeOperationFixture(),
		latest: terminalOperationFixture(),
	}
	handler, err := New(
		database, identityService, testRuntimeDependencies(), testWorkspaceDependencies(),
		testConfigurationDependencies(), OperationDependencies{Service: service},
		fstest.MapFS{"index.html": {Data: []byte("browser")}},
		SecurityConfig{PublicOrigin: identityTestOrigin},
	)
	if err != nil {
		t.Fatal(err)
	}
	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", login.Code, login.Body.String())
	}
	cookies := responseCookies(login)
	return &operationHTTPHarness{
		handler: handler, cookies: cookies, csrf: namedCookie(t, cookies, csrfCookieName).Value,
		identity: identityService, service: service,
	}
}

func (harness *operationHTTPHarness) request(t *testing.T, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	request := newIdentityRequest(method, path, body, harness.cookies, method != http.MethodGet)
	if csrf {
		request.Header.Set(csrfHeaderName, harness.csrf)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func operationPreviewFixture() operation.Preview {
	return operation.Preview{
		ReviewedPreviewToken: operationReviewToken,
		Policy:               operation.DefaultPolicy(),
		Intent:               operationIntentFixture(),
	}
}

func operationIntentFixture() configuration.ExecutionIntent {
	return configuration.ExecutionIntent{
		WorkingDirectory: "/srv/acme", ConfigurationPath: "/srv/acme/.lego.yml",
		StoragePath: "/srv/acme/.lego", RuntimeIdentity: "v5.3.1",
		RuntimeManifestID: compatibility.ManifestLegoV531,
		Certificates: []configuration.ExecutionCertificate{{
			Name: "gateway@example", Domains: []string{"gateway.home.example"}, Account: "admin@example.com",
			CA: "letsencrypt", ChallengeName: "web", ChallengeMode: "listener",
		}},
	}
}

func activeOperationFixture() jobs.Operation {
	return jobs.Operation{
		ID: strings.Repeat("a", 32), Kind: jobs.KindManual, State: jobs.StateRunning,
		Phase: jobs.PhaseExecuting, RequestedAt: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		StartedAt: time.Date(2026, 8, 16, 12, 0, 1, 0, time.UTC),
	}
}

func terminalOperationFixture() jobs.Operation {
	count := 1
	return jobs.Operation{
		ID: strings.Repeat("a", 32), Kind: jobs.KindManual, State: jobs.StateSucceeded,
		RequestedAt: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC),
		StartedAt:   time.Date(2026, 8, 16, 12, 0, 1, 0, time.UTC),
		FinishedAt:  time.Date(2026, 8, 16, 12, 0, 2, 0, time.UTC),
		Code:        "execution_succeeded", MayHaveChanged: true,
		Inventory: jobs.InventoryResult{
			State: jobs.InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
		},
		Output: "certificate evaluated\n", Items: []jobs.ItemResult{{
			Name: "gateway@example", State: jobs.ItemCompleted, Code: "evaluated",
		}},
	}
}

func TestOperationEndpointsPresentBoundedPreviewLifecycleAndResult(t *testing.T) {
	harness := newOperationHTTPHarness(t)

	policy := harness.request(t, http.MethodGet, "/api/v1/operations/cancel-policy", "", false)
	if policy.Code != http.StatusOK || !strings.Contains(policy.Body.String(), `"cancellation":"not_supported"`) ||
		!strings.Contains(policy.Body.String(), `"timeoutSeconds":1800`) {
		t.Fatalf("policy response = %d %s", policy.Code, policy.Body.String())
	}
	preview := harness.request(t, http.MethodPost, "/api/v1/operations/manual/previews", `{}`, true)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview response = %d %s", preview.Code, preview.Body.String())
	}
	var decodedPreview operationPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &decodedPreview); err != nil {
		t.Fatal(err)
	}
	if decodedPreview.State != "review_required" || decodedPreview.ReviewedPreviewToken != operationReviewToken ||
		decodedPreview.Intent.Runtime.ManifestID != string(compatibility.ManifestLegoV531) ||
		len(decodedPreview.Intent.Certificates) != 1 || decodedPreview.Intent.Certificates[0].Challenge.Kind != "http-01" ||
		len(decodedPreview.Intent.NativeEffects) != 4 {
		t.Fatalf("preview = %#v", decodedPreview)
	}
	for _, forbidden := range []string{"argv", "environment", "--config"} {
		if strings.Contains(preview.Body.String(), forbidden) {
			t.Fatalf("preview exposed forbidden value %q: %s", forbidden, preview.Body.String())
		}
	}

	enqueued := harness.request(t, http.MethodPost, "/api/v1/operations/manual", `{"reviewedPreviewToken":"`+operationReviewToken+`"}`, true)
	if enqueued.Code != http.StatusAccepted || harness.service.enqueueToken != operationReviewToken ||
		harness.service.guardCalls != 1 || !strings.Contains(enqueued.Body.String(), `"phase":"executing"`) {
		t.Fatalf("enqueue response = %d %s, service=%#v", enqueued.Code, enqueued.Body.String(), harness.service)
	}
	status := harness.request(t, http.MethodGet, "/api/v1/operations/status", "", false)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"state":"active"`) ||
		!strings.Contains(status.Body.String(), `"startedAt":"2026-08-16T12:00:01Z"`) {
		t.Fatalf("status response = %d %s", status.Code, status.Body.String())
	}
	latest := harness.request(t, http.MethodGet, "/api/v1/operations/latest", "", false)
	if latest.Code != http.StatusOK || !strings.Contains(latest.Body.String(), `"state":"available"`) ||
		!strings.Contains(latest.Body.String(), `"reasonCode":"execution_succeeded"`) ||
		!strings.Contains(latest.Body.String(), `"certificateCount":1`) {
		t.Fatalf("latest response = %d %s", latest.Code, latest.Body.String())
	}
}

func TestOperationEndpointsEnforceAuthenticationCSRFAndStrictBodies(t *testing.T) {
	harness := newOperationHTTPHarness(t)
	unauthenticated := httptest.NewRecorder()
	request := newIdentityRequest(http.MethodGet, "/api/v1/operations/status", "", nil, false)
	harness.handler.ServeHTTP(unauthenticated, request)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d %s", unauthenticated.Code, unauthenticated.Body.String())
	}
	withoutCSRF := harness.request(t, http.MethodPost, "/api/v1/operations/manual/previews", `{}`, false)
	if withoutCSRF.Code != http.StatusForbidden || harness.service.previewCalls != 0 {
		t.Fatalf("missing CSRF = %d %s", withoutCSRF.Code, withoutCSRF.Body.String())
	}
	for _, test := range []struct {
		name string
		path string
		body string
	}{
		{name: "preview unknown", path: "/api/v1/operations/manual/previews", body: `{"unknown":true}`},
		{name: "preview duplicate", path: "/api/v1/operations/manual/previews", body: `{} {}`},
		{name: "enqueue unknown", path: "/api/v1/operations/manual", body: `{"reviewedPreviewToken":"` + operationReviewToken + `","unknown":true}`},
		{name: "enqueue duplicate", path: "/api/v1/operations/manual", body: `{"reviewedPreviewToken":"` + operationReviewToken + `","reviewedPreviewToken":"` + operationReviewToken + `"}`},
		{name: "enqueue bad token", path: "/api/v1/operations/manual", body: `{"reviewedPreviewToken":"short"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := harness.request(t, http.MethodPost, test.path, test.body, true)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	request = newIdentityRequest(http.MethodPost, "/api/v1/operations/manual/previews", `{}`, harness.cookies, true)
	request.Header.Del("Content-Type")
	request.Header.Set(csrfHeaderName, harness.csrf)
	wrongMedia := httptest.NewRecorder()
	harness.handler.ServeHTTP(wrongMedia, request)
	if wrongMedia.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong media status = %d %s", wrongMedia.Code, wrongMedia.Body.String())
	}
}

func TestOperationEnqueueReauthorizesImmediatelyBeforeDurableAcceptance(t *testing.T) {
	harness := newOperationHTTPHarness(t)
	session := namedCookie(t, harness.cookies, sessionCookieName).Value
	harness.service.beforeGuard = func(ctx context.Context) error {
		return harness.identity.Logout(ctx, session)
	}
	response := harness.request(t, http.MethodPost, "/api/v1/operations/manual", `{"reviewedPreviewToken":"`+operationReviewToken+`"}`, true)
	if response.Code != http.StatusUnauthorized || harness.service.guardCalls != 1 ||
		!strings.Contains(response.Body.String(), `"code":"authentication_required"`) {
		t.Fatalf("reauthorization response = %d %s, guard calls=%d", response.Code, response.Body.String(), harness.service.guardCalls)
	}
}

func TestOperationEndpointMapsStableServiceErrors(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter bool
	}{
		{name: "active", err: operation.ErrActive, status: http.StatusConflict, code: "operation_active"},
		{name: "changed", err: operation.ErrChanged, status: http.StatusConflict, code: "operation_changed"},
		{name: "recovery", err: operation.ErrRecovery, status: http.StatusConflict, code: "recovery_required"},
		{name: "workspace", err: operation.ErrWorkspace, status: http.StatusConflict, code: "workspace_invalid"},
		{name: "configuration", err: operation.ErrConfiguration, status: http.StatusConflict, code: "configuration_invalid"},
		{name: "busy", err: operation.ErrBusy, status: http.StatusTooManyRequests, code: "service_busy", retryAfter: true},
		{name: "invalid", err: operation.ErrInvalid, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "unavailable", err: operation.ErrUnavailable, status: http.StatusServiceUnavailable, code: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newOperationHTTPHarness(t)
			harness.service.previewErr = test.err
			response := harness.request(t, http.MethodPost, "/api/v1/operations/manual/previews", `{}`, true)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			if test.retryAfter && response.Header().Get("Retry-After") == "" {
				t.Fatal("busy response omitted Retry-After")
			}
		})
	}
}

func TestOperationEndpointDoesNotReflectServiceErrorDetails(t *testing.T) {
	const canary = "TASK08_OPERATION_SECRET_CANARY"
	harness := newOperationHTTPHarness(t)
	harness.service.previewErr = errors.New("upstream failure included " + canary)
	response := harness.request(t, http.MethodPost, "/api/v1/operations/manual/previews", `{}`, true)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), canary) {
		t.Fatalf("service error response = %d %s", response.Code, response.Body.String())
	}
}

func TestOperationStatusAndLatestRepresentEmptyStatesAndRejectInvalidServiceData(t *testing.T) {
	harness := newOperationHTTPHarness(t)
	harness.service.statusErr = jobs.ErrNotFound
	harness.service.latestErr = jobs.ErrNotFound
	status := harness.request(t, http.MethodGet, "/api/v1/operations/status", "", false)
	latest := harness.request(t, http.MethodGet, "/api/v1/operations/latest", "", false)
	if status.Code != http.StatusOK || status.Body.String() != "{\"state\":\"idle\"}\n" ||
		latest.Code != http.StatusOK || latest.Body.String() != "{\"state\":\"empty\"}\n" {
		t.Fatalf("empty responses = status %d %q latest %d %q", status.Code, status.Body.String(), latest.Code, latest.Body.String())
	}
	harness.service.statusErr = nil
	harness.service.status = jobs.Operation{State: jobs.StateSucceeded}
	invalid := harness.request(t, http.MethodGet, "/api/v1/operations/status", "", false)
	if invalid.Code != http.StatusServiceUnavailable || !strings.Contains(invalid.Body.String(), `"code":"service_unavailable"`) {
		t.Fatalf("invalid service projection = %d %s", invalid.Code, invalid.Body.String())
	}
}
