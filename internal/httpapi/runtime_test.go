package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/identity"
	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
	"github.com/acmemux/AcmeMux/internal/state"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

const runtimeTestManifest = "lego-v5.3.1"

type runtimeInspectorStub struct {
	inspectObservation acmeruntime.Observation
	inspectErr         error
	verifyObservation  acmeruntime.Observation
	verifyErr          error
	inspectPaths       []string
	verifyReviewed     []acmeruntime.Observation
	inspectHook        func()
}

func (stub *runtimeInspectorStub) Inspect(_ context.Context, path string) (acmeruntime.Observation, error) {
	stub.inspectPaths = append(stub.inspectPaths, path)
	if stub.inspectHook != nil {
		stub.inspectHook()
	}
	return stub.inspectObservation, stub.inspectErr
}

func (stub *runtimeInspectorStub) Verify(_ context.Context, reviewed acmeruntime.Observation) (acmeruntime.Observation, error) {
	stub.verifyReviewed = append(stub.verifyReviewed, reviewed)
	return stub.verifyObservation, stub.verifyErr
}

type runtimeSelectionsStub struct {
	selection acmeruntime.Selection
	selected  bool
	loadErr   error
	saveErr   error
	saves     []acmeruntime.Selection
}

func (stub *runtimeSelectionsStub) Load(context.Context) (acmeruntime.Selection, error) {
	if stub.loadErr != nil {
		return acmeruntime.Selection{}, stub.loadErr
	}
	if !stub.selected {
		return acmeruntime.Selection{}, acmeruntime.ErrNoSelection
	}
	return stub.selection, nil
}

func (stub *runtimeSelectionsStub) Save(_ context.Context, selection acmeruntime.Selection) error {
	stub.saves = append(stub.saves, selection)
	if stub.saveErr != nil {
		return stub.saveErr
	}
	stub.selection = selection
	stub.selected = true
	return nil
}

type runtimeHTTPHarness struct {
	handler    http.Handler
	cookies    []*http.Cookie
	csrf       string
	inspector  *runtimeInspectorStub
	selections *runtimeSelectionsStub
	journal    *nativeEditJournalStub
	decision   compatibility.Result
	service    *identity.Service
	leaseErr   error
	purposes   []workspace.Purpose
	releases   int
}

func newRuntimeHTTPHarness(t *testing.T) *runtimeHTTPHarness {
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
	if err := service.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}

	observation := runtimeObservationFixture()
	harness := &runtimeHTTPHarness{
		inspector: &runtimeInspectorStub{
			inspectObservation: observation,
			verifyObservation:  observation,
		},
		selections: &runtimeSelectionsStub{},
		journal:    &nativeEditJournalStub{},
		decision: compatibility.Result{
			Code:       compatibility.CodeCompatible,
			ManifestID: compatibility.ManifestLegoV531,
		},
	}
	handler, err := New(
		database,
		service,
		RuntimeDependencies{
			Inspector:  harness.inspector,
			Selections: harness.selections,
			AcquireWorkspace: func(_ context.Context, purpose workspace.Purpose) (func() error, error) {
				harness.purposes = append(harness.purposes, purpose)
				if harness.leaseErr != nil {
					return nil, harness.leaseErr
				}
				return func() error {
					harness.releases++
					return nil
				}, nil
			},
			EditJournal: harness.journal,
			Classify: func(acmeruntime.Observation) compatibility.Result {
				return harness.decision
			},
			Now: func() time.Time { return time.Date(2030, 2, 3, 4, 5, 6, 7, time.UTC) },
		},
		testWorkspaceDependencies(),
		testConfigurationDependencies(),
		testOperationDependencies(),
		fstest.MapFS{"index.html": {Data: []byte("browser")}},
		SecurityConfig{PublicOrigin: identityTestOrigin},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	harness.handler = handler
	harness.service = service

	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", login.Code, login.Body.String())
	}
	harness.cookies = responseCookies(login)
	harness.csrf = namedCookie(t, harness.cookies, csrfCookieName).Value
	return harness
}

func runtimeObservationFixture() acmeruntime.Observation {
	modified := time.Date(2030, 1, 2, 3, 4, 5, 600, time.UTC)
	return acmeruntime.Observation{
		File: acmeruntime.FileIdentity{
			CanonicalPath: "/opt/acmemux/bin/lego",
			Device:        259,
			Inode:         123456,
			Mode:          0o100755,
			UID:           1000,
			GID:           1000,
			Size:          24_001_024,
			ModifiedAt:    modified,
			ChangedAt:     modified.Add(time.Second),
			SHA256:        strings.Repeat("a", 64),
		},
		Version:  acmeruntime.VersionIdentity{Kind: acmeruntime.VersionRelease, Value: "v5.3.1"},
		Platform: acmeruntime.Platform{OS: "linux", Arch: "amd64"},
		Build: acmeruntime.BuildEvidence{
			Available:             true,
			ProvenanceComplete:    true,
			GoVersion:             "go1.26.6",
			CommandPath:           "github.com/go-acme/lego/v5",
			MainPath:              "github.com/go-acme/lego/v5",
			MainVersion:           "v5.3.1",
			DependencyGraphSHA256: strings.Repeat("d", 64),
			GOOS:                  "linux",
			GOARCH:                "amd64",
			VCSRevision:           "589c84af4f26629fbdaa7fbca712f806632ccb7e",
			VCSModifiedKnown:      true,
			VCSModifiedValid:      true,
		},
		VersionOutput: "lego version v5.3.1 linux/amd64",
		ObservedAt:    modified.Add(2 * time.Second),
	}
}

func (harness *runtimeHTTPHarness) request(t *testing.T, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	request := newIdentityRequest(method, path, body, harness.cookies, method != http.MethodGet)
	if csrf {
		request.Header.Set(csrfHeaderName, harness.csrf)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func TestRuntimeHTTPReviewAdoptAndReverifyFlow(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)

	unauthenticated := newIdentityRequest(http.MethodGet, "/api/v1/runtime", "", nil, false)
	unauthenticatedResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(unauthenticatedResponse, unauthenticated)
	assertAPIError(t, unauthenticatedResponse, http.StatusUnauthorized, "authentication_required")

	unselected := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if unselected.Code != http.StatusOK || unselected.Body.String() != "{\"state\":\"unselected\"}\n" {
		t.Fatalf("unselected response = %d %q", unselected.Code, unselected.Body.String())
	}

	missingCSRF := harness.request(t, http.MethodPost, "/api/v1/runtime/candidates", `{"path":"/opt/acmemux/bin/lego"}`, false)
	assertAPIError(t, missingCSRF, http.StatusForbidden, "request_not_allowed")
	if len(harness.inspector.inspectPaths) != 0 {
		t.Fatal("candidate was inspected without CSRF authorization")
	}

	candidate := harness.request(t, http.MethodPost, "/api/v1/runtime/candidates", `{"path":"/opt/acmemux/bin/lego"}`, true)
	if candidate.Code != http.StatusOK {
		t.Fatalf("candidate status = %d, body = %s", candidate.Code, candidate.Body.String())
	}
	var candidateBody map[string]any
	decodeRuntimeResponse(t, candidate, &candidateBody)
	if candidateBody["state"] != "review_required" {
		t.Fatalf("candidate state = %v", candidateBody["state"])
	}
	evidence := candidateBody["candidate"].(map[string]any)
	if evidence["canonicalPath"] != "/opt/acmemux/bin/lego" || evidence["version"] != "v5.3.1" || evidence["commit"] != nil {
		t.Fatalf("candidate identity = %#v", evidence)
	}
	metadata := evidence["metadata"].(map[string]any)
	if metadata["mode"] != "0755" || metadata["device"] != "259" || metadata["inode"] != "123456" || metadata["modifiedAt"] != "2030-01-02T03:04:05.0000006Z" {
		t.Fatalf("candidate metadata = %#v", metadata)
	}
	if metadata["capabilities"] != "none" || metadata["changedAt"] != "2030-01-02T03:04:06.0000006Z" ||
		evidence["versionOutput"] != "lego version v5.3.1 linux/amd64" {
		t.Fatalf("candidate review evidence = %#v", evidence)
	}
	build := evidence["build"].(map[string]any)
	if build["commandPath"] != "github.com/go-acme/lego/v5" || build["dependencyGraphSha256"] != strings.Repeat("d", 64) {
		t.Fatalf("candidate build evidence = %#v", build)
	}
	reviewedEvidenceSHA256, ok := candidateBody["reviewedEvidenceSha256"].(string)
	if !ok || reviewedEvidenceSHA256 != acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, runtimeTestManifest) {
		t.Fatalf("candidate review fingerprint = %#v", candidateBody["reviewedEvidenceSha256"])
	}

	adoptionBody := runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, reviewedEvidenceSHA256)
	adopted := harness.request(t, http.MethodPut, "/api/v1/runtime", adoptionBody, true)
	if adopted.Code != http.StatusOK {
		t.Fatalf("adoption status = %d, body = %s", adopted.Code, adopted.Body.String())
	}
	if len(harness.selections.saves) != 1 {
		t.Fatalf("saved selections = %d, want 1", len(harness.selections.saves))
	}
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeSave || harness.releases != 1 {
		t.Fatalf("workspace leases = %v, releases = %d", harness.purposes, harness.releases)
	}
	saved := harness.selections.saves[0]
	if saved.ManifestID != runtimeTestManifest || saved.Observation.File.SHA256 != strings.Repeat("a", 64) || saved.ReviewedAt != time.Date(2030, 2, 3, 4, 5, 6, 7, time.UTC) {
		t.Fatalf("saved selection = %#v", saved)
	}

	selected := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if selected.Code != http.StatusOK || !strings.Contains(selected.Body.String(), `"state":"supported"`) || !strings.Contains(selected.Body.String(), `"manifestId":"lego-v5.3.1"`) {
		t.Fatalf("selected response = %d %s", selected.Code, selected.Body.String())
	}
	if len(harness.inspector.verifyReviewed) != 1 || harness.inspector.verifyReviewed[0] != saved.Observation {
		t.Fatal("GET did not verify the complete reviewed observation")
	}

	harness.inspector.verifyErr = &acmeruntime.ReplacementError{
		Path:    saved.Observation.File.CanonicalPath,
		Changes: []string{"sha256"},
	}
	changed := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if changed.Code != http.StatusOK || !strings.Contains(changed.Body.String(), `"state":"changed"`) || !strings.Contains(changed.Body.String(), `"code":"executable_replaced"`) {
		t.Fatalf("replacement response = %d %s", changed.Code, changed.Body.String())
	}
}

func TestRuntimeHTTPStrictRequestsAndBoundedDiagnostics(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	initialInspections := len(harness.inspector.inspectPaths)

	requests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
		wantStatus  int
	}{
		{name: "wrong media", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/opt/lego"}`, contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType},
		{name: "unknown field", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/opt/lego","extra":true}`, wantStatus: http.StatusBadRequest},
		{name: "wrong field case", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"Path":"/opt/lego"}`, wantStatus: http.StatusBadRequest},
		{name: "duplicate field", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/opt/lego","path":"/other/lego"}`, wantStatus: http.StatusBadRequest},
		{name: "missing field", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{}`, wantStatus: http.StatusBadRequest},
		{name: "trailing value", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/opt/lego"}{}`, wantStatus: http.StatusBadRequest},
		{name: "relative path", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"bin/lego"}`, wantStatus: http.StatusBadRequest},
		{name: "oversize", method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/` + strings.Repeat("a", maximumRuntimeBodyBytes) + `"}`, wantStatus: http.StatusRequestEntityTooLarge},
		{name: "bad digest", method: http.MethodPut, path: "/api/v1/runtime", body: `{"path":"/opt/lego","reviewedSha256":"ABC","reviewedManifestId":"lego-v5.3.1","reviewedEvidenceSha256":"` + strings.Repeat("b", 64) + `"}`, wantStatus: http.StatusBadRequest},
		{name: "bad manifest", method: http.MethodPut, path: "/api/v1/runtime", body: `{"path":"/opt/lego","reviewedSha256":"` + strings.Repeat("a", 64) + `","reviewedManifestId":"../manifest","reviewedEvidenceSha256":"` + strings.Repeat("b", 64) + `"}`, wantStatus: http.StatusBadRequest},
		{name: "missing review fingerprint", method: http.MethodPut, path: "/api/v1/runtime", body: `{"path":"/opt/lego","reviewedSha256":"` + strings.Repeat("a", 64) + `","reviewedManifestId":"lego-v5.3.1"}`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			request := newIdentityRequest(test.method, test.path, test.body, harness.cookies, true)
			request.Header.Set(csrfHeaderName, harness.csrf)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
	if len(harness.inspector.inspectPaths) != initialInspections {
		t.Fatal("invalid request reached the runtime inspector")
	}

	diagnostics := []struct {
		code acmeruntime.ErrorCode
		want string
	}{
		{code: acmeruntime.CodePathUnavailable, want: "missing"},
		{code: acmeruntime.CodeUnsafePermissions, want: "unsafe"},
		{code: acmeruntime.CodeMalformedVersion, want: "malformed_output"},
		{code: acmeruntime.CodeBuildIdentityMismatch, want: "malformed_output"},
		{code: acmeruntime.CodeExecutableNotQualified, want: "unsafe"},
		{code: acmeruntime.CodeProbeTimeout, want: "timed_out"},
		{code: acmeruntime.CodeInspectionTimeout, want: "timed_out"},
		{code: acmeruntime.CodeInspectionCanceled, want: "malformed_output"},
	}
	for _, test := range diagnostics {
		harness.inspector.inspectErr = &acmeruntime.Error{Code: test.code, Detail: "sensitive host or probe detail"}
		response := harness.request(t, http.MethodPost, "/api/v1/runtime/candidates", `{"path":"/opt/acmemux/bin/lego"}`, true)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"`+test.want+`"`) || !strings.Contains(response.Body.String(), `"code":"`+string(test.code)+`"`) {
			t.Fatalf("diagnostic %s response = %d %s", test.code, response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "sensitive") {
			t.Fatalf("diagnostic %s exposed internal detail", test.code)
		}
	}
}

func TestRuntimeHTTPAdoptionFailsClosed(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	valid := func(hash, manifest string) string {
		return runtimeAdoptionBody(hash, manifest, acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, manifest))
	}

	for _, test := range []struct {
		name     string
		body     string
		decision compatibility.Result
		err      error
	}{
		{name: "digest changed", body: valid(strings.Repeat("b", 64), runtimeTestManifest), decision: harness.decision},
		{name: "manifest changed", body: valid(strings.Repeat("a", 64), "lego-revision-2a58c3522708"), decision: harness.decision},
		{name: "review evidence changed", body: runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, strings.Repeat("b", 64)), decision: harness.decision},
		{name: "classification blocked", body: valid(strings.Repeat("a", 64), runtimeTestManifest), decision: compatibility.Result{Code: compatibility.CodeBuildModified, ManifestID: compatibility.ManifestLegoV531}},
		{name: "inspection blocked", body: valid(strings.Repeat("a", 64), runtimeTestManifest), decision: harness.decision, err: &acmeruntime.Error{Code: acmeruntime.CodeChangedDuringInspection}},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness.decision = test.decision
			harness.inspector.inspectErr = test.err
			before := len(harness.selections.saves)
			response := harness.request(t, http.MethodPut, "/api/v1/runtime", test.body, true)
			assertAPIError(t, response, http.StatusConflict, "runtime_changed")
			if len(harness.selections.saves) != before {
				t.Fatal("failed adoption persisted a runtime selection")
			}
		})
	}

	harness.inspector.inspectErr = errors.New("sensitive internal inspector failure")
	unknownFailure := harness.request(t, http.MethodPut, "/api/v1/runtime", valid(strings.Repeat("a", 64), runtimeTestManifest), true)
	assertAPIError(t, unknownFailure, http.StatusServiceUnavailable, "service_unavailable")
	if strings.Contains(unknownFailure.Body.String(), "sensitive") {
		t.Fatal("internal inspector error escaped the API")
	}

	harness.inspector.inspectErr = nil
	harness.decision = compatibility.Result{Code: compatibility.CodeCompatible, ManifestID: compatibility.ManifestLegoV531}
	harness.selections.saveErr = errors.New("sensitive database failure")
	storeFailure := harness.request(t, http.MethodPut, "/api/v1/runtime", valid(strings.Repeat("a", 64), runtimeTestManifest), true)
	assertAPIError(t, storeFailure, http.StatusServiceUnavailable, "service_unavailable")
	if strings.Contains(storeFailure.Body.String(), "sensitive") {
		t.Fatal("selection persistence error escaped the API")
	}
}

func TestRuntimeHTTPInspectionBusyIsRetryableAndNeverBlamesTheExecutable(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	busy := &acmeruntime.Error{Code: acmeruntime.CodeInspectionBusy, Detail: "sensitive queue detail"}

	harness.inspector.inspectErr = busy
	for _, request := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/api/v1/runtime/candidates", body: `{"path":"/opt/acmemux/bin/lego"}`},
		{method: http.MethodPut, path: "/api/v1/runtime", body: runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, runtimeTestManifest))},
	} {
		response := harness.request(t, request.method, request.path, request.body, true)
		assertAPIError(t, response, http.StatusServiceUnavailable, "service_unavailable")
		if response.Header().Get("Retry-After") != "1" || strings.Contains(response.Body.String(), "sensitive") {
			t.Fatalf("busy response = headers %#v, body %s", response.Header(), response.Body.String())
		}
	}

	harness.inspector.inspectErr = nil
	harness.selections.selected = true
	harness.selections.selection = acmeruntime.Selection{
		Observation: harness.inspector.inspectObservation,
		ManifestID:  runtimeTestManifest,
		ReviewedAt:  time.Now().UTC(),
	}
	harness.inspector.verifyErr = &acmeruntime.ReplacementError{
		Path:  harness.inspector.inspectObservation.File.CanonicalPath,
		Cause: busy,
	}
	response := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	assertAPIError(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if response.Header().Get("Retry-After") != "1" || strings.Contains(response.Body.String(), "unsafe") {
		t.Fatalf("busy selected response = headers %#v, body %s", response.Header(), response.Body.String())
	}
}

func TestRuntimeHTTPWorkspaceContentionBlocksAdoptionBeforeInspection(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	harness.leaseErr = workspace.ErrWorkspaceBusy
	review := acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, runtimeTestManifest)
	response := harness.request(t, http.MethodPut, "/api/v1/runtime", runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, review), true)
	assertAPIError(t, response, http.StatusTooManyRequests, "service_busy")
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeSave ||
		harness.releases != 0 || len(harness.inspector.inspectPaths) != 0 || len(harness.selections.saves) != 0 {
		t.Fatalf("contention effects: purposes=%v releases=%d inspections=%d saves=%d", harness.purposes, harness.releases, len(harness.inspector.inspectPaths), len(harness.selections.saves))
	}
}

func TestRuntimeHTTPPendingNativeEditRecoveryBlocksAdoptionBeforeInspection(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	harness.journal.pending = true
	review := acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, runtimeTestManifest)

	response := harness.request(t, http.MethodPut, "/api/v1/runtime", runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, review), true)

	assertAPIError(t, response, http.StatusConflict, "recovery_required")
	if strings.TrimSpace(response.Body.String()) != `{"error":{"code":"recovery_required","message":"Resolve the interrupted native configuration edit before changing the selected runtime or workspace."}}` {
		t.Fatalf("recovery response = %s", response.Body.String())
	}
	if harness.journal.loads != 1 || len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeSave ||
		harness.releases != 1 || len(harness.inspector.inspectPaths) != 0 || len(harness.selections.saves) != 0 {
		t.Fatalf("recovery effects: loads=%d purposes=%v releases=%d inspections=%d saves=%d",
			harness.journal.loads, harness.purposes, harness.releases, len(harness.inspector.inspectPaths), len(harness.selections.saves))
	}
}

func TestRuntimeHTTPRevalidatesSessionImmediatelyBeforeAdoption(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	harness.inspector.inspectHook = func() {
		if err := harness.service.RevokeSessions(context.Background()); err != nil {
			t.Errorf("RevokeSessions() error = %v", err)
		}
	}
	review := acmeruntime.ReviewFingerprint(harness.inspector.inspectObservation, runtimeTestManifest)
	response := harness.request(t, http.MethodPut, "/api/v1/runtime", runtimeAdoptionBody(strings.Repeat("a", 64), runtimeTestManifest, review), true)
	assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	if len(harness.selections.saves) != 0 {
		t.Fatal("selection was saved after the administrator sessions were revoked")
	}
}

func TestPresentRuntimeEvidenceExposesAllowedCapability(t *testing.T) {
	observation := runtimeObservationFixture()
	observation.File.Capabilities = "cap_net_bind_service=ep"
	evidence := presentRuntimeEvidence(observation)
	if evidence.Metadata.Capabilities != "cap_net_bind_service=ep" {
		t.Fatalf("capabilities = %q", evidence.Metadata.Capabilities)
	}
}

func runtimeAdoptionBody(hash, manifest, reviewedEvidenceSHA256 string) string {
	return `{"path":"/opt/acmemux/bin/lego","reviewedSha256":"` + hash +
		`","reviewedManifestId":"` + manifest + `","reviewedEvidenceSha256":"` + reviewedEvidenceSHA256 + `"}`
}

func TestRuntimeHTTPSelectedDiagnosticsAndCompatibilityDrift(t *testing.T) {
	harness := newRuntimeHTTPHarness(t)
	observation := runtimeObservationFixture()
	harness.selections.selected = true
	harness.selections.selection = acmeruntime.Selection{
		Observation: observation,
		ManifestID:  runtimeTestManifest,
		ReviewedAt:  time.Date(2030, 2, 3, 4, 5, 6, 7, time.UTC),
	}

	harness.inspector.verifyErr = &acmeruntime.ReplacementError{
		Path:  observation.File.CanonicalPath,
		Cause: &acmeruntime.Error{Code: acmeruntime.CodePathUnavailable, Detail: "sensitive path detail"},
	}
	missing := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if missing.Code != http.StatusOK ||
		!strings.Contains(missing.Body.String(), `"state":"missing"`) ||
		!strings.Contains(missing.Body.String(), `"runtime":{"canonicalPath":"/opt/acmemux/bin/lego"`) ||
		strings.Contains(missing.Body.String(), "sensitive") {
		t.Fatalf("missing response = %d %s", missing.Code, missing.Body.String())
	}

	harness.inspector.verifyErr = nil
	harness.decision = compatibility.Result{Code: compatibility.CodeUnknownIdentity}
	unverified := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if unverified.Code != http.StatusOK ||
		!strings.Contains(unverified.Body.String(), `"state":"unverified"`) ||
		!strings.Contains(unverified.Body.String(), `"code":"unknown_identity"`) {
		t.Fatalf("unverified response = %d %s", unverified.Code, unverified.Body.String())
	}

	harness.decision = compatibility.Result{Code: compatibility.CodeCompatible, ManifestID: compatibility.ManifestLegoRevision2A58}
	incompatible := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	if incompatible.Code != http.StatusOK || !strings.Contains(incompatible.Body.String(), `"state":"incompatible"`) || strings.Contains(incompatible.Body.String(), `"manifestId"`) {
		t.Fatalf("manifest drift response = %d %s", incompatible.Code, incompatible.Body.String())
	}

	harness.selections.loadErr = errors.New("sensitive database failure")
	unavailable := harness.request(t, http.MethodGet, "/api/v1/runtime", "", false)
	assertAPIError(t, unavailable, http.StatusServiceUnavailable, "service_unavailable")
	if strings.Contains(unavailable.Body.String(), "sensitive") {
		t.Fatal("load failure escaped the API")
	}
}

func TestNewRejectsIncompleteRuntimeDependencies(t *testing.T) {
	valid := testRuntimeDependencies()
	for _, test := range []struct {
		name         string
		dependencies RuntimeDependencies
	}{
		{name: "missing inspector", dependencies: RuntimeDependencies{Selections: valid.Selections, Classify: valid.Classify, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal}},
		{name: "missing selections", dependencies: RuntimeDependencies{Inspector: valid.Inspector, Classify: valid.Classify, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal}},
		{name: "missing classifier", dependencies: RuntimeDependencies{Inspector: valid.Inspector, Selections: valid.Selections, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal}},
		{name: "missing coordinator", dependencies: RuntimeDependencies{Inspector: valid.Inspector, Selections: valid.Selections, Classify: valid.Classify, EditJournal: valid.EditJournal}},
		{name: "missing edit journal", dependencies: RuntimeDependencies{Inspector: valid.Inspector, Selections: valid.Selections, Classify: valid.Classify, AcquireWorkspace: valid.AcquireWorkspace}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(
				readinessStub{},
				sharedTestIdentity(t),
				test.dependencies,
				testWorkspaceDependencies(),
				testConfigurationDependencies(),
				testOperationDependencies(),
				fstest.MapFS{},
				SecurityConfig{PublicOrigin: testPublicOrigin},
			)
			if err == nil {
				t.Fatal("New() error = nil")
			}
		})
	}
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("API error = %d %s, want %d %s", response.Code, response.Body.String(), status, code)
	}
}

func decodeRuntimeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode runtime response: %v; body = %s", err, response.Body.String())
	}
}
