package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	"github.com/sgurden-certleap/AcmeMux/internal/reporting"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

type workspaceInspectorStub struct {
	inspectReview workspace.Review
	inspectErr    error
	verifyReview  workspace.Review
	verifyErr     error
	requests      []workspace.Request
	verified      []workspace.Review
}

func (stub *workspaceInspectorStub) Inspect(_ context.Context, request workspace.Request) (workspace.Review, error) {
	stub.requests = append(stub.requests, request)
	return stub.inspectReview, stub.inspectErr
}

func (stub *workspaceInspectorStub) Verify(_ context.Context, review workspace.Review) (workspace.Review, error) {
	stub.verified = append(stub.verified, review)
	return stub.verifyReview, stub.verifyErr
}

type workspaceSelectionsStub struct {
	selection workspace.Selection
	selected  bool
	loadErr   error
	saveErr   error
	saves     []workspace.Selection
}

func (stub *workspaceSelectionsStub) Load(context.Context) (workspace.Selection, error) {
	if stub.loadErr != nil {
		return workspace.Selection{}, stub.loadErr
	}
	if !stub.selected {
		return workspace.Selection{}, workspace.ErrNoSelection
	}
	return stub.selection, nil
}

func (stub *workspaceSelectionsStub) Save(_ context.Context, selection workspace.Selection) error {
	stub.saves = append(stub.saves, selection)
	if stub.saveErr != nil {
		return stub.saveErr
	}
	stub.selection = selection
	stub.selected = true
	return nil
}

type preparedWorkspaceStub struct {
	closed int
}

func (*preparedWorkspaceStub) StartContext(context.Context, func(*exec.Cmd) error, ...string) (*exec.Cmd, error) {
	return nil, errors.New("unexpected prepared executable start")
}

func (prepared *preparedWorkspaceStub) Close() error {
	prepared.closed++
	return nil
}

type workspaceInventoryStub struct {
	certificates []inventory.Certificate
	err          error
	paths        []string
	hook         func()
}

func (stub *workspaceInventoryStub) Read(_ context.Context, prepared inventory.PreparedExecutable, path string) ([]inventory.Certificate, error) {
	stub.paths = append(stub.paths, path)
	if stub.hook != nil {
		stub.hook()
	}
	_ = prepared.Close()
	return stub.certificates, stub.err
}

type workspaceHTTPHarness struct {
	handler      http.Handler
	cookies      []*http.Cookie
	csrf         string
	service      *identity.Service
	inspector    *workspaceInspectorStub
	selections   *workspaceSelectionsStub
	journal      *nativeEditJournalStub
	inventory    *workspaceInventoryStub
	prepareErr   error
	prepared     []*preparedWorkspaceStub
	prepareCount int
	leaseErr     error
	purposes     []workspace.Purpose
	releases     int
}

func newWorkspaceHTTPHarness(t *testing.T) *workspaceHTTPHarness {
	t.Helper()
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	service, err := identity.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	review := workspaceReviewFixture()
	harness := &workspaceHTTPHarness{
		service:    service,
		inspector:  &workspaceInspectorStub{inspectReview: review, verifyReview: review},
		selections: &workspaceSelectionsStub{},
		journal:    &nativeEditJournalStub{},
		inventory:  &workspaceInventoryStub{},
	}
	dependencies := WorkspaceDependencies{
		Inspector:  harness.inspector,
		Selections: harness.selections,
		Inventory:  harness.inventory,
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
		PrepareRuntime: func(context.Context) (inventory.PreparedExecutable, error) {
			harness.prepareCount++
			if harness.prepareErr != nil {
				return nil, harness.prepareErr
			}
			prepared := &preparedWorkspaceStub{}
			harness.prepared = append(harness.prepared, prepared)
			return prepared, nil
		},
		Now: func() time.Time { return time.Date(2031, 2, 3, 4, 5, 6, 7, time.UTC) },
	}
	handler, err := New(
		database,
		service,
		testRuntimeDependencies(),
		dependencies,
		testConfigurationDependencies(),
		testOperationDependencies(),
		fstest.MapFS{"index.html": {Data: []byte("browser")}},
		SecurityConfig{PublicOrigin: identityTestOrigin},
	)
	if err != nil {
		t.Fatal(err)
	}
	harness.handler = handler
	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	harness.cookies = responseCookies(login)
	harness.csrf = namedCookie(t, harness.cookies, csrfCookieName).Value
	return harness
}

func (harness *workspaceHTTPHarness) request(t *testing.T, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	request := newIdentityRequest(method, path, body, harness.cookies, method != http.MethodGet)
	if csrf {
		request.Header.Set(csrfHeaderName, harness.csrf)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func TestWorkspaceGetUnadoptedUsesExactMinimalState(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"state":"unadopted"}` {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if harness.prepareCount != 0 {
		t.Fatal("unadopted workspace prepared a runtime")
	}
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeInventory || harness.releases != 1 {
		t.Fatalf("workspace leases = %v, releases = %d", harness.purposes, harness.releases)
	}
}

func TestWorkspaceCandidateMapsCompleteBoundEvidenceWithoutRawDetail(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	review := workspaceReviewFixture()
	review.Diagnostics = []workspace.Diagnostic{{
		Code: workspace.CodeConfigurationPrecedence, Severity: workspace.SeverityNotice,
		Role: workspace.RoleConfiguration, Path: review.Configuration.Path,
		Component: "/secret/component", Detail: "sensitive internal detail",
	}}
	review.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(review)
	harness.inspector.inspectReview = review

	response := harness.request(t, http.MethodPost, "/api/v1/workspace/candidates", `{"workingDirectory":"/srv/lego","configurationPath":null}`, true)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	var candidate workspaceCandidate
	if err := json.Unmarshal(response.Body.Bytes(), &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.State != "review_required" || !candidate.Adoptable || candidate.ReviewedEvidenceSHA256 != review.ReviewedEvidenceSHA256 {
		t.Fatalf("candidate = %#v", candidate)
	}
	if len(candidate.Candidate.WorkingDirectory.Components) == 0 || candidate.Candidate.Storage.Metadata == nil {
		t.Fatal("candidate omitted path or component evidence")
	}
	if strings.Contains(response.Body.String(), "sensitive internal detail") || strings.Contains(response.Body.String(), `"nlink":2,"access"`) {
		t.Fatalf("response exposed raw detail or volatile component nlink: %s", response.Body.String())
	}
	if len(candidate.Diagnostics) != 1 || candidate.Diagnostics[0].Component == nil || *candidate.Diagnostics[0].Component != "/secret/component" {
		t.Fatalf("diagnostics = %#v", candidate.Diagnostics)
	}
	if len(harness.inspector.requests) != 1 || harness.inspector.requests[0].ConfigurationPath != "" {
		t.Fatalf("inspector requests = %#v", harness.inspector.requests)
	}
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeRead || harness.releases != 1 {
		t.Fatalf("workspace leases = %v, releases = %d", harness.purposes, harness.releases)
	}
	if len(harness.prepared) != 1 || harness.prepared[0].closed != 1 {
		t.Fatalf("prepared handles = %#v", harness.prepared)
	}
}

func TestWorkspaceGetReadyInventoriesExactStorageAndPreservesNotice(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	review := workspaceReviewFixture()
	review.Diagnostics = []workspace.Diagnostic{{
		Code: workspace.CodeConfigurationPrecedence, Severity: workspace.SeverityNotice,
		Role: workspace.RoleConfiguration, Path: review.Configuration.Path, Component: "/srv/lego/.lego.yaml", Detail: "fixed safe detail",
	}}
	review.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(review)
	harness.selections.selected = true
	harness.selections.selection = workspace.Selection{Review: review, ReviewedAt: time.Now().UTC()}
	harness.inspector.verifyReview = review
	harness.inventory.certificates = []inventory.Certificate{{
		Name: "gateway.home.example", DNSNames: []string{"gateway.home.example", "home.example"},
		Issuer: "Home CA", ExpiresAt: time.Date(2032, 1, 2, 3, 4, 5, 6, time.UTC),
		NativePath: "/srv/lego/.lego/certificates/gateway.home.example.crt",
		Artifact: inventory.FileMetadata{Device: 2, Inode: 3, Mode: 0o100600, UID: 991, GID: 991, LinkCount: 1, Size: 2048,
			ModifiedAt: time.Date(2031, 1, 1, 0, 0, 0, 1, time.UTC), ChangedAt: time.Date(2031, 1, 1, 0, 0, 0, 2, time.UTC)},
	}}

	response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	var snapshot workspaceSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.State != "ready" || len(snapshot.Inventory) != 1 || len(snapshot.Diagnostics) != 1 ||
		snapshot.InventoryObservedAt == nil || snapshot.Inventory[0].Health != "healthy" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if len(harness.inventory.paths) != 1 || harness.inventory.paths[0] != review.Storage.Path {
		t.Fatalf("inventory paths = %q", harness.inventory.paths)
	}
	if snapshot.Inventory[0].Artifact.NativePath == "" || snapshot.Inventory[0].Artifact.NLink != 1 {
		t.Fatalf("inventory = %#v", snapshot.Inventory)
	}
}

func TestWorkspaceCertificatePresentationUsesEmptyDNSArray(t *testing.T) {
	projection, err := reporting.ProjectInventory([]inventory.Certificate{{
		Name:       "192.0.2.10",
		DNSNames:   nil,
		Issuer:     "Home CA",
		ExpiresAt:  time.Date(2032, 1, 2, 3, 4, 5, 0, time.UTC),
		NativePath: "/srv/lego/.lego/certificates/192.0.2.10.crt",
	}}, time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	presented := presentWorkspaceCertificates(projection.Certificates)
	encoded, err := json.Marshal(presented)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"dnsNames":[]`) {
		t.Fatalf("presentation = %s", encoded)
	}
}

func TestWorkspaceGetRechecksPathsAfterInventoryBeforeReportingReady(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	reviewed := workspaceReviewFixture()
	changed := reviewed
	changed.Storage.Inode++
	changed.Diagnostics = []workspace.Diagnostic{{
		Code: workspace.CodeChangedDuringInspection, Severity: workspace.SeverityBlocking,
		Role: workspace.RoleStorage, Path: changed.Storage.Path, Component: changed.Storage.Path,
	}}
	changed.Adoptable = false
	changed.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(changed)
	harness.selections.selected = true
	harness.selections.selection = workspace.Selection{Review: reviewed, ReviewedAt: time.Now().UTC()}
	harness.inspector.verifyReview = reviewed
	harness.inventory.hook = func() {
		harness.inspector.verifyReview = changed
		harness.inspector.verifyErr = &workspace.VerificationError{Reviewed: reviewed, Current: changed, Changes: []string{"storage"}}
	}

	response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"unsafe"`) ||
		!strings.Contains(response.Body.String(), `"code":"review_evidence_changed"`) ||
		strings.Contains(response.Body.String(), `"state":"ready"`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if len(harness.inspector.verified) != 2 {
		t.Fatalf("Verify() count = %d, want 2", len(harness.inspector.verified))
	}
}

func TestChangedWorkspaceSnapshotReservesBoundedMandatoryDiagnostic(t *testing.T) {
	for _, test := range []struct {
		name      string
		stateCode workspace.ErrorCode
		wantState string
	}{
		{name: "unsafe", stateCode: workspace.CodePathPermissionsUnsafe, wantState: "unsafe"},
		{name: "missing", stateCode: workspace.CodePathMissing, wantState: "missing"},
		{name: "read only", stateCode: workspace.CodePathReadOnly, wantState: "read_only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := workspaceReviewFixture()
			current.Diagnostics = make([]workspace.Diagnostic, maximumWorkspaceDiagnosticCount)
			for index := range current.Diagnostics {
				current.Diagnostics[index] = workspace.Diagnostic{
					Code: workspace.CodePathPermissionsUnsafe, Severity: workspace.SeverityBlocking,
					Role: workspace.RoleStorage, Path: current.Storage.Path, Component: current.Storage.Path,
				}
			}
			current.Diagnostics[maximumWorkspaceDiagnosticCount-2].Code = test.stateCode
			current.Diagnostics[len(current.Diagnostics)-1] = workspace.Diagnostic{
				Code: workspace.CodeReviewEvidenceLimit, Severity: workspace.SeverityBlocking, Role: workspace.RoleWorkspace,
			}
			response := httptest.NewRecorder()
			changed := &workspace.VerificationError{Current: current, Changes: []string{"diagnostics"}}
			if !writeChangedWorkspaceSnapshot(response, current, changed) {
				t.Fatal("writeChangedWorkspaceSnapshot() = false")
			}
			var snapshot workspaceSnapshot
			if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.State != test.wantState || len(snapshot.Diagnostics) != maximumWorkspaceDiagnosticCount {
				t.Fatalf("snapshot state/count = %s/%d", snapshot.State, len(snapshot.Diagnostics))
			}
			codes := make(map[string]bool, len(snapshot.Diagnostics))
			for _, diagnostic := range snapshot.Diagnostics {
				codes[diagnostic.Code] = true
			}
			if !codes[string(test.stateCode)] || !codes[string(workspace.CodeReviewEvidenceLimit)] ||
				!codes[string(workspace.CodeReviewEvidenceChanged)] {
				t.Fatalf("diagnostic codes = %#v", codes)
			}
		})
	}
}

func TestWorkspaceAdoptionReinspectsInventoriesReauthorizesAndSaves(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	review := workspaceReviewFixture()
	harness.inspector.inspectReview = review
	response := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+review.ReviewedEvidenceSHA256+`"}`, true)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if len(harness.selections.saves) != 1 || harness.selections.saves[0].Review.ReviewedEvidenceSHA256 != review.ReviewedEvidenceSHA256 {
		t.Fatalf("saves = %#v", harness.selections.saves)
	}
	if got := harness.selections.saves[0].ReviewedAt; !got.Equal(time.Date(2031, 2, 3, 4, 5, 6, 7, time.UTC)) {
		t.Fatalf("ReviewedAt = %s", got)
	}
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeInventory || harness.releases != 1 {
		t.Fatalf("workspace leases = %v, releases = %d", harness.purposes, harness.releases)
	}

	changed := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+strings.Repeat("a", 64)+`"}`, true)
	assertAPIError(t, changed, http.StatusConflict, "workspace_changed")
	if len(harness.selections.saves) != 1 {
		t.Fatal("changed evidence was saved")
	}
}

func TestWorkspaceAdoptionReturnsPreciseInventoryBlockerWithoutSaving(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	review := workspaceReviewFixture()
	harness.inspector.inspectReview = review
	harness.inventory.err = &inventory.Error{
		Code:   inventory.CodeUnsafePermissions,
		Path:   "/srv/lego/.lego/certificates/example.com.key",
		Detail: "sensitive mode detail",
	}

	response := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+review.ReviewedEvidenceSHA256+`"}`, true)
	if response.Code != http.StatusOK {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	var candidate workspaceCandidate
	if err := json.Unmarshal(response.Body.Bytes(), &candidate); err != nil {
		t.Fatal(err)
	}
	if candidate.State != "review_required" || candidate.Adoptable || len(candidate.Diagnostics) != 1 ||
		candidate.Diagnostics[0].Code != string(inventory.CodeUnsafePermissions) ||
		candidate.Diagnostics[0].Path == nil || *candidate.Diagnostics[0].Path != harness.inventory.err.(*inventory.Error).Path {
		t.Fatalf("candidate = %#v", candidate)
	}
	if strings.Contains(response.Body.String(), "sensitive mode detail") || len(harness.selections.saves) != 0 {
		t.Fatalf("inventory blocker leaked detail or saved selection: %s", response.Body.String())
	}
}

func TestWorkspaceAdoptionDoesNotSaveAfterConcurrentSessionRevocation(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	harness.inventory.hook = func() {
		if err := harness.service.RevokeSessions(context.Background()); err != nil {
			t.Errorf("RevokeSessions() error = %v", err)
		}
	}
	review := harness.inspector.inspectReview
	response := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+review.ReviewedEvidenceSHA256+`"}`, true)
	assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	if len(harness.selections.saves) != 0 {
		t.Fatal("revoked request saved a workspace")
	}
}

func TestWorkspaceAdoptionRechecksPathsAfterInventoryBeforeSaving(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	review := harness.inspector.inspectReview
	current := review
	current.Storage.Inode++
	current.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(current)
	harness.inventory.hook = func() {
		harness.inspector.verifyReview = current
		harness.inspector.verifyErr = &workspace.VerificationError{Reviewed: review, Current: current, Changes: []string{"storage"}}
	}
	response := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+review.ReviewedEvidenceSHA256+`"}`, true)
	assertAPIError(t, response, http.StatusConflict, "workspace_changed")
	if len(harness.selections.saves) != 0 || len(harness.inspector.verified) != 1 {
		t.Fatalf("saves = %d, verifies = %d", len(harness.selections.saves), len(harness.inspector.verified))
	}
}

func TestWorkspaceGetReportsChangedMissingReadOnlyAndUnsafeStates(t *testing.T) {
	tests := []struct {
		name  string
		code  workspace.ErrorCode
		state string
		path  *workspace.PathEvidence
	}{
		{name: "missing", code: workspace.CodePathMissing, state: "missing"},
		{name: "read only", code: workspace.CodePathReadOnly, state: "read_only"},
		{name: "unsafe", code: workspace.CodePathPermissionsUnsafe, state: "unsafe"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newWorkspaceHTTPHarness(t)
			reviewed := workspaceReviewFixture()
			current := workspaceReviewFixture()
			target := &current.Storage
			if test.state == "missing" {
				target.Exists = false
				target.Type = workspace.PathTypeMissing
				target.Safe = false
			}
			current.Diagnostics = []workspace.Diagnostic{{Code: test.code, Severity: workspace.SeverityBlocking, Role: workspace.RoleStorage, Path: target.Path, Component: target.Path, Detail: "secret detail"}}
			current.Adoptable = false
			current.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(current)
			harness.selections.selected = true
			harness.selections.selection = workspace.Selection{Review: reviewed, ReviewedAt: time.Now().UTC()}
			harness.inspector.verifyReview = current
			harness.inspector.verifyErr = &workspace.VerificationError{Reviewed: reviewed, Current: current, Changes: []string{"storage"}}

			response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"`+test.state+`"`) {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "secret detail") || len(harness.inventory.paths) != 0 || harness.prepared[0].closed != 1 {
				t.Fatalf("unsafe response leaked detail, inventoried, or leaked handle: %s", response.Body.String())
			}
		})
	}
}

func TestWorkspaceRuntimeAndInventoryFailuresAreBounded(t *testing.T) {
	t.Run("runtime busy", func(t *testing.T) {
		harness := newWorkspaceHTTPHarness(t)
		harness.selections.selected = true
		harness.selections.selection = workspace.Selection{Review: workspaceReviewFixture(), ReviewedAt: time.Now().UTC()}
		harness.prepareErr = &acmeruntime.ReplacementError{Cause: &acmeruntime.Error{Code: acmeruntime.CodeInspectionBusy}}
		response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
		assertAPIError(t, response, http.StatusServiceUnavailable, "service_busy")
		if response.Header().Get("Retry-After") != "1" {
			t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
		}
	})
	t.Run("runtime", func(t *testing.T) {
		harness := newWorkspaceHTTPHarness(t)
		harness.selections.selected = true
		harness.selections.selection = workspace.Selection{Review: workspaceReviewFixture(), ReviewedAt: time.Now().UTC()}
		harness.prepareErr = errors.New("sensitive runtime failure")
		response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"incompatible"`) || strings.Contains(response.Body.String(), "sensitive") {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("inventory", func(t *testing.T) {
		harness := newWorkspaceHTTPHarness(t)
		review := workspaceReviewFixture()
		harness.selections.selected = true
		harness.selections.selection = workspace.Selection{Review: review, ReviewedAt: time.Now().UTC()}
		harness.inventory.err = &inventory.Error{Code: inventory.CodeMalformedOutput, Path: "/sensitive\tchild-path", Cause: errors.New("sensitive child output")}
		response := harness.request(t, http.MethodGet, "/api/v1/workspace", "", false)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"inventory_unavailable"`) || strings.Contains(response.Body.String(), "sensitive") || !strings.Contains(response.Body.String(), `"path":null`) {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestWorkspaceContentionBlocksInspectionBeforeNativeWork(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	harness.leaseErr = workspace.ErrWorkspaceBusy
	response := harness.request(t, http.MethodPost, "/api/v1/workspace/candidates", `{"workingDirectory":"/srv/lego","configurationPath":null}`, true)
	assertAPIError(t, response, http.StatusTooManyRequests, "service_busy")
	if len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeRead || harness.releases != 0 ||
		harness.prepareCount != 0 || len(harness.inspector.requests) != 0 {
		t.Fatalf("contention effects: purposes=%v releases=%d prepares=%d inspections=%d", harness.purposes, harness.releases, harness.prepareCount, len(harness.inspector.requests))
	}
}

func TestWorkspacePendingNativeEditRecoveryBlocksAdoptionBeforeNativeWork(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	harness.journal.pending = true
	review := harness.inspector.inspectReview

	response := harness.request(t, http.MethodPut, "/api/v1/workspace", `{"workingDirectory":"/srv/lego","configurationPath":"/srv/lego/.lego.yml","reviewedEvidenceSha256":"`+review.ReviewedEvidenceSHA256+`"}`, true)

	assertAPIError(t, response, http.StatusConflict, "recovery_required")
	if strings.TrimSpace(response.Body.String()) != `{"error":{"code":"recovery_required","message":"Resolve the interrupted native configuration edit before changing the selected runtime or workspace."}}` {
		t.Fatalf("recovery response = %s", response.Body.String())
	}
	if harness.journal.loads != 1 || len(harness.purposes) != 1 || harness.purposes[0] != workspace.PurposeInventory ||
		harness.releases != 1 || harness.prepareCount != 0 || len(harness.inspector.requests) != 0 ||
		len(harness.inventory.paths) != 0 || len(harness.selections.saves) != 0 {
		t.Fatalf("recovery effects: loads=%d purposes=%v releases=%d prepares=%d inspections=%d inventory=%d saves=%d",
			harness.journal.loads, harness.purposes, harness.releases, harness.prepareCount, len(harness.inspector.requests),
			len(harness.inventory.paths), len(harness.selections.saves))
	}
}

func TestWorkspaceBoundaryRejectsMissingAuthCSRFAndMalformedBodies(t *testing.T) {
	harness := newWorkspaceHTTPHarness(t)
	unauthenticated := newIdentityRequest(http.MethodGet, "/api/v1/workspace", "", nil, false)
	unauthenticatedResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(unauthenticatedResponse, unauthenticated)
	assertAPIError(t, unauthenticatedResponse, http.StatusUnauthorized, "authentication_required")

	missingCSRF := harness.request(t, http.MethodPost, "/api/v1/workspace/candidates", `{"workingDirectory":"/srv/lego","configurationPath":null}`, false)
	assertAPIError(t, missingCSRF, http.StatusForbidden, "request_not_allowed")

	for _, body := range []string{
		`{"workingDirectory":"relative","configurationPath":null}`,
		`{"workingDirectory":"/srv/lego","configurationPath":""}`,
		`{"workingDirectory":"/srv/lego","configurationPath":null,"unknown":true}`,
		`{"workingDirectory":"/srv/lego","workingDirectory":"/srv/other","configurationPath":null}`,
		`{"workingDirectory":"/srv/lego"}`,
	} {
		response := harness.request(t, http.MethodPost, "/api/v1/workspace/candidates", body, true)
		assertAPIError(t, response, http.StatusBadRequest, "invalid_request")
	}
	oversize := `{"workingDirectory":"/srv/` + strings.Repeat("a", maximumWorkspaceBodyBytes) + `","configurationPath":null}`
	response := harness.request(t, http.MethodPost, "/api/v1/workspace/candidates", oversize, true)
	assertAPIError(t, response, http.StatusRequestEntityTooLarge, "invalid_request")
}

func TestWorkspacePresentationPreservesPartialTraversalWithoutFabricatingFinalMetadata(t *testing.T) {
	base := workspace.PathEvidence{
		Role: workspace.RoleStorage, Path: "/srv/blocked/certificates", Type: workspace.PathTypeUnknown,
		Components: []workspace.ComponentEvidence{
			{Path: "/", Type: workspace.PathTypeDirectory, Device: 2, Inode: 1, Mode: 0o040755},
			{Path: "/srv", Type: workspace.PathTypeDirectory, Device: 2, Inode: 2, Mode: 0o040755},
		},
	}
	tests := []struct {
		name       string
		evidence   workspace.PathEvidence
		diagnostic workspace.Diagnostic
		status     string
	}{
		{
			name: "inaccessible component", evidence: base, status: "inaccessible",
			diagnostic: workspace.Diagnostic{Code: workspace.CodePathUnavailable, Role: workspace.RoleStorage, Path: base.Path, Component: "/srv/blocked"},
		},
		{
			name: "intermediate non-directory", evidence: base, status: "unsafe",
			diagnostic: workspace.Diagnostic{Code: workspace.CodeComponentNotDirectory, Role: workspace.RoleStorage, Path: base.Path, Component: "/srv/blocked"},
		},
		{
			name: "intermediate symlink",
			evidence: func() workspace.PathEvidence {
				value := base
				value.Exists = true
				value.Type = workspace.PathTypeSymlink
				value.Device, value.Inode, value.Mode, value.UID, value.GID, value.NLink = 2, 3, 0o120777, 991, 991, 1
				value.Components = append(append([]workspace.ComponentEvidence(nil), base.Components...), workspace.ComponentEvidence{
					Path: "/srv/blocked", Type: workspace.PathTypeSymlink, Device: 2, Inode: 3, Mode: 0o120777, UID: 991, GID: 991, NLink: 1,
				})
				return value
			}(),
			diagnostic: workspace.Diagnostic{Code: workspace.CodeSymlinkNotAllowed, Role: workspace.RoleStorage, Path: base.Path, Component: "/srv/blocked"},
			status:     "unsafe",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			presented := presentWorkspacePath(test.evidence, []workspace.Diagnostic{test.diagnostic})
			if presented.Status != test.status || presented.Metadata != nil || presented.CanonicalPath == nil || *presented.CanonicalPath != base.Path {
				t.Fatalf("presented evidence = %#v", presented)
			}
			if len(presented.Components) == 0 || presented.Components[len(presented.Components)-1].Path == base.Path {
				t.Fatalf("partial traversal was lost: %#v", presented.Components)
			}
		})
	}
}

func TestNewRejectsIncompleteWorkspaceDependencies(t *testing.T) {
	valid := testWorkspaceDependencies()
	tests := []WorkspaceDependencies{
		{Selections: valid.Selections, Inventory: valid.Inventory, PrepareRuntime: valid.PrepareRuntime, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal},
		{Inspector: valid.Inspector, Inventory: valid.Inventory, PrepareRuntime: valid.PrepareRuntime, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal},
		{Inspector: valid.Inspector, Selections: valid.Selections, PrepareRuntime: valid.PrepareRuntime, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal},
		{Inspector: valid.Inspector, Selections: valid.Selections, Inventory: valid.Inventory, AcquireWorkspace: valid.AcquireWorkspace, EditJournal: valid.EditJournal},
		{Inspector: valid.Inspector, Selections: valid.Selections, Inventory: valid.Inventory, PrepareRuntime: valid.PrepareRuntime, EditJournal: valid.EditJournal},
		{Inspector: valid.Inspector, Selections: valid.Selections, Inventory: valid.Inventory, PrepareRuntime: valid.PrepareRuntime, AcquireWorkspace: valid.AcquireWorkspace},
	}
	for _, dependencies := range tests {
		if _, err := New(readinessStub{}, sharedTestIdentity(t), testRuntimeDependencies(), dependencies, testConfigurationDependencies(), testOperationDependencies(), fstest.MapFS{}, SecurityConfig{PublicOrigin: testPublicOrigin}); err == nil {
			t.Fatal("New() accepted incomplete workspace dependencies")
		}
	}
}

func workspaceReviewFixture() workspace.Review {
	observed := time.Date(2030, 1, 2, 3, 4, 5, 6, time.UTC)
	working := workspacePathFixture(workspace.RoleWorkingDirectory, "", "/srv/lego", workspace.PathTypeDirectory, 10, 0o040700, observed)
	configuration := workspacePathFixture(workspace.RoleConfiguration, "", "/srv/lego/.lego.yml", workspace.PathTypeRegular, 11, 0o100600, observed)
	storage := workspacePathFixture(workspace.RoleStorage, ".lego", "/srv/lego/.lego", workspace.PathTypeDirectory, 12, 0o040700, observed)
	review := workspace.Review{
		ConfigurationSource: workspace.ConfigurationExplicit,
		WorkingDirectory:    working,
		Configuration:       configuration,
		Storage:             storage,
		DotenvFiles: []workspace.PathEvidence{
			workspacePathFixture(workspace.RoleDotenv, "credentials.env", "/srv/lego/credentials.env", workspace.PathTypeRegular, 13, 0o100600, observed),
		},
		Webroots: []workspace.PathEvidence{
			workspacePathFixture(workspace.RoleWebroot, "public", "/srv/lego/public", workspace.PathTypeDirectory, 14, 0o040700, observed),
		},
		Adoptable:  true,
		ObservedAt: observed,
	}
	review.ReviewedEvidenceSHA256 = workspace.ReviewFingerprint(review)
	return review
}

func workspacePathFixture(role workspace.PathRole, reference, path string, pathType workspace.PathType, inode uint64, mode uint32, observed time.Time) workspace.PathEvidence {
	access := workspace.AccessEvidence{Readable: true, Writable: true, Searchable: pathType == workspace.PathTypeDirectory}
	return workspace.PathEvidence{
		Role: role, Reference: reference, Path: path, Exists: true, Type: pathType,
		Device: 2, Inode: inode, Mode: mode, UID: 991, GID: 991, NLink: 1, Size: 4096,
		ModifiedAt: observed, ChangedAt: observed.Add(time.Nanosecond), Access: access, Safe: true,
		Components: []workspace.ComponentEvidence{
			{Path: "/", Type: workspace.PathTypeDirectory, Device: 2, Inode: 1, Mode: 0o040755, UID: 0, GID: 0, NLink: 20, Access: workspace.AccessEvidence{Readable: true, Searchable: true}},
			{Path: path, Type: pathType, Device: 2, Inode: inode, Mode: mode, UID: 991, GID: 991, NLink: 2, Access: access},
		},
	}
}
