package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/identity"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/state"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

var (
	configurationBaseToken    = strings.Repeat("A", 43)
	configurationPreviewToken = strings.Repeat("B", 43)
)

const configurationSecretCanary = "configuration-secret-canary-value"

type configurationServiceStub struct {
	snapshotView  configuration.View
	snapshotErr   error
	snapshotCalls int

	previewResult configuration.Preview
	previewErr    error
	previewCalls  int
	previewBase   string
	previewEdits  []nativeconfig.Change

	saveView    configuration.View
	saveErr     error
	saveCalls   int
	saveBase    string
	saveReview  string
	saveEdits   []nativeconfig.Change
	beforeGuard func(context.Context) error
	guardCalls  int

	recoveryView       configuration.View
	recoveryErr        error
	recoveryCalls      int
	recoveryBase       string
	recoveryResolution workspace.RecoveryResolution
}

func (stub *configurationServiceStub) Snapshot(context.Context) (configuration.View, error) {
	stub.snapshotCalls++
	return stub.snapshotView, stub.snapshotErr
}

func (stub *configurationServiceStub) Preview(_ context.Context, base string, edits []nativeconfig.Change) (configuration.Preview, error) {
	stub.previewCalls++
	stub.previewBase = base
	stub.previewEdits = cloneConfigurationEdits(edits)
	return stub.previewResult, stub.previewErr
}

func (stub *configurationServiceStub) Save(
	ctx context.Context,
	base string,
	edits []nativeconfig.Change,
	review string,
	guard workspace.CommitGuard,
) (configuration.View, error) {
	stub.saveCalls++
	stub.saveBase = base
	stub.saveReview = review
	stub.saveEdits = cloneConfigurationEdits(edits)
	if stub.saveErr != nil {
		return configuration.View{}, stub.saveErr
	}
	if stub.beforeGuard != nil {
		if err := stub.beforeGuard(ctx); err != nil {
			return configuration.View{}, err
		}
	}
	stub.guardCalls++
	if err := guard(ctx); err != nil {
		return configuration.View{}, err
	}
	return stub.saveView, nil
}

func (stub *configurationServiceStub) ResolveRecovery(
	ctx context.Context,
	base string,
	resolution workspace.RecoveryResolution,
	guard workspace.CommitGuard,
) (configuration.View, error) {
	stub.recoveryCalls++
	stub.recoveryBase = base
	stub.recoveryResolution = resolution
	if stub.recoveryErr != nil {
		return configuration.View{}, stub.recoveryErr
	}
	if stub.beforeGuard != nil {
		if err := stub.beforeGuard(ctx); err != nil {
			return configuration.View{}, err
		}
	}
	stub.guardCalls++
	if err := guard(ctx); err != nil {
		return configuration.View{}, err
	}
	if stub.recoveryView.State == "" {
		return stub.saveView, nil
	}
	return stub.recoveryView, nil
}

func cloneConfigurationEdits(source []nativeconfig.Change) []nativeconfig.Change {
	result := slices.Clone(source)
	for index := range result {
		result[index].Bindings = slices.Clone(result[index].Bindings)
	}
	return result
}

type configurationHTTPHarness struct {
	handler  http.Handler
	cookies  []*http.Cookie
	csrf     string
	identity *identity.Service
	service  *configurationServiceStub
}

func newConfigurationHTTPHarness(t *testing.T) *configurationHTTPHarness {
	t.Helper()
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	identityService, err := identity.New(database)
	if err != nil {
		t.Fatalf("identity.New() error = %v", err)
	}
	if err := identityService.Bootstrap(context.Background(), []byte(testPassword)); err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	view := configurationViewFixture(t)
	service := &configurationServiceStub{snapshotView: view, saveView: view}
	handler, err := New(
		database,
		identityService,
		testRuntimeDependencies(),
		testWorkspaceDependencies(),
		ConfigurationDependencies{Service: service},
		fstest.MapFS{"index.html": {Data: []byte("browser")}},
		SecurityConfig{PublicOrigin: identityTestOrigin},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	login := identityRequest(t, handler, http.MethodPost, "/api/v1/session", `{"password":"`+testPassword+`"}`, nil, true)
	if login.Code != http.StatusOK {
		t.Fatalf("sign-in status = %d, body = %s", login.Code, login.Body.String())
	}
	cookies := responseCookies(login)
	return &configurationHTTPHarness{
		handler: handler, cookies: cookies,
		csrf:     namedCookie(t, cookies, csrfCookieName).Value,
		identity: identityService, service: service,
	}
}

func (harness *configurationHTTPHarness) request(t *testing.T, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	request := newIdentityRequest(method, path, body, harness.cookies, method != http.MethodGet)
	if csrf {
		request.Header.Set(csrfHeaderName, harness.csrf)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func configurationViewFixture(t *testing.T) configuration.View {
	t.Helper()
	inspection := configurationInspectionFixture(t, "/srv/acme")
	inspection.SourceSHA256 = strings.Repeat("f", 64)
	inspection.Projection = append(inspection.Projection, nativeconfig.ProjectedField{
		FieldID: integrations.FieldID("provider.cloudflare.token"),
		Bindings: []nativeconfig.Binding{{
			ID: integrations.BindingID("certificate"), Value: "gateway",
		}},
		Label: "Cloudflare API token", Kind: integrations.FieldString,
		Present: true, Configured: true, PresenceKnown: true, Secret: true,
	})
	return configuration.View{
		State: configuration.StateReady,
		Source: configuration.Source{
			BaseRevisionToken: configurationBaseToken,
			ConfigurationPath: "/srv/acme/lego.yml",
			DotenvPaths:       []string{"/srv/acme/cloudflare.env"},
			RuntimeManifestID: compatibility.ManifestLegoV531,
		},
		Inspection: inspection,
		Diagnostics: []configuration.Diagnostic{{
			Code: configuration.CodeUnknownField, Severity: configuration.SeverityNotice,
			Role: configuration.RoleConfiguration, FieldID: integrations.FieldWorkspaceStorage,
			Path: "/srv/acme/lego.yml", Line: 3, Column: 5,
		}},
		Editing: true, Execution: true,
	}
}

func configurationInspectionFixture(t *testing.T, storage string) nativeconfig.Inspection {
	t.Helper()
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatalf("compatibility.Schema() error = %v", err)
	}
	manifest, ok := integrations.BaseManifest(compatibility.ManifestLegoV531)
	if !ok {
		t.Fatal("base native configuration manifest is unavailable")
	}
	engine, err := nativeconfig.NewEngine(
		compatibility.ManifestLegoV531, schema, manifest, nativeconfig.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("nativeconfig.NewEngine() error = %v", err)
	}
	source := []byte("storage: '" + storage + "'\naccounts:\n  home: {}\nchallenges:\n  web:\n    http: {}\ncertificates:\n  gateway:\n    domains: [gateway.home.example]\n    account: home\n    challenge: web\n")
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatalf("Engine.Inspect() error = %v", err)
	}
	return inspection
}

func configurationReviewPreviewFixture(t *testing.T) configuration.Preview {
	t.Helper()
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	engine, err := nativeconfig.NewEngine(compatibility.ManifestLegoV531, schema, manifest, nativeconfig.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("storage: '.lego'\naccounts:\n  home: {}\nchallenges:\n  web:\n    http: {}\ncertificates:\n  gateway:\n    domains: [gateway.home.example]\n    account: home\n    challenge: web\n")
	baseInspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := engine.Preview(source, []nativeconfig.Change{{
		FieldID:   integrations.FieldWorkspaceStorage,
		Operation: nativeconfig.OperationSet,
		Value:     integrations.StringValue("/srv/acme"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	bindings := []nativeconfig.Binding{{ID: integrations.BindingID("certificate"), Value: "gateway"}}
	baseInspection.Projection = append(baseInspection.Projection, nativeconfig.ProjectedField{
		FieldID: integrations.FieldID("provider.cloudflare.token"), Bindings: bindings,
		Label: "Cloudflare API token", Kind: integrations.FieldString,
		PresenceKnown: true, Secret: true,
	})
	afterInspection := candidate.Inspection
	afterInspection.Projection = append(afterInspection.Projection, nativeconfig.ProjectedField{
		FieldID: integrations.FieldID("provider.cloudflare.token"), Bindings: bindings,
		Label: "Cloudflare API token", Kind: integrations.FieldString,
		Present: true, Configured: true, PresenceKnown: true, Secret: true,
	})
	summary := slices.Clone(candidate.Summary)
	summary = append(summary, nativeconfig.ChangeSummary{
		FieldID: integrations.FieldID("provider.cloudflare.token"), Bindings: bindings,
		Label: "Cloudflare API token", Target: integrations.TargetDotenv,
		Action: nativeconfig.SummarySet, Secret: true,
	})
	return configuration.Preview{
		State:                configuration.PreviewReviewRequired,
		BaseRevisionToken:    configurationBaseToken,
		ReviewedPreviewToken: configurationPreviewToken,
		ResultingState:       configuration.StateReady,
		BaseInspection:       baseInspection,
		Inspection:           afterInspection,
		Summary:              summary,
		Diagnostics: []configuration.Diagnostic{{
			Code: configuration.CodeUnsupportedContent, Severity: configuration.SeverityNotice,
			Role: configuration.RoleConfiguration,
		}},
		Execution: true,
	}
}

func validConfigurationPreviewBody(value string) string {
	encoded, _ := json.Marshal(value)
	return `{"baseRevisionToken":"` + configurationBaseToken + `","changes":[{"fieldId":"provider.cloudflare.token","bindings":[{"id":"certificate","value":"gateway"}],"operation":"set","value":` + string(encoded) + `}]}`
}

func validConfigurationSaveBody(value string) string {
	body := validConfigurationPreviewBody(value)
	return strings.TrimSuffix(body, "}") + `,"reviewedPreviewToken":"` + configurationPreviewToken + `"}`
}

func TestConfigurationHTTPRequiresSessionAndCSRFBeforeCallingService(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)

	request := newIdentityRequest(http.MethodGet, "/api/v1/configuration", "", nil, false)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")

	missingCSRF := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", validConfigurationPreviewBody("safe"), false)
	assertAPIError(t, missingCSRF, http.StatusForbidden, "request_not_allowed")

	wrongCSRFRequest := newIdentityRequest(
		http.MethodPut, "/api/v1/configuration", validConfigurationSaveBody("safe"), harness.cookies, true,
	)
	wrongCSRFRequest.Header.Set(csrfHeaderName, strings.Repeat("Z", 43))
	wrongCSRF := httptest.NewRecorder()
	harness.handler.ServeHTTP(wrongCSRF, wrongCSRFRequest)
	assertAPIError(t, wrongCSRF, http.StatusForbidden, "request_not_allowed")

	if harness.service.snapshotCalls != 0 || harness.service.previewCalls != 0 || harness.service.saveCalls != 0 {
		t.Fatalf("unauthorized calls reached service: snapshot=%d preview=%d save=%d",
			harness.service.snapshotCalls, harness.service.previewCalls, harness.service.saveCalls)
	}
}

func TestConfigurationSnapshotPresentsOnlyLogicalBoundedState(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	response := harness.request(t, http.MethodGet, "/api/v1/configuration", "", false)
	if response.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload map[string]any
	decodeConfigurationResponse(t, response, &payload)
	if payload["state"] != "ready" {
		t.Fatalf("snapshot state = %v", payload["state"])
	}
	source := payload["source"].(map[string]any)
	if source["baseRevisionToken"] != configurationBaseToken || source["configurationPath"] != "/srv/acme/lego.yml" || source["runtimeManifestId"] != string(compatibility.ManifestLegoV531) {
		t.Fatalf("snapshot source = %#v", source)
	}
	projection := payload["projection"].([]any)
	if len(projection) != 2 {
		t.Fatalf("projection length = %d, body = %s", len(projection), response.Body.String())
	}
	public := projection[0].(map[string]any)
	if public["fieldId"] != "workspace.storage" || public["kind"] != "string" || public["value"] != "/srv/acme" {
		t.Fatalf("public projection = %#v", public)
	}
	secret := projection[1].(map[string]any)
	if secret["fieldId"] != "provider.cloudflare.token" || secret["kind"] != "secret" || secret["present"] != true || secret["presenceKnown"] != true {
		t.Fatalf("secret projection = %#v", secret)
	}
	if _, exposed := secret["value"]; exposed {
		t.Fatalf("secret projection exposed a value: %#v", secret)
	}
	diagnostics := payload["diagnostics"].([]any)
	diagnostic := diagnostics[0].(map[string]any)
	if diagnostic["message"] != "An unrecognized native field is preserved and blocks managed execution." || diagnostic["path"] != "/srv/acme/lego.yml" || diagnostic["line"] != float64(3) {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
	if strings.Contains(response.Body.String(), harness.service.snapshotView.Inspection.SourceSHA256) || strings.Contains(response.Body.String(), configurationSecretCanary) {
		t.Fatalf("snapshot exposed source digest or secret material: %s", response.Body.String())
	}
}

func TestConfigurationRecoveryOmitsTransactionAndContentIdentity(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	harness.service.snapshotView = configuration.View{
		State: configuration.StateRecoveryRequired,
		Source: configuration.Source{
			BaseRevisionToken: configurationBaseToken,
			ConfigurationPath: "/srv/acme/lego.yml",
			DotenvPaths:       []string{"/srv/acme/cloudflare.env"},
			RuntimeManifestID: compatibility.ManifestLegoV531,
		},
		Inspection: nativeconfig.Inspection{SourceSHA256: strings.Repeat("e", 64)},
		Recovery: &workspace.Recovery{
			TransactionID:    configurationSecretCanary,
			WorkingDirectory: "/srv/acme", ConfigurationPath: "/srv/acme/lego.yml",
			Phase: workspace.JournalReplacing, State: workspace.RecoveryPartial,
			Files: []workspace.RecoveryFile{
				{Ordinal: 0, Role: workspace.RoleConfiguration, Path: "/srv/acme/lego.yml", State: workspace.RecoveryFileApplied},
				{Ordinal: 1, Role: workspace.RoleDotenv, Path: "/srv/acme/cloudflare.env", State: workspace.RecoveryFileUnapplied},
			},
		},
	}
	response := harness.request(t, http.MethodGet, "/api/v1/configuration", "", false)
	if response.Code != http.StatusOK {
		t.Fatalf("recovery status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload map[string]any
	decodeConfigurationResponse(t, response, &payload)
	if _, exists := payload["projection"]; exists {
		t.Fatalf("recovery response included projection: %#v", payload)
	}
	recovery := payload["recovery"].(map[string]any)
	if recovery["phase"] != "replacing" || recovery["state"] != "partial" {
		t.Fatalf("recovery = %#v", recovery)
	}
	if _, exists := recovery["transactionId"]; exists {
		t.Fatalf("recovery exposed transaction ID: %#v", recovery)
	}
	if strings.Contains(response.Body.String(), configurationSecretCanary) || strings.Contains(response.Body.String(), strings.Repeat("e", 64)) {
		t.Fatalf("recovery response exposed transaction or content identity: %s", response.Body.String())
	}
}

func TestConfigurationRecoveryAdoptCurrentIsStrictAndReauthorized(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	harness.service.recoveryView = configurationViewFixture(t)
	body := `{"baseRevisionToken":"` + configurationBaseToken + `","resolution":"adopt_current"}`
	response := harness.request(t, http.MethodPut, "/api/v1/configuration/recovery", body, true)
	if response.Code != http.StatusOK || harness.service.recoveryCalls != 1 ||
		harness.service.recoveryBase != configurationBaseToken ||
		harness.service.recoveryResolution != workspace.ResolutionAdoptCurrent || harness.service.guardCalls != 1 {
		t.Fatalf("adopt-current response = %d %s, calls=%d resolution=%s guards=%d",
			response.Code, response.Body.String(), harness.service.recoveryCalls,
			harness.service.recoveryResolution, harness.service.guardCalls)
	}

	for _, invalid := range []string{
		`{"baseRevisionToken":"` + configurationBaseToken + `","resolution":"replay"}`,
		`{"baseRevisionToken":"` + configurationBaseToken + `","resolution":"adopt_current","resolution":"adopt_current"}`,
		`{"baseRevisionToken":"` + configurationBaseToken + `","resolution":"adopt_current","extra":true}`,
	} {
		response = harness.request(t, http.MethodPut, "/api/v1/configuration/recovery", invalid, true)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid recovery request = %d %s", response.Code, response.Body.String())
		}
	}

	harness = newConfigurationHTTPHarness(t)
	harness.service.beforeGuard = func(ctx context.Context) error {
		return harness.identity.RevokeSessions(ctx)
	}
	response = harness.request(t, http.MethodPut, "/api/v1/configuration/recovery", body, true)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked recovery request = %d %s", response.Code, response.Body.String())
	}
}

func TestConfigurationPreviewWireStatesAndSecretRedaction(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)

	harness.service.previewResult = configuration.Preview{
		State: configuration.PreviewUnchanged, BaseRevisionToken: configurationBaseToken,
	}
	unchanged := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", validConfigurationPreviewBody("unchanged"), true)
	if unchanged.Code != http.StatusOK || strings.TrimSpace(unchanged.Body.String()) != `{"state":"unchanged","baseRevisionToken":"`+configurationBaseToken+`"}` {
		t.Fatalf("unchanged preview = %d %s", unchanged.Code, unchanged.Body.String())
	}

	harness.service.previewResult = configuration.Preview{
		State: configuration.PreviewInvalid, BaseRevisionToken: configurationBaseToken,
		Diagnostics: []configuration.Diagnostic{{
			Code:     configuration.CodeSemanticValidationFailed,
			Severity: configuration.SeverityBlocking, Role: configuration.RoleSemantic,
		}},
	}
	invalid := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", validConfigurationPreviewBody("invalid"), true)
	if invalid.Code != http.StatusOK {
		t.Fatalf("invalid preview status = %d, body = %s", invalid.Code, invalid.Body.String())
	}
	var invalidPayload map[string]any
	decodeConfigurationResponse(t, invalid, &invalidPayload)
	if invalidPayload["state"] != "invalid" || invalidPayload["reviewedPreviewToken"] != nil || invalidPayload["resultingState"] != nil || invalidPayload["executionAllowed"] != nil {
		t.Fatalf("invalid preview shape = %#v", invalidPayload)
	}
	if _, ok := invalidPayload["summary"]; !ok {
		t.Fatalf("invalid preview omitted bounded summary: %#v", invalidPayload)
	}

	harness.service.previewResult = configurationReviewPreviewFixture(t)
	review := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", validConfigurationPreviewBody(configurationSecretCanary), true)
	if review.Code != http.StatusOK {
		t.Fatalf("review preview status = %d, body = %s", review.Code, review.Body.String())
	}
	var reviewPayload map[string]any
	decodeConfigurationResponse(t, review, &reviewPayload)
	if reviewPayload["state"] != "review_required" || reviewPayload["reviewedPreviewToken"] != configurationPreviewToken || reviewPayload["resultingState"] != "ready" || reviewPayload["executionAllowed"] != true {
		t.Fatalf("review preview = %#v", reviewPayload)
	}
	summaries := reviewPayload["summary"].([]any)
	if len(summaries) != 2 {
		t.Fatalf("review summaries = %#v", summaries)
	}
	public := summaries[0].(map[string]any)
	if public["action"] != "changed" || public["file"] != "configuration" || public["sensitive"] != false {
		t.Fatalf("public summary = %#v", public)
	}
	secret := summaries[1].(map[string]any)
	if secret["action"] != "secret_replaced" || secret["file"] != "dotenv" || secret["sensitive"] != true {
		t.Fatalf("secret summary = %#v", secret)
	}
	if secret["before"].(map[string]any)["state"] != "absent" || secret["after"].(map[string]any)["state"] != "present_secret" {
		t.Fatalf("secret presence summary = %#v", secret)
	}
	if strings.Contains(review.Body.String(), configurationSecretCanary) {
		t.Fatalf("preview echoed secret request material: %s", review.Body.String())
	}
	if harness.service.previewBase != configurationBaseToken || len(harness.service.previewEdits) != 1 {
		t.Fatalf("preview service input = %q %#v", harness.service.previewBase, harness.service.previewEdits)
	}
	secretValue, ok := harness.service.previewEdits[0].Value.String()
	if !ok || secretValue != configurationSecretCanary {
		t.Fatalf("service did not receive exact typed secret input")
	}
}

func TestConfigurationRequestDecoderRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	base := `"baseRevisionToken":"` + configurationBaseToken + `"`
	validChange := `{"fieldId":"workspace.storage","bindings":[],"operation":"set","value":"/srv/acme"}`
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate top level", body: `{` + base + `,` + base + `,"changes":[` + validChange + `]}`},
		{name: "unknown top level", body: `{` + base + `,"changes":[` + validChange + `],"nativePath":"/secret"}`},
		{name: "malformed", body: `{` + base + `,"changes":[`},
		{name: "trailing document", body: `{` + base + `,"changes":[` + validChange + `]} {}`},
		{name: "missing changes", body: `{` + base + `}`},
		{name: "empty changes", body: `{` + base + `,"changes":[]}`},
		{name: "preview token forbidden", body: `{` + base + `,"changes":[` + validChange + `],"reviewedPreviewToken":"` + configurationPreviewToken + `"}`},
		{name: "unkeyed digest token", body: `{"baseRevisionToken":"` + strings.Repeat("a", 64) + `","changes":[` + validChange + `]}`},
		{name: "duplicate change field", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","fieldId":"workspace.storage","bindings":[],"operation":"remove"}]}`},
		{name: "unknown change field", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"remove","selector":"storage"}]}`},
		{name: "native selector field ID", body: `{` + base + `,"changes":[{"fieldId":"storage[0]","bindings":[],"operation":"remove"}]}`},
		{name: "remove value", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"remove","value":"secret"}]}`},
		{name: "set missing value", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"set"}]}`},
		{name: "duplicate binding", body: `{` + base + `,"changes":[{"fieldId":"certificate.domains","bindings":[{"id":"certificate","value":"one"},{"id":"certificate","value":"two"}],"operation":"remove"}]}`},
		{name: "binding object required", body: `{` + base + `,"changes":[{"fieldId":"certificate.domains","bindings":{},"operation":"remove"}]}`},
		{name: "field ID type", body: `{` + base + `,"changes":[{"fieldId":1,"bindings":[],"operation":"remove"}]}`},
		{name: "operation type", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":1}]}`},
		{name: "null value", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"set","value":null}]}`},
		{name: "fractional number", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"set","value":1.5}]}`},
		{name: "object value", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"set","value":{"raw":"secret"}}]}`},
		{name: "empty string value", body: `{` + base + `,"changes":[{"fieldId":"workspace.storage","bindings":[],"operation":"set","value":""}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", test.body, true)
			assertAPIError(t, response, http.StatusBadRequest, "invalid_request")
			if strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("invalid request echoed input detail: %s", response.Body.String())
			}
		})
	}

	oversized := harness.request(
		t, http.MethodPost, "/api/v1/configuration/previews",
		strings.Repeat("x", maximumConfigurationBodyBytes+1), true,
	)
	assertAPIError(t, oversized, http.StatusRequestEntityTooLarge, "invalid_request")

	wrongMediaRequest := newIdentityRequest(http.MethodPost, "/api/v1/configuration/previews", "", harness.cookies, true)
	wrongMediaRequest.Header.Set(csrfHeaderName, harness.csrf)
	wrongMediaRequest.Header.Set("Content-Type", "text/plain")
	wrongMedia := httptest.NewRecorder()
	harness.handler.ServeHTTP(wrongMedia, wrongMediaRequest)
	assertAPIError(t, wrongMedia, http.StatusUnsupportedMediaType, "invalid_request")

	if harness.service.previewCalls != 0 {
		t.Fatalf("invalid requests reached preview service %d times", harness.service.previewCalls)
	}
}

func TestConfigurationSaveRequiresReviewTokenAndReauthorizesCommit(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)

	missingReview := harness.request(t, http.MethodPut, "/api/v1/configuration", validConfigurationPreviewBody("safe"), true)
	assertAPIError(t, missingReview, http.StatusBadRequest, "invalid_request")
	if harness.service.saveCalls != 0 {
		t.Fatal("save service was called without a reviewed preview token")
	}

	response := harness.request(t, http.MethodPut, "/api/v1/configuration", validConfigurationSaveBody(configurationSecretCanary), true)
	if response.Code != http.StatusOK {
		t.Fatalf("save status = %d, body = %s", response.Code, response.Body.String())
	}
	if harness.service.saveCalls != 1 || harness.service.guardCalls != 1 || harness.service.saveBase != configurationBaseToken || harness.service.saveReview != configurationPreviewToken {
		t.Fatalf("save calls/guard/tokens = %d/%d/%q/%q", harness.service.saveCalls, harness.service.guardCalls, harness.service.saveBase, harness.service.saveReview)
	}
	value, ok := harness.service.saveEdits[0].Value.String()
	if !ok || value != configurationSecretCanary {
		t.Fatal("save service did not receive exact typed secret")
	}
	if strings.Contains(response.Body.String(), configurationSecretCanary) {
		t.Fatalf("save response echoed secret: %s", response.Body.String())
	}
}

func TestConfigurationSaveCommitGuardRejectsRevokedSession(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	harness.service.beforeGuard = func(ctx context.Context) error {
		return harness.identity.ResetPassword(ctx, []byte("replacement administrator password"))
	}

	response := harness.request(t, http.MethodPut, "/api/v1/configuration", validConfigurationSaveBody(configurationSecretCanary), true)
	assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	if harness.service.saveCalls != 1 || harness.service.guardCalls != 1 {
		t.Fatalf("save/guard calls = %d/%d, want 1/1", harness.service.saveCalls, harness.service.guardCalls)
	}
	if strings.Contains(response.Body.String(), configurationSecretCanary) {
		t.Fatalf("authorization failure echoed secret: %s", response.Body.String())
	}
}

func TestConfigurationServiceErrorsUseBoundedStatusAndMessages(t *testing.T) {
	harness := newConfigurationHTTPHarness(t)
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "busy", err: configuration.ErrBusy, wantStatus: http.StatusTooManyRequests, wantCode: "service_busy"},
		{name: "changed", err: configuration.ErrChanged, wantStatus: http.StatusConflict, wantCode: "configuration_changed"},
		{name: "source changed", err: workspace.ErrSourceChanged, wantStatus: http.StatusConflict, wantCode: "configuration_changed"},
		{name: "invalid", err: configuration.ErrInvalid, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "foreign", err: errors.New(configurationSecretCanary), wantStatus: http.StatusServiceUnavailable, wantCode: "service_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness.service.previewErr = test.err
			response := harness.request(t, http.MethodPost, "/api/v1/configuration/previews", validConfigurationPreviewBody(configurationSecretCanary), true)
			assertAPIError(t, response, test.wantStatus, test.wantCode)
			if strings.Contains(response.Body.String(), configurationSecretCanary) {
				t.Fatalf("service error exposed internal detail: %s", response.Body.String())
			}
			if test.err == configuration.ErrBusy && response.Header().Get("Retry-After") != "1" {
				t.Fatalf("busy Retry-After = %q", response.Header().Get("Retry-After"))
			}
		})
	}
}

func decodeConfigurationResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode configuration response: %v; body = %s", err, response.Body.String())
	}
}
