package nativeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/integrations"
)

const validNativeConfiguration = `# native lego configuration
accounts:
  home: {}
challenges:
  web:
    http: {}
certificates:
  gateway:
    domains:
      - gateway.home.example
    account: home
    challenge: web
`

func testEngine(t *testing.T) *Engine {
	t.Helper()
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	manifest, ok := integrations.BaseManifest(compatibility.ManifestLegoV531)
	if !ok {
		t.Fatal("base manifest unavailable")
	}
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func engineWithFields(t *testing.T, fields ...integrations.FieldSpec) *Engine {
	t.Helper()
	base, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	manifest, err := base.Extend("test-native-v1", fields...)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestInspectUsesExactSchemaSemanticModelAndSupportClassification(t *testing.T) {
	inspection, err := testEngine(t).Inspect([]byte(validNativeConfiguration))
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.SchemaValid || !inspection.SemanticValid || !inspection.Replaceable {
		t.Fatalf("validation = schema:%v semantic:%v replaceable:%v issues:%#v", inspection.SchemaValid, inspection.SemanticValid, inspection.Replaceable, inspection.Issues)
	}
	if inspection.Executable {
		t.Fatal("base manifest treated recognized advanced content as executable")
	}
	unsupported := 0
	for _, issue := range inspection.Issues {
		if issue.Class == IssueUnsupported {
			unsupported++
		}
	}
	if unsupported != 3 {
		t.Fatalf("unsupported issues = %d, want top-level accounts/challenges/certificates", unsupported)
	}
	if len(inspection.Projection) != 1 {
		t.Fatalf("projection = %#v", inspection.Projection)
	}
	storage := inspection.Projection[0]
	value, ok := storage.Value()
	text, textOK := value.String()
	if storage.FieldID != integrations.FieldWorkspaceStorage || storage.Present || !storage.Defaulted || !ok || !textOK || text != ".lego" {
		t.Fatalf("storage projection = %#v, value=%#v", storage, value)
	}
}

func TestObservedSecretsReturnsOnlyManifestOwnedYAMLValues(t *testing.T) {
	manifest, ok := integrations.CoreManifest(compatibility.ManifestLegoV531)
	if !ok {
		t.Fatal("core manifest unavailable")
	}
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, DefaultLimits())
	clear(schema)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "TASK08_YAML_SECRET_CANARY"
	source := []byte(`accounts:
  first:
    eab: {kid: public-kid, hmacKey: TASK08_YAML_SECRET_CANARY}
  second:
    eab: {kid: another-public-kid, hmacKey: TASK08_YAML_SECRET_CANARY}
certificates: {}
unmanaged: TASK08_YAML_SECRET_CANARY
`)
	secrets, err := engine.ObservedSecrets(source)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for index := range secrets {
			clear(secrets[index])
		}
	}()
	if len(secrets) != 1 || string(secrets[0]) != secret {
		t.Fatalf("ObservedSecrets() = %#v", secrets)
	}
	if bytes.Contains(secrets[0], []byte("public-kid")) {
		t.Fatal("public field was returned as an observed secret")
	}
}

func TestInspectFailsClosedWhenProjectionLimitWouldOmitManagedFields(t *testing.T) {
	userAgent, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "workspace.user_agent", Label: "User agent", Kind: integrations.FieldString,
		Target: integrations.TargetYAML, Sensitivity: integrations.SensitivityPublic,
		Disposition: integrations.DispositionManaged,
		Selector:    []integrations.SelectorSegment{integrations.YAMLKey("userAgent")},
		Rules:       integrations.Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	manifest, err := base.Extend("projection-limit-test", userAgent)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxProjectionFields = 1
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Inspect([]byte("storage: /srv/lego\nuserAgent: acmemux\n"))
	assertErrorCode(t, err, ErrorStructureComplex)
}

func TestInspectPreservesButBlocksManagedValuesOutsideManifestRules(t *testing.T) {
	provider, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "challenge.provider", Label: "DNS provider", Kind: integrations.FieldString,
		Target: integrations.TargetYAML, Sensitivity: integrations.SensitivityPublic,
		Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{
			integrations.YAMLKey("challenges"), integrations.YAMLBinding("challenge"),
			integrations.YAMLKey("dns"), integrations.YAMLKey("provider"),
		},
		Rules: integrations.Rules{MaxBytes: 64, Enum: []string{"cloudflare"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := engineWithFields(t, provider).Inspect([]byte(`accounts:
  home: {}
challenges:
  home:
    dns:
      provider: route53
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: home
`))
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.Replaceable || inspection.Executable || !hasIssue(inspection.Issues, IssueUnsupported) {
		t.Fatalf("unsupported managed value classification = %#v", inspection)
	}
	projected := findProjection(t, inspection, provider.ID())
	if !projected.Present || projected.Configured {
		t.Fatalf("unsupported provider repair projection = %#v", projected)
	}
}

func TestInspectDoesNotProjectEmptyStorageOutsideManifestRules(t *testing.T) {
	inspection, err := testEngine(t).Inspect([]byte("storage: ''\n" + validNativeConfiguration))
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.Replaceable || inspection.Executable || !hasIssue(inspection.Issues, IssueUnsupported) {
		t.Fatalf("empty storage classification = %#v", inspection)
	}
	projected := findProjection(t, inspection, integrations.FieldWorkspaceStorage)
	if !projected.Present || projected.Configured {
		t.Fatalf("invalid empty storage repair projection = %#v", projected)
	}
}

func TestPreviewPatchesOnlyLogicalFieldAndPreservesPresentation(t *testing.T) {
	source := []byte("# heading\nstorage: '.lego' # retained\n" + strings.TrimPrefix(validNativeConfiguration, "# native lego configuration\n"))
	candidate, err := testEngine(t).Preview(source, []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
		Value: integrations.StringValue("/srv/lego"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	output := candidate.YAML()
	for _, retained := range []string{"# heading", "storage: '/srv/lego' # retained", "accounts:", "certificates:", "gateway.home.example"} {
		if !bytes.Contains(output, []byte(retained)) {
			t.Fatalf("candidate omitted %q:\n%s", retained, output)
		}
	}
	if !candidate.Changed || candidate.SourceSHA256 == candidate.CandidateSHA256 || len(candidate.Summary) != 1 {
		t.Fatalf("candidate metadata = %#v", candidate)
	}
	before, beforeOK := candidate.Summary[0].Before()
	after, afterOK := candidate.Summary[0].After()
	beforeText, _ := before.String()
	afterText, _ := after.String()
	if !beforeOK || !afterOK || beforeText != ".lego" || afterText != "/srv/lego" {
		t.Fatalf("summary before/after = %q/%q, %v/%v", beforeText, afterText, beforeOK, afterOK)
	}
	if !candidate.Inspection.Replaceable || candidate.Inspection.Executable {
		t.Fatalf("candidate validation = %#v", candidate.Inspection)
	}
}

func TestPreviewNoOpRetainsExactBytes(t *testing.T) {
	source := []byte("storage: '.lego'\n" + validNativeConfiguration)
	candidate, err := testEngine(t).Preview(source, []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
		Value: integrations.StringValue(".lego"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if candidate.Changed || len(candidate.Summary) != 0 || !bytes.Equal(candidate.YAML(), source) || candidate.SourceSHA256 != candidate.CandidateSHA256 {
		t.Fatalf("no-op candidate changed: %#v", candidate)
	}
	copyBytes := candidate.YAML()
	copyBytes[0] = 'X'
	if bytes.Equal(copyBytes, candidate.YAML()) {
		t.Fatal("Candidate.YAML returned owned bytes")
	}
}

func TestPreviewRemovalShowsEffectiveManifestDefault(t *testing.T) {
	candidate, err := testEngine(t).Preview([]byte("storage: /srv/lego\n"+validNativeConfiguration), []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationRemove,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if len(candidate.Summary) != 1 || candidate.Summary[0].Action != SummaryRemove {
		t.Fatalf("summary = %#v", candidate.Summary)
	}
	after, ok := candidate.Summary[0].After()
	text, isString := after.String()
	if !ok || !isString || text != ".lego" {
		t.Fatalf("effective default after removal = %#v, %v", after, ok)
	}
}

func TestUnknownAndUnsupportedContentIsPreservedButBlocked(t *testing.T) {
	engine := testEngine(t)
	source := []byte(validNativeConfiguration + "mystery: preserve-me\n")
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.SchemaValid || inspection.Replaceable || inspection.Executable || !hasIssue(inspection.Issues, IssueUnknown) {
		t.Fatalf("unknown classification = %#v", inspection)
	}
	candidate, err := engine.Preview(source, []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet,
		Value: integrations.StringValue("/var/lib/lego"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if !bytes.Contains(candidate.YAML(), []byte("mystery: preserve-me")) || candidate.Inspection.Replaceable {
		t.Fatalf("unknown content not preserved and blocked:\n%s\n%#v", candidate.YAML(), candidate.Inspection)
	}
}

func TestSchemaAndSourceSemanticValidationAreBothRequired(t *testing.T) {
	engine := testEngine(t)
	tests := []struct {
		name        string
		source      string
		schemaValid bool
		semantic    bool
		class       IssueClass
	}{
		{
			name: "schema source divergence RSA3072",
			source: `accounts:
  home:
    keyType: RSA3072
challenges:
  web:
    http: {}
certificates:
  one:
    domains: [one.example]
    challenge: web
    account: home
`,
			schemaValid: false, semantic: false, class: IssueSchema,
		},
		{
			name: "semantic missing challenge",
			source: `certificates:
  one:
    domains: [one.example]
    challenge: absent
`,
			schemaValid: true, semantic: false, class: IssueSemantic,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection, err := engine.Inspect([]byte(test.source))
			if err != nil {
				t.Fatal(err)
			}
			if inspection.SchemaValid != test.schemaValid || inspection.SemanticValid != test.semantic || inspection.Replaceable || !hasIssue(inspection.Issues, test.class) {
				t.Fatalf("inspection = %#v", inspection)
			}
		})
	}
}

func TestStructuralYAMLRejectionsAreStableAndValueFree(t *testing.T) {
	engine := testEngine(t)
	tests := []struct {
		name   string
		source []byte
		code   ErrorCode
	}{
		{"alias", []byte("storage: &s .lego\nuserAgent: *s\ncertificates: {}\n"), ErrorAliasUnsupported},
		{"merge", []byte("<<: {storage: .lego}\ncertificates: {}\n"), ErrorMergeUnsupported},
		{"custom tag", []byte("storage: !secret canary-value\ncertificates: {}\n"), ErrorTagUnsupported},
		{"duplicate", []byte("storage: one\nstorage: secret-canary\ncertificates: {}\n"), ErrorDuplicateKey},
		{"multiple documents", []byte("certificates: {}\n---\ncertificates: {}\n"), ErrorMultipleDocuments},
		{"invalid utf8", []byte{0xff, 0xfe}, ErrorInvalidUTF8},
		{"root sequence", []byte("- certificates\n"), ErrorRootNotMapping},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := engine.Inspect(test.source)
			var configError *Error
			if !errors.As(err, &configError) || configError.Code != test.code {
				t.Fatalf("error = %#v, want %q", err, test.code)
			}
			if strings.Contains(err.Error(), "canary") {
				t.Fatalf("error echoed input: %v", err)
			}
		})
	}
}

func TestComplexityAndByteLimits(t *testing.T) {
	schema, _ := compatibility.Schema(compatibility.ManifestLegoV531)
	manifest, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	limits := DefaultLimits()
	limits.MaxBytes = 64
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Inspect([]byte(validNativeConfiguration))
	assertErrorCode(t, err, ErrorSourceTooLarge)

	limits = DefaultLimits()
	limits.MaxNodes = 8
	limits.MaxDepth = 8
	limits.MaxIssues = 8
	limits.MaxProjectionFields = 8
	engine, err = NewEngine(compatibility.ManifestLegoV531, schema, manifest, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Inspect([]byte(validNativeConfiguration))
	assertErrorCode(t, err, ErrorStructureComplex)
}

func TestDotenvFieldProjectsPresenceAndNormalizesExactSecretEdit(t *testing.T) {
	secret, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "cloudflare.api_token", Label: "Cloudflare API token", Kind: integrations.FieldString,
		Target: integrations.TargetDotenv, Sensitivity: integrations.SensitivitySecret, Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{
			integrations.YAMLKey("challenges"), integrations.YAMLBinding("challenge"),
			integrations.YAMLKey("dns"), integrations.YAMLKey("envFile"),
		},
		EnvironmentKey: "CLOUDFLARE_DNS_API_TOKEN", Rules: integrations.Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	identifier, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "cloudflare.account_id", Label: "Cloudflare account ID", Kind: integrations.FieldString,
		Target: integrations.TargetDotenv, Sensitivity: integrations.SensitivitySecret, Disposition: integrations.DispositionManaged,
		Selector: secret.Selector(), EnvironmentKey: "CLOUDFLARE_ACCOUNT_ID", Rules: integrations.Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := engineWithFields(t, secret, identifier)
	source := []byte(`challenges:
  cloudflare-home:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.example]
    challenge: cloudflare-home
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	routes := inspection.DotenvRoutes()
	if len(routes) != 2 || routes[0].Reference() != "credentials.env" || routes[1].Reference() != "credentials.env" || !routes[0].Secret() || !routes[1].Secret() {
		t.Fatalf("routes = %#v", routes)
	}
	foundExactKey := false
	for _, route := range routes {
		foundExactKey = foundExactKey || route.EnvironmentKey() == "CLOUDFLARE_DNS_API_TOKEN"
	}
	if !foundExactKey {
		t.Fatalf("exact token route missing: %#v", routes)
	}
	projected := findProjection(t, inspection, "cloudflare.api_token")
	if projected.PresenceKnown || projected.Configured {
		t.Fatalf("dotenv presence was guessed: %#v", projected)
	}
	inspection = inspection.WithDotenvPresence([]DotenvPresence{{
		FieldID: "cloudflare.api_token", Bindings: []Binding{{ID: "challenge", Value: "cloudflare-home"}}, Present: true, Valid: true,
	}})
	projected = findProjection(t, inspection, "cloudflare.api_token")
	if !projected.PresenceKnown || !projected.Configured {
		t.Fatalf("trusted presence not projected: %#v", projected)
	}

	const canary = "dotenv-secret-canary"
	candidate, err := engine.Preview(source, []Change{{
		FieldID: "cloudflare.api_token", Bindings: []Binding{{ID: "challenge", Value: "cloudflare-home"}},
		Operation: OperationSet, Value: integrations.StringValue(canary),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(candidate.YAML(), source) || !candidate.Changed || len(candidate.ExternalChanges()) != 1 || len(candidate.Summary) != 1 {
		t.Fatalf("dotenv candidate = %#v", candidate)
	}
	external := candidate.ExternalChanges()[0]
	value, ok := external.Value()
	secretValue, _ := value.String()
	if !ok || secretValue != canary || external.Reference() != "credentials.env" || external.EnvironmentKey() != "CLOUDFLARE_DNS_API_TOKEN" {
		t.Fatalf("external change = %#v", external)
	}
	if _, ok := candidate.Summary[0].Before(); ok {
		t.Fatal("secret summary exposed before value")
	}
	if _, ok := candidate.Summary[0].After(); ok {
		t.Fatal("secret summary exposed after value")
	}
	encoded, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(canary)) || bytes.Contains(encoded, []byte("CLOUDFLARE_DNS_API_TOKEN")) || bytes.Contains(encoded, []byte("credentials.env")) {
		t.Fatalf("candidate JSON exposed server-only data: %s", encoded)
	}
	candidate.Clear()
	if candidate.YAML() != nil || candidate.ExternalChanges() != nil {
		t.Fatal("Candidate.Clear retained owned data")
	}
}

func TestSecretYAMLProjectionAndSummaryDoNotEcho(t *testing.T) {
	secret, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "account.eab_hmac", Label: "EAB HMAC key", Kind: integrations.FieldString,
		Target: integrations.TargetYAML, Sensitivity: integrations.SensitivitySecret, Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{
			integrations.YAMLKey("accounts"), integrations.YAMLBinding("account"), integrations.YAMLKey("eab"), integrations.YAMLKey("hmacKey"),
		},
		Rules: integrations.Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := engineWithFields(t, secret)
	source := []byte(`accounts:
  home:
    eab:
      kid: example-kid
      hmacKey: old-secret-canary
challenges:
  web:
    http: {}
certificates:
  one:
    domains: [one.example]
    account: home
    challenge: web
`)
	inspection, err := engine.Inspect(source)
	if err != nil {
		t.Fatal(err)
	}
	projected := findProjection(t, inspection, "account.eab_hmac")
	if !projected.Secret || !projected.Configured {
		t.Fatalf("secret projection = %#v", projected)
	}
	if _, ok := projected.Value(); ok {
		t.Fatal("secret projection exposed value")
	}
	encoded, _ := json.Marshal(inspection)
	if bytes.Contains(encoded, []byte("old-secret-canary")) {
		t.Fatalf("inspection JSON exposed secret: %s", encoded)
	}
	candidate, err := engine.Preview(source, []Change{{
		FieldID: "account.eab_hmac", Bindings: []Binding{{ID: "account", Value: "home"}},
		Operation: OperationSet, Value: integrations.StringValue("new-secret-canary"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Clear()
	if _, ok := candidate.Summary[0].Before(); ok {
		t.Fatal("secret YAML summary exposed before value")
	}
	if _, ok := candidate.Summary[0].After(); ok {
		t.Fatal("secret YAML summary exposed after value")
	}
	encoded, _ = json.Marshal(candidate)
	if bytes.Contains(encoded, []byte("new-secret-canary")) || bytes.Contains(encoded, []byte("old-secret-canary")) {
		t.Fatalf("candidate JSON exposed secret: %s", encoded)
	}
	same, err := engine.Preview(source, []Change{{
		FieldID: "account.eab_hmac", Bindings: []Binding{{ID: "account", Value: "home"}},
		Operation: OperationSet, Value: integrations.StringValue("old-secret-canary"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer same.Clear()
	if !same.Changed || same.SourceSHA256 == same.CandidateSHA256 || len(same.Summary) != len(candidate.Summary) ||
		same.Summary[0].Action != candidate.Summary[0].Action || !same.Summary[0].Secret {
		t.Fatalf("same-value secret set exposed equality: same=%#v different=%#v", same, candidate)
	}
}

func TestPreviewRejectsUntrustedSelectorsAndDuplicateChanges(t *testing.T) {
	engine := testEngine(t)
	_, err := engine.Preview([]byte(validNativeConfiguration), []Change{{
		FieldID: integrations.FieldWorkspaceStorage, Bindings: []Binding{{ID: "path", Value: "storage"}},
		Operation: OperationSet, Value: integrations.StringValue("x"),
	}})
	assertErrorCode(t, err, ErrorInvalidChange)
	_, err = engine.Preview([]byte(validNativeConfiguration), []Change{
		{FieldID: integrations.FieldWorkspaceStorage, Operation: OperationSet, Value: integrations.StringValue("one")},
		{FieldID: integrations.FieldWorkspaceStorage, Operation: OperationRemove},
	})
	assertErrorCode(t, err, ErrorInvalidChange)
}

func TestSchemaCompilationDisablesRemoteResolution(t *testing.T) {
	manifest, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	_, err := compileSchema([]byte(`{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "$ref":"file:///tmp/should-not-be-read.json"
}`))
	assertErrorCode(t, err, ErrorSchemaInvalid)
	_, err = NewEngine("unknown", []byte(`{"$schema":"http://json-schema.org/draft-07/schema#"}`), manifest, DefaultLimits())
	assertErrorCode(t, err, ErrorRuntimeMismatch)
	_, err = NewEngine(compatibility.ManifestLegoV531, []byte(`{"$schema":"http://json-schema.org/draft-07/schema#"}`), manifest, DefaultLimits())
	assertErrorCode(t, err, ErrorSchemaInvalid)

	wrongKind, fieldErr := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "workspace.invalid_storage", Label: "Invalid storage", Kind: integrations.FieldBoolean,
		Target: integrations.TargetYAML, Sensitivity: integrations.SensitivityPublic, Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{integrations.YAMLKey("storage")},
	})
	if fieldErr != nil {
		t.Fatal(fieldErr)
	}
	badManifest, fieldErr := integrations.NewManifest("bad", []compatibility.ManifestID{compatibility.ManifestLegoV531}, wrongKind)
	if fieldErr != nil {
		t.Fatal(fieldErr)
	}
	schema, _ := compatibility.Schema(compatibility.ManifestLegoV531)
	_, err = NewEngine(compatibility.ManifestLegoV531, schema, badManifest, DefaultLimits())
	assertErrorCode(t, err, ErrorManifestInvalid)
}

func TestCodeOfTraversesWrappedErrors(t *testing.T) {
	err := errors.Join(errors.New("outer"), &Error{Code: ErrorInvalidChange, Detail: "fixed"})
	if got := CodeOf(err); got != ErrorInvalidChange {
		t.Fatalf("CodeOf() = %q", got)
	}
	if got := CodeOf(errors.New("foreign")); got != "" {
		t.Fatalf("CodeOf(foreign) = %q", got)
	}
}

func FuzzInspectBoundedNativeYAML(f *testing.F) {
	schema, err := compatibility.Schema(compatibility.ManifestLegoV531)
	if err != nil {
		f.Fatal(err)
	}
	manifest, _ := integrations.BaseManifest(compatibility.ManifestLegoV531)
	limits := DefaultLimits()
	limits.MaxBytes = 8 << 10
	limits.MaxNodes = 512
	limits.MaxDepth = 32
	limits.MaxIssues = 64
	limits.MaxProjectionFields = 64
	engine, err := NewEngine(compatibility.ManifestLegoV531, schema, manifest, limits)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		[]byte(validNativeConfiguration),
		[]byte("storage: &value .lego\nuserAgent: *value\ncertificates: {}\n"),
		[]byte("storage: !custom value\ncertificates: {}\n"),
		{0xff, 0xfe, 0xfd},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		inspection, inspectErr := engine.Inspect(source)
		if inspectErr != nil && CodeOf(inspectErr) == "" {
			t.Fatalf("Inspect returned foreign error: %T", inspectErr)
		}
		if len(inspection.Issues) > limits.MaxIssues || len(inspection.Projection) > limits.MaxProjectionFields {
			t.Fatalf("bounded output exceeded limits: issues=%d projection=%d", len(inspection.Issues), len(inspection.Projection))
		}
	})
}

func hasIssue(issues []Issue, class IssueClass) bool {
	for _, issue := range issues {
		if issue.Class == class {
			return true
		}
	}
	return false
}

func findProjection(t *testing.T, inspection Inspection, id integrations.FieldID) ProjectedField {
	t.Helper()
	for _, field := range inspection.Projection {
		if field.FieldID == id {
			return field
		}
	}
	t.Fatalf("projection %q not found: %#v", id, inspection.Projection)
	return ProjectedField{}
}

func assertErrorCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var configError *Error
	if !errors.As(err, &configError) || configError.Code != code {
		t.Fatalf("error = %#v, want %q", err, code)
	}
}
