package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/integrations"
	"github.com/acmemux/AcmeMux/internal/nativeconfig"
	acmeruntime "github.com/acmemux/AcmeMux/internal/runtime"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

const serviceTestConfiguration = `# authoritative native file
networkStack: ipv4only
accounts:
  home:
    server: letsencrypt
    acceptsTermsOfService: true
challenges:
  web:
    http:
      address: ":8080"
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: web
`

const task07EABCanary = "AQIDBAUGBwgJ-secret-safe_url"

type fakeRuntimeSelections struct {
	selection acmeruntime.Selection
}

func (store fakeRuntimeSelections) Load(context.Context) (acmeruntime.Selection, error) {
	return store.selection, nil
}

type fakeRuntimeInspector struct {
	observation acmeruntime.Observation
}

func (inspector fakeRuntimeInspector) Verify(context.Context, acmeruntime.Observation) (acmeruntime.Observation, error) {
	return inspector.observation, nil
}

type fakeTransactions struct {
	mu                sync.Mutex
	workingDirectory  string
	configurationPath string
	dotenvPath        string
	configuration     []byte
	dotenv            []byte
	generation        uint64
	recovery          *workspace.Recovery
	commits           int
	selectionMissing  bool
}

func (fake *fakeTransactions) Snapshot(context.Context, *workspace.Lease) (*workspace.SourceSet, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.recovery != nil {
		return nil, workspace.ErrRecoveryRequired
	}
	if fake.selectionMissing {
		return nil, workspace.ErrNoSelection
	}
	return fake.snapshot(), nil
}

func (fake *fakeTransactions) snapshot() *workspace.SourceSet {
	generation := fake.generation
	if generation == 0 {
		generation = 1
	}
	stamp := time.Date(2026, 8, 15, 12, 0, int(generation), 0, time.UTC)
	configurationIdentity := workspace.FileIdentity{
		Exists: true, Device: 1, Inode: 100 + generation, Mode: 0o600,
		UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), NLink: 1,
		Size: int64(len(fake.configuration)), ModifiedAt: stamp, ChangedAt: stamp,
	}
	review := workspace.Review{
		ConfigurationSource: workspace.ConfigurationExplicit, Adoptable: true,
		WorkingDirectory: workspace.PathEvidence{
			Role: workspace.RoleWorkingDirectory, Path: fake.workingDirectory,
		},
		Configuration: workspace.PathEvidence{
			Role: workspace.RoleConfiguration, Reference: fake.configurationPath,
			Path: fake.configurationPath,
		},
		Storage: workspace.PathEvidence{
			Role: workspace.RoleStorage, Reference: ".lego",
			Path: filepath.Join(fake.workingDirectory, ".lego"), Safe: true, Exists: true,
		},
	}
	sources := &workspace.SourceSet{
		Selection: workspace.Selection{Review: review, ReviewedAt: stamp},
		Configuration: workspace.SourceFile{
			Role: workspace.RoleConfiguration, Path: fake.configurationPath,
			Reference: fake.configurationPath, Content: slices.Clone(fake.configuration),
			Fingerprint: workspace.SourceFingerprint{
				Path: fake.configurationPath, Identity: configurationIdentity,
				SHA256: sha256.Sum256(fake.configuration),
			},
		},
	}
	if fake.dotenvPath != "" {
		dotenvIdentity := workspace.FileIdentity{
			Exists: true, Device: 1, Inode: 200 + generation, Mode: 0o600,
			UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), NLink: 1,
			Size: int64(len(fake.dotenv)), ModifiedAt: stamp, ChangedAt: stamp,
		}
		sources.Selection.Review.DotenvFiles = []workspace.PathEvidence{{
			Role: workspace.RoleDotenv, Reference: filepath.Base(fake.dotenvPath), Path: fake.dotenvPath,
		}}
		sources.Dotenv = []workspace.SourceFile{{
			Role: workspace.RoleDotenv, Path: fake.dotenvPath, Reference: filepath.Base(fake.dotenvPath),
			Content: slices.Clone(fake.dotenv), Fingerprint: workspace.SourceFingerprint{
				Path: fake.dotenvPath, Identity: dotenvIdentity, SHA256: sha256.Sum256(fake.dotenv),
			},
		}}
	}
	return sources
}

func (fake *fakeTransactions) AuditCandidate(context.Context, *workspace.Lease, *workspace.SourceSet, []byte, []workspace.Replacement) (workspace.CandidateAudit, error) {
	return workspace.CandidateAudit{}, nil
}

func (fake *fakeTransactions) Commit(_ context.Context, _ *workspace.Lease, plan workspace.CommitPlan, guard workspace.CommitGuard) (workspace.Selection, error) {
	if err := guard(context.Background()); err != nil {
		return workspace.Selection{}, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, replacement := range plan.Replacements {
		switch replacement.Role {
		case workspace.RoleConfiguration:
			fake.configuration = slices.Clone(replacement.Content)
		case workspace.RoleDotenv:
			fake.dotenv = slices.Clone(replacement.Content)
			fake.dotenvPath = replacement.Path
		}
	}
	fake.generation++
	fake.commits++
	return fake.snapshot().Selection, nil
}

func (fake *fakeTransactions) AuditBootstrap(
	context.Context,
	*workspace.Lease,
	workspace.BootstrapRequest,
	[]byte,
	[]workspace.Replacement,
) (workspace.BootstrapAudit, error) {
	return workspace.BootstrapAudit{}, nil
}

func (fake *fakeTransactions) Bootstrap(
	ctx context.Context,
	_ *workspace.Lease,
	plan workspace.BootstrapPlan,
	guard workspace.CommitGuard,
) (workspace.Selection, error) {
	if err := guard(ctx); err != nil {
		return workspace.Selection{}, err
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.selectionMissing {
		return workspace.Selection{}, workspace.ErrSourceChanged
	}
	for _, replacement := range plan.Replacements {
		switch replacement.Role {
		case workspace.RoleConfiguration:
			fake.configuration = slices.Clone(replacement.Content)
			fake.configurationPath = replacement.Path
		case workspace.RoleDotenv:
			fake.dotenv = slices.Clone(replacement.Content)
			fake.dotenvPath = replacement.Path
		}
	}
	fake.workingDirectory = plan.Request.WorkingDirectory
	fake.selectionMissing = false
	fake.generation++
	fake.commits++
	return fake.snapshot().Selection, nil
}

func (fake *fakeTransactions) InspectRecovery(context.Context, *workspace.Lease) (workspace.Recovery, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.recovery == nil {
		return workspace.Recovery{}, workspace.ErrNoEditJournal
	}
	result := *fake.recovery
	result.Files = slices.Clone(fake.recovery.Files)
	return result, nil
}

func (fake *fakeTransactions) ResolveRecovery(
	ctx context.Context,
	_ *workspace.Lease,
	resolution workspace.RecoveryResolution,
	guard workspace.CommitGuard,
	validator workspace.RecoveryValidator,
) (workspace.RecoveryResult, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.recovery == nil {
		return workspace.RecoveryResult{}, workspace.ErrNoEditJournal
	}
	if err := guard(ctx); err != nil {
		return workspace.RecoveryResult{}, err
	}
	switch resolution {
	case workspace.ResolutionDiscardUnapplied:
		if fake.recovery.State != workspace.RecoveryUnapplied {
			return workspace.RecoveryResult{}, workspace.ErrInvalidEdit
		}
		bootstrap := fake.recovery.Bootstrap
		fake.recovery = nil
		if bootstrap {
			fake.selectionMissing = true
			return workspace.RecoveryResult{}, nil
		}
	case workspace.ResolutionFinalizeApplied:
		if fake.recovery.Bootstrap || fake.recovery.State != workspace.RecoveryApplied || validator == nil {
			return workspace.RecoveryResult{}, workspace.ErrInvalidEdit
		}
		sources := fake.snapshot()
		defer sources.Close()
		if err := validator(ctx, sources); err != nil {
			return workspace.RecoveryResult{}, err
		}
	case workspace.ResolutionAdoptCurrent:
		if (fake.recovery.State != workspace.RecoveryApplied &&
			fake.recovery.State != workspace.RecoveryPartial &&
			fake.recovery.State != workspace.RecoveryAmbiguous) || validator == nil {
			return workspace.RecoveryResult{}, workspace.ErrInvalidEdit
		}
		sources := fake.snapshot()
		defer sources.Close()
		if err := validator(ctx, sources); err != nil {
			return workspace.RecoveryResult{}, err
		}
	default:
		return workspace.RecoveryResult{}, workspace.ErrInvalidEdit
	}
	fake.recovery = nil
	fake.selectionMissing = false
	return workspace.RecoveryResult{Selection: fake.snapshot().Selection, SelectionPresent: true}, nil
}

func newTestService(t *testing.T, transactions *fakeTransactions, factory EngineFactory, key byte) *Service {
	t.Helper()
	stateDirectory := t.TempDir()
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	coordinator, err := workspace.NewCoordinator(filepath.Join(stateDirectory, "workspace.lock"))
	if err != nil {
		t.Fatal(err)
	}
	observation := acmeruntime.Observation{
		Version: acmeruntime.VersionIdentity{Kind: acmeruntime.VersionRelease, Value: "v5.3.1"},
	}
	selection := acmeruntime.Selection{
		Observation: observation, ManifestID: string(compatibility.ManifestLegoV531),
		ReviewedAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
	}
	service, err := New(Dependencies{
		RuntimeSelections: fakeRuntimeSelections{selection: selection},
		RuntimeInspector:  fakeRuntimeInspector{observation: observation},
		Classify: func(acmeruntime.Observation) compatibility.Result {
			return compatibility.Result{Code: compatibility.CodeCompatible, ManifestID: compatibility.ManifestLegoV531}
		},
		Coordinator: coordinator, Transactions: transactions, EngineFactory: factory,
		Random: bytes.NewReader(bytes.Repeat([]byte{key}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func secretTestEngineFactory(t *testing.T) EngineFactory {
	t.Helper()
	secretField, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "provider.api_token", Label: "Provider API token", Kind: integrations.FieldString,
		Target: integrations.TargetDotenv, Sensitivity: integrations.SensitivitySecret,
		Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{
			integrations.YAMLKey("challenges"), integrations.YAMLBinding("challenge"),
			integrations.YAMLKey("dns"), integrations.YAMLKey("envFile"),
		},
		EnvironmentKey: "CLOUDFLARE_DNS_API_TOKEN", Rules: integrations.Rules{MaxBytes: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	return func(runtimeID compatibility.ManifestID) (*nativeconfig.Engine, integrations.Manifest, error) {
		base, _ := integrations.BaseManifest(runtimeID)
		manifest, err := base.Extend("secret-test-v1", secretField)
		if err != nil {
			return nil, integrations.Manifest{}, err
		}
		schema, err := compatibility.Schema(runtimeID)
		if err != nil {
			return nil, integrations.Manifest{}, err
		}
		engine, err := nativeconfig.NewEngine(runtimeID, schema, manifest, nativeconfig.DefaultLimits())
		clear(schema)
		return engine, manifest, err
	}
}

func newDotenvFileTestEngineFactory(t *testing.T) EngineFactory {
	t.Helper()
	envFile, err := integrations.NewFieldSpec(integrations.FieldDefinition{
		ID: "challenge.env_file", Label: "Credential file", Kind: integrations.FieldString,
		Target: integrations.TargetYAML, Sensitivity: integrations.SensitivityPublic,
		Disposition: integrations.DispositionManaged,
		Selector: []integrations.SelectorSegment{
			integrations.YAMLKey("challenges"), integrations.YAMLBinding("challenge"),
			integrations.YAMLKey("dns"), integrations.YAMLKey("envFile"),
		},
		Rules: integrations.Rules{MaxBytes: 4095},
	})
	if err != nil {
		t.Fatal(err)
	}
	secretFactory := secretTestEngineFactory(t)
	return func(runtimeID compatibility.ManifestID) (*nativeconfig.Engine, integrations.Manifest, error) {
		_, secretManifest, err := secretFactory(runtimeID)
		if err != nil {
			return nil, integrations.Manifest{}, err
		}
		manifest, err := secretManifest.Extend("new-dotenv-test-v1", envFile)
		if err != nil {
			return nil, integrations.Manifest{}, err
		}
		schema, err := compatibility.Schema(runtimeID)
		if err != nil {
			return nil, integrations.Manifest{}, err
		}
		engine, err := nativeconfig.NewEngine(runtimeID, schema, manifest, nativeconfig.DefaultLimits())
		clear(schema)
		return engine, manifest, err
	}
}

func TestSnapshotUsesOpaqueSourceTokenAndPreservesUnsupportedNativeContent(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		configuration: []byte(serviceTestConfiguration), generation: 1,
	}
	service := newTestService(t, transactions, nil, 0x11)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.State != StateUnsupported || !view.Editing || view.Execution {
		t.Fatalf("view state/capabilities = %s/%v/%v", view.State, view.Editing, view.Execution)
	}
	if len(view.Source.BaseRevisionToken) != 43 {
		t.Fatalf("revision token = %q", view.Source.BaseRevisionToken)
	}
	rawDigest := sha256.Sum256(transactions.configuration)
	if view.Source.BaseRevisionToken == hex.EncodeToString(rawDigest[:]) {
		t.Fatal("revision token exposed an unkeyed content digest")
	}
	if !slices.ContainsFunc(view.Inspection.Projection, func(field nativeconfig.ProjectedField) bool {
		return field.FieldID == integrations.FieldWorkspaceStorage && field.Label == "Workspace storage"
	}) {
		t.Fatalf("projection = %#v", view.Inspection.Projection)
	}
	if len(view.Diagnostics) == 0 || view.Diagnostics[0].Code != CodeUnsupportedContent {
		t.Fatalf("diagnostics = %#v", view.Diagnostics)
	}
}

func TestPreviewAndSaveRequireExactOpaqueReviewTokens(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		configuration: []byte(serviceTestConfiguration), generation: 1,
	}
	service := newTestService(t, transactions, nil, 0x22)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := []nativeconfig.Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
		Value: integrations.StringValue("/srv/lego"),
	}}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.ReviewedPreviewToken) != 43 || len(preview.Summary) != 1 {
		t.Fatalf("preview = %#v", preview)
	}
	if _, err := service.Save(context.Background(), view.Source.BaseRevisionToken, changes, strings.Repeat("A", 43), func(context.Context) error { return nil }); !errors.Is(err, ErrChanged) {
		t.Fatalf("Save(wrong token) error = %v", err)
	}
	if transactions.commits != 0 {
		t.Fatal("wrong review token committed native files")
	}
	updated, err := service.Save(context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if transactions.commits != 1 || updated.Source.BaseRevisionToken == view.Source.BaseRevisionToken || !bytes.Contains(transactions.configuration, []byte("storage: /srv/lego")) {
		t.Fatalf("commit result = commits:%d token:%q config:%s", transactions.commits, updated.Source.BaseRevisionToken, transactions.configuration)
	}
}

func TestRepairableConstraintStateRemainsEditableButCannotSaveUnrepairedCandidate(t *testing.T) {
	directory := t.TempDir()
	source := []byte(`storage: ./native
accounts:
  home: {}
challenges:
  web:
    http:
      address: ":8080"
certificates:
  gateway:
    domains: [gateway.home.example]
`)
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		configuration: source, generation: 1,
	}
	service := newTestService(t, transactions, nil, 0x23)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.State != StateInvalid || !view.Editing || view.Execution {
		t.Fatalf("repairable constraint view = %#v", view)
	}
	unrepaired, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, []nativeconfig.Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
		Value: integrations.StringValue("./other-native"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if unrepaired.State != PreviewInvalid || unrepaired.ResultingState != StateInvalid || unrepaired.ReviewedPreviewToken != "" {
		t.Fatalf("unrepaired candidate = %#v", unrepaired)
	}
	repaired, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, []nativeconfig.Change{
		{
			FieldID:   integrations.FieldAccountServer,
			Bindings:  []nativeconfig.Binding{{ID: integrations.BindingAccount, Value: "home"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("letsencrypt"),
		},
		{
			FieldID:   integrations.FieldCertificateAccount,
			Bindings:  []nativeconfig.Binding{{ID: integrations.BindingCertificate, Value: "gateway"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("home"),
		},
		{
			FieldID:   integrations.FieldCertificateChallenge,
			Bindings:  []nativeconfig.Binding{{ID: integrations.BindingCertificate, Value: "gateway"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("web"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if repaired.State != PreviewReviewRequired || repaired.ResultingState != StateReady || len(repaired.ReviewedPreviewToken) != 43 {
		t.Fatalf("repaired candidate = %#v", repaired)
	}
}

func TestUnrelatedStorageEditPreservesImplicitUnsupportedChallenge(t *testing.T) {
	for index, challengeName := range []string{"tls-alpn-01", "dns-persist-01"} {
		t.Run(challengeName, func(t *testing.T) {
			directory := t.TempDir()
			source := []byte(`storage: ./native
accounts:
  home:
    server: letsencrypt
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: ` + challengeName + "\n")
			transactions := &fakeTransactions{
				workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
				configuration: source, generation: 1,
			}
			service := newTestService(t, transactions, nil, byte(0x24+index))
			view, err := service.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if view.State != StateUnsupported || !view.Editing || view.Execution ||
				!slices.ContainsFunc(view.Diagnostics, func(diagnostic Diagnostic) bool {
					return diagnostic.Code == CodeUnsupportedChallenge
				}) {
				t.Fatalf("implicit built-in view = %#v", view)
			}
			changes := []nativeconfig.Change{{
				FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
				Value: integrations.StringValue("./other-native"),
			}}
			preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
			if err != nil {
				t.Fatal(err)
			}
			if preview.State != PreviewReviewRequired || preview.ResultingState != StateUnsupported || preview.Execution {
				t.Fatalf("implicit built-in preview = %#v", preview)
			}
			updated, err := service.Save(
				context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, allowServiceCommit,
			)
			if err != nil {
				t.Fatal(err)
			}
			if updated.State != StateUnsupported || updated.Execution ||
				!bytes.Contains(transactions.configuration, []byte("challenge: "+challengeName)) ||
				bytes.Contains(transactions.configuration, []byte("challenges:")) {
				t.Fatalf("unrelated edit changed implicit built-in: %s, %#v", transactions.configuration, updated)
			}
		})
	}
}

func TestUnrelatedStorageEditPreservesExplicitUnsupportedEntities(t *testing.T) {
	tests := []struct {
		name, source, retained string
		prohibited             []string
	}{
		{
			name: "TLS-ALPN challenge",
			source: `storage: ./native
accounts:
  home:
    server: letsencrypt
challenges:
  alpn:
    tls:
      address: ":443"
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
`, retained: "tls:\n      address: \":443\"", prohibited: []string{"http:", "\n    challenge:"},
		},
		{
			name: "HTTP memcached challenge",
			source: `storage: ./native
accounts:
  home:
    server: letsencrypt
challenges:
  cache:
    http:
      memcachedHosts: [127.0.0.1:11211]
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: cache
`, retained: "memcachedHosts:", prohibited: []string{"address: :80"},
		},
		{
			name: "HTTP S3 challenge",
			source: `storage: ./native
accounts:
  home:
    server: letsencrypt
challenges:
  object:
    http:
      s3Bucket: acme-tokens
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: object
`, retained: "s3Bucket: acme-tokens", prohibited: []string{"address: :80"},
		},
		{
			name: "CSR certificate",
			source: `storage: ./native
accounts:
  home:
    server: letsencrypt
certificates:
  imported:
    csr: request.csr
    account: home
    challenge: http-01
`, retained: "csr: request.csr", prohibited: []string{"domains:", "challenges:"},
		},
		{
			name: "PFX output",
			source: `storage: ./native
accounts:
  home:
    server: letsencrypt
challenges:
  web:
    http:
      address: ":8080"
certificates:
  gateway:
    domains: [gateway.home.example]
    pfx:
      password: pfx-preserved-canary
      format: SHA256
`, retained: "pfx:\n      password: pfx-preserved-canary\n      format: SHA256", prohibited: []string{"\n    account:", "\n    challenge:", "keyType:", "renew:"},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			transactions := &fakeTransactions{
				workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
				configuration: []byte(test.source), generation: 1,
			}
			service := newTestService(t, transactions, nil, byte(0x2a+index))
			view, err := service.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if view.State != StateUnsupported || !view.Editing || view.Execution ||
				!slices.ContainsFunc(view.Diagnostics, func(diagnostic Diagnostic) bool {
					return diagnostic.Code == CodeUnsupportedChallenge || diagnostic.Code == CodeUnsupportedContent ||
						diagnostic.Code == CodeUnsupportedOutput
				}) {
				t.Fatalf("unsupported entity view = %#v", view)
			}
			changes := []nativeconfig.Change{{
				FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
				Value: integrations.StringValue("./other-native"),
			}}
			preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
			if err != nil {
				t.Fatal(err)
			}
			if preview.State != PreviewReviewRequired || preview.ResultingState != StateUnsupported || preview.Execution {
				t.Fatalf("unsupported entity preview = %#v", preview)
			}
			updated, err := service.Save(
				context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, allowServiceCommit,
			)
			if err != nil {
				t.Fatal(err)
			}
			materialized := slices.ContainsFunc(test.prohibited, func(value string) bool {
				return bytes.Contains(transactions.configuration, []byte(value))
			})
			if updated.State != StateUnsupported || updated.Execution ||
				!bytes.Contains(transactions.configuration, []byte(test.retained)) || materialized {
				t.Fatalf("unrelated edit changed unsupported entity: %s, %#v", transactions.configuration, updated)
			}
		})
	}
}

func TestSaveRejectsSourceChangeAfterPreview(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		configuration: []byte(serviceTestConfiguration), generation: 1,
	}
	service := newTestService(t, transactions, nil, 0x33)
	view, _ := service.Snapshot(context.Background())
	changes := []nativeconfig.Change{{
		FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
		Value: integrations.StringValue("/srv/lego"),
	}}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	transactions.mu.Lock()
	transactions.configuration = append(transactions.configuration, []byte("# external\n")...)
	transactions.generation++
	transactions.mu.Unlock()
	if _, err := service.Save(context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, func(context.Context) error { return nil }); !errors.Is(err, ErrChanged) {
		t.Fatalf("Save(changed source) error = %v", err)
	}
	if transactions.commits != 0 {
		t.Fatal("changed source was overwritten")
	}
}

func TestReviewTokensAreProcessKeyed(t *testing.T) {
	directory := t.TempDir()
	newTransactions := func() *fakeTransactions {
		return &fakeTransactions{
			workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
			configuration: []byte(serviceTestConfiguration), generation: 1,
		}
	}
	left, _ := newTestService(t, newTransactions(), nil, 0x44).Snapshot(context.Background())
	right, _ := newTestService(t, newTransactions(), nil, 0x55).Snapshot(context.Background())
	if left.Source.BaseRevisionToken == right.Source.BaseRevisionToken {
		t.Fatal("independent processes produced the same source review token")
	}
}

func TestCreationRequiredPreviewAndCreateUseReviewedBootstrapToken(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{workingDirectory: directory, selectionMissing: true, generation: 1}
	service := newTestService(t, transactions, nil, 0x56)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.State != StateCreationRequired || len(view.Source.BaseRevisionToken) != 43 ||
		view.Source.ConfigurationPath != "" || len(view.Source.DotenvPaths) != 0 || view.Editing || view.Execution {
		t.Fatalf("creation-required view = %#v", view)
	}
	request := CreationRequest{WorkingDirectory: directory, Changes: completeCreationChanges()}
	preview, err := service.PreviewCreation(context.Background(), view.Source.BaseRevisionToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || preview.ResultingState != StateReady ||
		len(preview.ReviewedPreviewToken) != 43 || preview.BaseRevisionToken != view.Source.BaseRevisionToken {
		t.Fatalf("creation preview = %#v", preview)
	}
	if _, err := service.Create(context.Background(), view.Source.BaseRevisionToken, request, strings.Repeat("Z", 43), allowServiceCommit); !errors.Is(err, ErrChanged) {
		t.Fatalf("Create(wrong review token) error = %v", err)
	}
	if transactions.commits != 0 || !transactions.selectionMissing {
		t.Fatal("wrong creation token activated a configuration")
	}
	created, err := service.Create(context.Background(), view.Source.BaseRevisionToken, request, preview.ReviewedPreviewToken, allowServiceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if transactions.commits != 1 || transactions.selectionMissing || created.State != StateReady ||
		transactions.configurationPath != filepath.Join(directory, ".lego.yml") ||
		!bytes.Contains(transactions.configuration, []byte("server: letsencrypt")) {
		t.Fatalf("creation result = commits:%d missing:%v path:%q state:%s yaml:%s",
			transactions.commits, transactions.selectionMissing, transactions.configurationPath, created.State, transactions.configuration)
	}
}

func TestCreationPreviewEnforcesRegistrationInputsAndBindsTarget(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{workingDirectory: directory, selectionMissing: true, generation: 1}
	service := newTestService(t, transactions, nil, 0x57)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	missingEmail := slices.DeleteFunc(completeCreationChanges(), func(change nativeconfig.Change) bool {
		return change.FieldID == integrations.FieldAccountEmail
	})
	invalid, err := service.PreviewCreation(context.Background(), view.Source.BaseRevisionToken, CreationRequest{
		WorkingDirectory: directory, Changes: missingEmail,
	})
	if err != nil {
		t.Fatal(err)
	}
	if invalid.State != PreviewInvalid || invalid.ReviewedPreviewToken != "" || invalid.ResultingState != StateInvalid {
		t.Fatalf("missing-email preview = %#v", invalid)
	}

	first := CreationRequest{
		WorkingDirectory: directory, ConfigurationPath: filepath.Join(directory, "first.yml"),
		Changes: completeCreationChanges(),
	}
	reviewed, err := service.PreviewCreation(context.Background(), view.Source.BaseRevisionToken, first)
	if err != nil || reviewed.State != PreviewReviewRequired {
		t.Fatalf("first preview = %#v, error = %v", reviewed, err)
	}
	changedTarget := first
	changedTarget.ConfigurationPath = filepath.Join(directory, "second.yml")
	if _, err := service.Create(context.Background(), view.Source.BaseRevisionToken, changedTarget, reviewed.ReviewedPreviewToken, allowServiceCommit); !errors.Is(err, ErrChanged) {
		t.Fatalf("Create(changed target) error = %v, want ErrChanged", err)
	}
}

func TestGTSCreationKeepsEABHMACPresenceOnlyUntilNativeSave(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{workingDirectory: directory, selectionMissing: true, generation: 1}
	service := newTestService(t, transactions, nil, 0x5a)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := completeCreationChanges()
	for index := range changes {
		if changes[index].FieldID == integrations.FieldAccountServer {
			changes[index].Value = integrations.StringValue("googletrust")
		}
	}
	account := []nativeconfig.Binding{{ID: integrations.BindingAccount, Value: "home"}}
	changes = append(changes,
		nativeconfig.Change{FieldID: integrations.FieldAccountEABKID, Bindings: account, Operation: nativeconfig.OperationSet, Value: integrations.StringValue("public-kid")},
		nativeconfig.Change{FieldID: integrations.FieldAccountEABHMACKey, Bindings: account, Operation: nativeconfig.OperationSet, Value: integrations.StringValue(task07EABCanary)},
	)
	request := CreationRequest{WorkingDirectory: directory, Changes: changes}
	preview, err := service.PreviewCreation(context.Background(), view.Source.BaseRevisionToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || preview.ResultingState != StateReady {
		t.Fatalf("GTS creation preview = %#v", preview)
	}
	var hmacSummary *nativeconfig.ChangeSummary
	for index := range preview.Summary {
		if preview.Summary[index].FieldID == integrations.FieldAccountEABHMACKey {
			hmacSummary = &preview.Summary[index]
			break
		}
	}
	if hmacSummary == nil || !hmacSummary.Secret || hmacSummary.Action != nativeconfig.SummarySet {
		t.Fatalf("HMAC summary = %#v", hmacSummary)
	}
	if _, present := hmacSummary.Before(); present {
		t.Fatal("HMAC summary exposed a before value")
	}
	if _, present := hmacSummary.After(); present {
		t.Fatal("HMAC summary exposed an after value")
	}
	if strings.Contains(preview.BaseRevisionToken, task07EABCanary) ||
		strings.Contains(preview.ReviewedPreviewToken, task07EABCanary) ||
		strings.Contains(fmt.Sprintf("%#v", preview.Diagnostics), task07EABCanary) {
		t.Fatal("GTS preview metadata exposed EAB HMAC")
	}
	if _, err := service.Create(context.Background(), view.Source.BaseRevisionToken, request, preview.ReviewedPreviewToken, allowServiceCommit); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(transactions.configuration, []byte("hmacKey: "+task07EABCanary)) {
		t.Fatalf("saved GTS YAML does not contain exact HMAC: %s", transactions.configuration)
	}
}

func TestCoreDNSCreationAtomicallyCreatesRestrictiveCredentialSource(t *testing.T) {
	directory := t.TempDir()
	transactions := &fakeTransactions{workingDirectory: directory, selectionMissing: true, generation: 1}
	service := newTestService(t, transactions, nil, 0x5c)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := completeCreationChanges()
	challenge := []nativeconfig.Binding{{ID: integrations.BindingChallenge, Value: "web"}}
	for index := len(changes) - 1; index >= 0; index-- {
		if changes[index].FieldID == integrations.FieldChallengeHTTPAddress || changes[index].FieldID == integrations.FieldChallengeHTTPDelay {
			changes = slices.Delete(changes, index, index+1)
		}
	}
	set := func(field integrations.FieldID, value integrations.Value) nativeconfig.Change {
		return nativeconfig.Change{FieldID: field, Bindings: challenge, Operation: nativeconfig.OperationSet, Value: value}
	}
	const secret = "task09-cloudflare-secret-canary"
	changes = append(changes,
		set(integrations.FieldChallengeDNSProvider, integrations.StringValue("cloudflare")),
		set(integrations.FieldChallengeDNSEnvFile, integrations.StringValue(".cloudflare.env")),
		set(integrations.FieldChallengeDNSTimeout, integrations.IntegerValue(30)),
		set(integrations.FieldChallengeDNSDisableAuthoritativeNameservers, integrations.BooleanValue(false)),
		set(integrations.FieldChallengeDNSDisableRecursiveNameservers, integrations.BooleanValue(false)),
		set(integrations.FieldChallengeDNSPropagationWait, integrations.StringValue("0s")),
		set(integrations.FieldCloudflareDNSAPIToken, integrations.StringValue(secret)),
		set(integrations.FieldCloudflareTTL, integrations.StringValue("300")),
	)
	request := CreationRequest{WorkingDirectory: directory, Changes: changes}
	preview, err := service.PreviewCreation(context.Background(), view.Source.BaseRevisionToken, request)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || preview.ResultingState != StateReady || !preview.Execution {
		t.Fatalf("DNS creation preview = %#v", preview)
	}
	if strings.Contains(fmt.Sprintf("%#v", preview), secret) {
		t.Fatal("DNS creation preview exposed the provider token")
	}
	created, err := service.Create(context.Background(), view.Source.BaseRevisionToken, request, preview.ReviewedPreviewToken, allowServiceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if created.State != StateReady || !created.Execution || transactions.dotenvPath != filepath.Join(directory, ".cloudflare.env") ||
		!bytes.Contains(transactions.dotenv, []byte("CLOUDFLARE_DNS_API_TOKEN='"+secret+"'")) ||
		!bytes.Contains(transactions.dotenv, []byte("CLOUDFLARE_TTL='300'")) {
		t.Fatalf("created DNS workspace = state:%s execution:%v path:%q dotenv:%q", created.State, created.Execution, transactions.dotenvPath, transactions.dotenv)
	}
}

func TestCoreDNSCredentialRotationIsWriteOnlyAndAtomic(t *testing.T) {
	directory := t.TempDir()
	const oldToken = "task09-old-cloudflare-secret"
	const newToken = "task09-new-cloudflare-secret"
	transactions := &fakeTransactions{
		workingDirectory:  directory,
		configurationPath: filepath.Join(directory, ".lego.yml"),
		dotenvPath:        filepath.Join(directory, ".cloudflare.env"),
		configuration:     []byte(coreDNSServiceTestConfiguration),
		dotenv:            []byte("CLOUDFLARE_DNS_API_TOKEN='" + oldToken + "'\nUNMANAGED='preserved'\n"),
		generation:        1,
	}
	service := newTestService(t, transactions, nil, 0x2f)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := []nativeconfig.Change{{
		FieldID:   integrations.FieldCloudflareDNSAPIToken,
		Bindings:  []nativeconfig.Binding{{ID: integrations.BindingChallenge, Value: "dns-home"}},
		Operation: nativeconfig.OperationSet,
		Value:     integrations.StringValue(newToken),
	}}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.Summary) != 1 || !preview.Summary[0].Secret ||
		strings.Contains(fmt.Sprintf("%#v", preview), oldToken) || strings.Contains(fmt.Sprintf("%#v", preview), newToken) {
		t.Fatalf("credential rotation preview = %#v", preview)
	}
	if _, err := service.Save(
		context.Background(), view.Source.BaseRevisionToken, changes,
		preview.ReviewedPreviewToken, allowServiceCommit,
	); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(transactions.dotenv, []byte(oldToken)) ||
		!bytes.Contains(transactions.dotenv, []byte("CLOUDFLARE_DNS_API_TOKEN='"+newToken+"'")) ||
		!bytes.Contains(transactions.dotenv, []byte("UNMANAGED='preserved'")) {
		t.Fatalf("rotated provider dotenv = %q", transactions.dotenv)
	}
}

func TestBootstrapRecoveryAdoptionUsesCreationPrerequisites(t *testing.T) {
	for _, recoveryState := range []workspace.RecoveryState{workspace.RecoveryApplied, workspace.RecoveryAmbiguous} {
		t.Run(string(recoveryState), func(t *testing.T) {
			directory := t.TempDir()
			configurationPath := filepath.Join(directory, ".lego.yml")
			transactions := &fakeTransactions{
				workingDirectory: directory, configurationPath: configurationPath,
				configuration: []byte(serviceTestConfiguration), generation: 1, selectionMissing: true,
				recovery: &workspace.Recovery{
					TransactionID: strings.Repeat("d", 32), WorkingDirectory: directory,
					ConfigurationPath: configurationPath, Bootstrap: true,
					Phase: workspace.JournalFinalizing, State: recoveryState,
					Files: []workspace.RecoveryFile{{
						Ordinal: 0, Role: workspace.RoleConfiguration, Path: configurationPath,
						State: workspace.RecoveryFileApplied,
					}},
				},
			}
			service := newTestService(t, transactions, nil, 0x58)
			recovery, err := service.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !recovery.Recovery.Bootstrap {
				t.Fatalf("recovery view = %#v", recovery)
			}
			if _, err := service.ResolveRecovery(context.Background(), recovery.Source.BaseRevisionToken, workspace.ResolutionAdoptCurrent, allowServiceCommit); !errors.Is(err, ErrInvalid) {
				t.Fatalf("ResolveRecovery(invalid bootstrap) error = %v, want ErrInvalid", err)
			}
			if transactions.recovery == nil || !transactions.selectionMissing {
				t.Fatal("invalid bootstrap recovery was adopted")
			}
		})
	}
}

func TestDiscardedBootstrapRecoveryReturnsToCreationRequired(t *testing.T) {
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, ".lego.yml")
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: configurationPath,
		configuration: []byte(serviceTestConfiguration), generation: 1, selectionMissing: true,
		recovery: &workspace.Recovery{
			TransactionID: strings.Repeat("e", 32), WorkingDirectory: directory,
			ConfigurationPath: configurationPath, Bootstrap: true,
			Phase: workspace.JournalPrepared, State: workspace.RecoveryUnapplied,
			Files: []workspace.RecoveryFile{{
				Ordinal: 0, Role: workspace.RoleConfiguration, Path: configurationPath,
				State: workspace.RecoveryFileUnapplied,
			}},
		},
	}
	service := newTestService(t, transactions, nil, 0x59)
	recovery, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.ResolveRecovery(context.Background(), recovery.Source.BaseRevisionToken, workspace.ResolutionDiscardUnapplied, allowServiceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != StateCreationRequired || transactions.recovery != nil || !transactions.selectionMissing {
		t.Fatalf("discarded creation recovery = %#v, recovery %#v", view, transactions.recovery)
	}
}

func completeCreationChanges() []nativeconfig.Change {
	account := []nativeconfig.Binding{{ID: integrations.BindingAccount, Value: "home"}}
	challenge := []nativeconfig.Binding{{ID: integrations.BindingChallenge, Value: "web"}}
	certificate := []nativeconfig.Binding{{ID: integrations.BindingCertificate, Value: "gateway"}}
	set := func(field integrations.FieldID, bindings []nativeconfig.Binding, value integrations.Value) nativeconfig.Change {
		return nativeconfig.Change{FieldID: field, Bindings: bindings, Operation: nativeconfig.OperationSet, Value: value}
	}
	return []nativeconfig.Change{
		set(integrations.FieldWorkspaceStorage, nil, integrations.StringValue("./native-storage")),
		set(integrations.FieldAccountServer, account, integrations.StringValue("letsencrypt")),
		set(integrations.FieldAccountEmail, account, integrations.StringValue("admin@example.com")),
		set(integrations.FieldAccountKeyType, account, integrations.StringValue("EC256")),
		set(integrations.FieldAccountAcceptsTerms, account, integrations.BooleanValue(true)),
		set(integrations.FieldChallengeHTTPAddress, challenge, integrations.StringValue(":8080")),
		set(integrations.FieldChallengeHTTPDelay, challenge, integrations.StringValue("0s")),
		set(integrations.FieldCertificateDomains, certificate, integrations.StringListValue([]string{"gateway.home.example"})),
		set(integrations.FieldCertificateKeyType, certificate, integrations.StringValue("EC256")),
		set(integrations.FieldCertificateAccount, certificate, integrations.StringValue("home")),
		set(integrations.FieldCertificateChallenge, certificate, integrations.StringValue("web")),
		set(integrations.FieldCertificateRenewDays, certificate, integrations.IntegerValue(0)),
		set(integrations.FieldCertificateRenewReuseKey, certificate, integrations.BooleanValue(false)),
		set(integrations.FieldCertificateRenewRandomSleep, certificate, integrations.BooleanValue(false)),
		set(integrations.FieldCertificateRenewARIDisable, certificate, integrations.BooleanValue(false)),
		set(integrations.FieldCertificateRenewARIWait, certificate, integrations.StringValue("0s")),
	}
}

func TestSnapshotSurfacesSecretFreeRecovery(t *testing.T) {
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "lego.yml")
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: configurationPath,
		configuration: []byte(serviceTestConfiguration), generation: 1,
		recovery: &workspace.Recovery{
			TransactionID: strings.Repeat("a", 32), WorkingDirectory: directory,
			ConfigurationPath: configurationPath, Phase: workspace.JournalReplacing,
			State: workspace.RecoveryPartial, Files: []workspace.RecoveryFile{{
				Ordinal: 0, Role: workspace.RoleDotenv, Path: filepath.Join(directory, ".env"),
				State: workspace.RecoveryFileApplied,
			}},
		},
	}
	view, err := newTestService(t, transactions, nil, 0x66).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if view.State != StateRecoveryRequired || view.Recovery == nil || view.Source.ConfigurationPath != configurationPath || view.Editing || view.Execution {
		t.Fatalf("recovery view = %#v", view)
	}
	serialized := view.Source.BaseRevisionToken + view.Source.ConfigurationPath
	if strings.Contains(serialized, transactions.recovery.TransactionID) {
		t.Fatal("recovery response exposed the journal transaction ID")
	}
}

func TestResolveRecoveryAdoptsOnlyValidatedCurrentNativeFiles(t *testing.T) {
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "lego.yml")
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: configurationPath,
		configuration: []byte(serviceTestConfiguration), generation: 1,
		recovery: &workspace.Recovery{
			TransactionID: strings.Repeat("b", 32), WorkingDirectory: directory,
			ConfigurationPath: configurationPath, Phase: workspace.JournalReplacing,
			State: workspace.RecoveryAmbiguous, Files: []workspace.RecoveryFile{{
				Ordinal: 0, Role: workspace.RoleConfiguration, Path: configurationPath,
				State: workspace.RecoveryFileAmbiguous,
			}},
		},
	}
	service := newTestService(t, transactions, nil, 0x67)
	recovery, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	guardCalls := 0
	view, err := service.ResolveRecovery(
		context.Background(), recovery.Source.BaseRevisionToken, workspace.ResolutionAdoptCurrent,
		func(context.Context) error { guardCalls++; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if guardCalls != 1 || view.State == StateRecoveryRequired || transactions.recovery != nil {
		t.Fatalf("adopt-current result = guards %d, view %#v, recovery %#v", guardCalls, view, transactions.recovery)
	}
}

func TestResolveRecoveryAllowsExplicitAdoptFallbackForAppliedSet(t *testing.T) {
	directory := t.TempDir()
	configurationPath := filepath.Join(directory, "lego.yml")
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: configurationPath,
		configuration: []byte(serviceTestConfiguration), generation: 1,
		recovery: &workspace.Recovery{
			TransactionID: strings.Repeat("c", 32), WorkingDirectory: directory,
			ConfigurationPath: configurationPath, Phase: workspace.JournalFinalizing,
			State: workspace.RecoveryApplied, Files: []workspace.RecoveryFile{{
				Ordinal: 0, Role: workspace.RoleConfiguration, Path: configurationPath,
				State: workspace.RecoveryFileApplied,
			}},
		},
	}
	service := newTestService(t, transactions, nil, 0x68)
	recovery, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.ResolveRecovery(
		context.Background(), recovery.Source.BaseRevisionToken, workspace.ResolutionAdoptCurrent,
		allowServiceCommit,
	)
	if err != nil {
		t.Fatal(err)
	}
	if view.State == StateRecoveryRequired || transactions.recovery != nil {
		t.Fatalf("applied adopt-current result = %#v, recovery %#v", view, transactions.recovery)
	}
}

func TestSecretDotenvPreviewAndSaveNeverEchoValue(t *testing.T) {
	directory := t.TempDir()
	configuration := `accounts:
  home: {}
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: dns
`
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
		dotenv: []byte("CLOUDFLARE_DNS_API_TOKEN=old\nUNMANAGED=preserved\n"), generation: 1,
	}
	factory := secretTestEngineFactory(t)
	service := newTestService(t, transactions, factory, 0x77)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secret := "TASK06_SECRET_CANARY"
	changes := []nativeconfig.Change{{
		FieldID: "provider.api_token", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "dns"}},
		Operation: nativeconfig.OperationSet, Value: integrations.StringValue(secret),
	}}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.Summary) != 1 || !preview.Summary[0].Secret {
		t.Fatalf("secret preview = %#v", preview)
	}
	if _, present := preview.Summary[0].Before(); present {
		t.Fatal("secret summary exposed a before value")
	}
	if _, present := preview.Summary[0].After(); present {
		t.Fatal("secret summary exposed an after value")
	}
	if strings.Contains(preview.ReviewedPreviewToken, secret) || strings.Contains(preview.BaseRevisionToken, secret) {
		t.Fatal("review token exposed the submitted secret")
	}
	if _, err := service.Save(context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(transactions.dotenv, []byte(secret)) || !bytes.Contains(transactions.dotenv, []byte("UNMANAGED=preserved")) {
		t.Fatalf("dotenv replacement = %q", transactions.dotenv)
	}
}

func TestPreviewDoesNotRevealSecretEqualityAlongsideYAMLEdit(t *testing.T) {
	directory := t.TempDir()
	configuration := `accounts:
  home: {}
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: dns
`
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
		dotenv: []byte("CLOUDFLARE_DNS_API_TOKEN=same\n"), generation: 1,
	}
	service := newTestService(t, transactions, secretTestEngineFactory(t), 0x78)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	changes := []nativeconfig.Change{
		{
			FieldID: integrations.FieldWorkspaceStorage, Operation: nativeconfig.OperationSet,
			Value: integrations.StringValue("/srv/lego"),
		},
		{
			FieldID: "provider.api_token", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "dns"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("same"),
		},
	}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.Summary) != 2 ||
		preview.Summary[0].FieldID != integrations.FieldWorkspaceStorage ||
		preview.Summary[1].FieldID != "provider.api_token" || !preview.Summary[1].Secret {
		t.Fatalf("secret-equality-safe summary = %#v", preview.Summary)
	}
}

func TestPreviewSecretReplacementShapeDoesNotRevealEquality(t *testing.T) {
	directory := t.TempDir()
	configuration := `accounts:
  home: {}
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: dns
`
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
		dotenv: []byte("CLOUDFLARE_DNS_API_TOKEN=same\n"), generation: 1,
	}
	service := newTestService(t, transactions, secretTestEngineFactory(t), 0x7a)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	preview := func(value string) Preview {
		result, previewErr := service.Preview(context.Background(), view.Source.BaseRevisionToken, []nativeconfig.Change{{
			FieldID: "provider.api_token", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "dns"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue(value),
		}})
		if previewErr != nil {
			t.Fatal(previewErr)
		}
		return result
	}
	same := preview("same")
	different := preview("different")
	if same.State != PreviewReviewRequired || different.State != PreviewReviewRequired ||
		len(same.Summary) != 1 || len(different.Summary) != 1 ||
		same.Summary[0].FieldID != different.Summary[0].FieldID ||
		same.Summary[0].Action != different.Summary[0].Action ||
		!same.Summary[0].Secret || !different.Summary[0].Secret ||
		same.ResultingState != different.ResultingState || same.Execution != different.Execution {
		t.Fatalf("secret replacement shapes differ: same %#v, different %#v", same, different)
	}
}

func TestPreviewExpandsSharedDotenvImpactAcrossLogicalBindings(t *testing.T) {
	directory := t.TempDir()
	configuration := `accounts:
  home: {}
challenges:
  first:
    dns:
      provider: cloudflare
      envFile: credentials.env
  second:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: first
`
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
		dotenv: []byte("CLOUDFLARE_DNS_API_TOKEN=old\n"), generation: 1,
	}
	service := newTestService(t, transactions, secretTestEngineFactory(t), 0x72)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, []nativeconfig.Change{{
		FieldID: "provider.api_token", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "first"}},
		Operation: nativeconfig.OperationSet, Value: integrations.StringValue("new-secret"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.Summary) != 2 {
		t.Fatalf("shared dotenv preview = %#v", preview)
	}
	bindings := []string{preview.Summary[0].Bindings[0].Value, preview.Summary[1].Bindings[0].Value}
	slices.Sort(bindings)
	if !slices.Equal(bindings, []string{"first", "second"}) ||
		!preview.Summary[0].Secret || !preview.Summary[1].Secret {
		t.Fatalf("shared dotenv impacts = %#v", preview.Summary)
	}
}

func TestSnapshotBlocksExistingSecretsOutsideManifestRules(t *testing.T) {
	configuration := `accounts:
  home: {}
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: dns
`
	for _, test := range []struct {
		name  string
		value []byte
	}{
		{name: "empty", value: nil},
		{name: "field bound", value: bytes.Repeat([]byte{'x'}, 4097)},
		{name: "control", value: []byte("tab\tvalue")},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			encoded := append([]byte("CLOUDFLARE_DNS_API_TOKEN='"), test.value...)
			encoded = append(encoded, []byte("'\n")...)
			transactions := &fakeTransactions{
				workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
				dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
				dotenv: encoded, generation: 1,
			}
			service := newTestService(t, transactions, secretTestEngineFactory(t), 0x7b)
			view, err := service.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if view.State != StateUnsupported || !view.Editing || view.Execution {
				t.Fatalf("invalid secret state = %#v", view)
			}
			found := false
			for _, field := range view.Inspection.Projection {
				if field.FieldID != "provider.api_token" {
					continue
				}
				found = true
				if !field.Present || field.Configured {
					t.Fatalf("invalid secret projection = %#v", field)
				}
			}
			if !found {
				t.Fatal("invalid secret repair control is missing")
			}
		})
	}
}

func TestUnsupportedNativeCategoriesHaveStableDiagnostics(t *testing.T) {
	tests := map[string]DiagnosticCode{
		"/servers":                              CodeUnsupportedCA,
		"/servers/internal":                     CodeUnsupportedCA,
		"/challenges":                           CodeUnsupportedChallenge,
		"/challenges/home/dns/provider":         CodeUnsupportedProvider,
		"/hooks":                                CodeUnsupportedHooks,
		"/hooks/run":                            CodeUnsupportedHooks,
		"/log":                                  CodeUnsupportedOutput,
		"/certificates/home/pfx":                CodeUnsupportedOutput,
		"/certificates/home/pfx/exportPassword": CodeUnsupportedOutput,
		"/certificates/home/other":              CodeUnsupportedContent,
	}
	for path, want := range tests {
		if got := unsupportedDiagnosticCode(path); got != want {
			t.Errorf("unsupportedDiagnosticCode(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestPreviewAndSaveCreateNewReferencedDotenvWithSecret(t *testing.T) {
	directory := t.TempDir()
	configuration := `accounts:
  home: {}
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: credentials.env
certificates:
  gateway:
    domains: [gateway.home.example]
    account: home
    challenge: dns
`
	transactions := &fakeTransactions{
		workingDirectory: directory, configurationPath: filepath.Join(directory, "lego.yml"),
		dotenvPath: filepath.Join(directory, "credentials.env"), configuration: []byte(configuration),
		dotenv: []byte("CLOUDFLARE_DNS_API_TOKEN=old\n"), generation: 1,
	}
	service := newTestService(t, transactions, newDotenvFileTestEngineFactory(t), 0x79)
	view, err := service.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(directory, "created.env")
	changes := []nativeconfig.Change{
		{
			FieldID: "challenge.env_file", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "dns"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("created.env"),
		},
		{
			FieldID: "provider.api_token", Bindings: []nativeconfig.Binding{{ID: "challenge", Value: "dns"}},
			Operation: nativeconfig.OperationSet, Value: integrations.StringValue("new-secret"),
		},
	}
	preview, err := service.Preview(context.Background(), view.Source.BaseRevisionToken, changes)
	if err != nil {
		t.Fatal(err)
	}
	if preview.State != PreviewReviewRequired || len(preview.Summary) != 2 {
		t.Fatalf("new dotenv preview = %#v", preview)
	}
	updated, err := service.Save(context.Background(), view.Source.BaseRevisionToken, changes, preview.ReviewedPreviewToken, allowServiceCommit)
	if err != nil {
		t.Fatal(err)
	}
	if transactions.dotenvPath != created || !bytes.Contains(transactions.dotenv, []byte("new-secret")) ||
		!bytes.Contains(transactions.configuration, []byte("envFile: created.env")) || updated.State == StateInvalid {
		t.Fatalf("new dotenv save = path %q, dotenv %q, configuration %q, state %s", transactions.dotenvPath, transactions.dotenv, transactions.configuration, updated.State)
	}
}

func allowServiceCommit(context.Context) error { return nil }
