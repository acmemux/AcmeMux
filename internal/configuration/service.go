// Package configuration coordinates exact-runtime native configuration
// projection, preview, and journaled replacement.
package configuration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	acmeruntime "github.com/sgurden-certleap/AcmeMux/internal/runtime"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

var (
	ErrBusy           = errors.New("native configuration service is busy")
	ErrChanged        = errors.New("native configuration changed after review")
	ErrRuntimeChanged = errors.New("selected runtime changed")
	ErrInvalid        = errors.New("native configuration request is invalid")
	ErrUnavailable    = errors.New("native configuration service is unavailable")
)

type State string

const (
	StateReady            State = "ready"
	StateUnsupported      State = "unsupported"
	StateInvalid          State = "invalid"
	StateRecoveryRequired State = "recovery_required"
	StateCreationRequired State = "creation_required"
)

type PreviewState string

const (
	PreviewUnchanged      PreviewState = "unchanged"
	PreviewInvalid        PreviewState = "invalid"
	PreviewReviewRequired PreviewState = "review_required"
)

type Severity string

const (
	SeverityBlocking Severity = "blocking"
	SeverityNotice   Severity = "notice"
)

type DiagnosticRole string

const (
	RoleConfiguration DiagnosticRole = "configuration"
	RoleDotenv        DiagnosticRole = "dotenv"
	RoleSchema        DiagnosticRole = "schema"
	RoleSemantic      DiagnosticRole = "semantic"
	RoleFilesystem    DiagnosticRole = "filesystem"
	RoleRecovery      DiagnosticRole = "recovery"
)

type DiagnosticCode string

const (
	CodeUnsupportedCA             DiagnosticCode = "unsupported_ca"
	CodeUnsupportedProvider       DiagnosticCode = "unsupported_provider"
	CodeUnsupportedChallenge      DiagnosticCode = "unsupported_challenge"
	CodeUnsupportedHooks          DiagnosticCode = "unsupported_hooks"
	CodeUnsupportedOutput         DiagnosticCode = "unsupported_output"
	CodeUnsupportedContent        DiagnosticCode = "unsupported_content"
	CodeUnknownField              DiagnosticCode = "unknown_field"
	CodeYAMLAliasUnsupported      DiagnosticCode = "yaml_alias_unsupported"
	CodeYAMLMergeUnsupported      DiagnosticCode = "yaml_merge_unsupported"
	CodeYAMLTagUnsupported        DiagnosticCode = "yaml_tag_unsupported"
	CodeMultipleDocuments         DiagnosticCode = "multiple_documents"
	CodeDuplicateKey              DiagnosticCode = "duplicate_key"
	CodeInvalidUTF8               DiagnosticCode = "invalid_utf8"
	CodeDocumentEmpty             DiagnosticCode = "document_empty"
	CodeDocumentMalformed         DiagnosticCode = "document_malformed"
	CodeDocumentTooLarge          DiagnosticCode = "document_too_large"
	CodeDocumentTooComplex        DiagnosticCode = "document_too_complex"
	CodeDotenvMalformed           DiagnosticCode = "dotenv_malformed"
	CodeDotenvDuplicateKey        DiagnosticCode = "dotenv_duplicate_key"
	CodeDotenvKeyNotAllowed       DiagnosticCode = "dotenv_key_not_allowed"
	CodeDotenvExpansionNotAllowed DiagnosticCode = "dotenv_expansion_not_allowed"
	CodeSchemaValidationFailed    DiagnosticCode = "schema_validation_failed"
	CodeSemanticValidationFailed  DiagnosticCode = "semantic_validation_failed"
	CodeRuntimeManifestChanged    DiagnosticCode = "runtime_manifest_changed"
	CodeSourceChanged             DiagnosticCode = "source_changed"
	CodeUnsafePath                DiagnosticCode = "unsafe_path"
	CodeSynchronizationFailed     DiagnosticCode = "synchronization_failed"
	CodeReplacementInterrupted    DiagnosticCode = "replacement_interrupted"
	CodeRecoveryRequired          DiagnosticCode = "recovery_required"
)

// Diagnostic contains stable identifiers and native locations only. It never
// carries a source value, a credential value, or an upstream error string.
type Diagnostic struct {
	Code     DiagnosticCode
	Severity Severity
	Role     DiagnosticRole
	FieldID  integrations.FieldID
	Bindings []nativeconfig.Binding
	Path     string
	Line     int
	Column   int
}

type Source struct {
	BaseRevisionToken string
	ConfigurationPath string
	DotenvPaths       []string
	RuntimeManifestID compatibility.ManifestID
}

type View struct {
	State       State
	Source      Source
	Inspection  nativeconfig.Inspection
	Diagnostics []Diagnostic
	Editing     bool
	Execution   bool
	Recovery    *workspace.Recovery
}

type Preview struct {
	State                PreviewState
	BaseRevisionToken    string
	ReviewedPreviewToken string
	ResultingState       State
	BaseInspection       nativeconfig.Inspection
	Inspection           nativeconfig.Inspection
	Summary              []nativeconfig.ChangeSummary
	Diagnostics          []Diagnostic
	Execution            bool
}

// CreationRequest describes a missing native configuration target and the
// complete logical field changes used to synthesize it. An empty
// ConfigurationPath selects conventional .lego.yml creation.
type CreationRequest struct {
	WorkingDirectory  string
	ConfigurationPath string
	Changes           []nativeconfig.Change
}

type RuntimeSelections interface {
	Load(context.Context) (acmeruntime.Selection, error)
}

type RuntimeInspector interface {
	Verify(context.Context, acmeruntime.Observation) (acmeruntime.Observation, error)
}

type RuntimeClassifier func(acmeruntime.Observation) compatibility.Result

type LeaseCoordinator interface {
	TryAcquire(context.Context, workspace.Purpose) (*workspace.Lease, error)
}

type Transactions interface {
	Snapshot(context.Context, *workspace.Lease) (*workspace.SourceSet, error)
	AuditCandidate(context.Context, *workspace.Lease, *workspace.SourceSet, []byte, []workspace.Replacement) (workspace.CandidateAudit, error)
	Commit(context.Context, *workspace.Lease, workspace.CommitPlan, workspace.CommitGuard) (workspace.Selection, error)
	AuditBootstrap(context.Context, *workspace.Lease, workspace.BootstrapRequest, []byte, []workspace.Replacement) (workspace.BootstrapAudit, error)
	Bootstrap(context.Context, *workspace.Lease, workspace.BootstrapPlan, workspace.CommitGuard) (workspace.Selection, error)
	InspectRecovery(context.Context, *workspace.Lease) (workspace.Recovery, error)
	ResolveRecovery(context.Context, *workspace.Lease, workspace.RecoveryResolution, workspace.CommitGuard, workspace.RecoveryValidator) (workspace.RecoveryResult, error)
}

type EngineFactory func(compatibility.ManifestID) (*nativeconfig.Engine, integrations.Manifest, error)

type Dependencies struct {
	RuntimeSelections RuntimeSelections
	RuntimeInspector  RuntimeInspector
	Classify          RuntimeClassifier
	Coordinator       LeaseCoordinator
	Transactions      Transactions
	EngineFactory     EngineFactory
	Random            io.Reader
}

type Service struct {
	runtimeSelections RuntimeSelections
	runtimeInspector  RuntimeInspector
	classify          RuntimeClassifier
	coordinator       LeaseCoordinator
	transactions      Transactions
	engineFactory     EngineFactory
	tokenKey          []byte
}

func New(dependencies Dependencies) (*Service, error) {
	if dependencies.RuntimeSelections == nil || dependencies.RuntimeInspector == nil ||
		dependencies.Classify == nil || dependencies.Coordinator == nil || dependencies.Transactions == nil {
		return nil, errors.New("native configuration dependencies are required")
	}
	if dependencies.EngineFactory == nil {
		dependencies.EngineFactory = productionEngine
	}
	if dependencies.Random == nil {
		dependencies.Random = rand.Reader
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(dependencies.Random, key); err != nil {
		return nil, fmt.Errorf("initialize native configuration review tokens: %w", err)
	}
	return &Service{
		runtimeSelections: dependencies.RuntimeSelections,
		runtimeInspector:  dependencies.RuntimeInspector,
		classify:          dependencies.Classify,
		coordinator:       dependencies.Coordinator,
		transactions:      dependencies.Transactions,
		engineFactory:     dependencies.EngineFactory,
		tokenKey:          key,
	}, nil
}

func productionEngine(runtimeID compatibility.ManifestID) (*nativeconfig.Engine, integrations.Manifest, error) {
	manifest, ok := integrations.CoreManifest(runtimeID)
	if !ok {
		return nil, integrations.Manifest{}, fmt.Errorf("%w: runtime integration manifest", ErrUnavailable)
	}
	schema, err := compatibility.Schema(runtimeID)
	if err != nil {
		return nil, integrations.Manifest{}, fmt.Errorf("%w: runtime schema", ErrUnavailable)
	}
	defer clear(schema)
	engine, err := nativeconfig.NewEngine(runtimeID, schema, manifest, nativeconfig.DefaultLimits())
	if err != nil {
		return nil, integrations.Manifest{}, fmt.Errorf("%w: native configuration engine", ErrUnavailable)
	}
	return engine, manifest, nil
}

type runtimeContext struct {
	selection   acmeruntime.Selection
	observation acmeruntime.Observation
	manifestID  compatibility.ManifestID
	manifest    integrations.Manifest
	engine      *nativeconfig.Engine
	fingerprint string
}

func (service *Service) loadRuntime(ctx context.Context) (runtimeContext, error) {
	selection, err := service.runtimeSelections.Load(ctx)
	if err != nil {
		return runtimeContext{}, fmt.Errorf("%w: selected runtime", ErrUnavailable)
	}
	observation, err := service.runtimeInspector.Verify(ctx, selection.Observation)
	if err != nil {
		return runtimeContext{}, fmt.Errorf("%w: %w", ErrChanged, ErrRuntimeChanged)
	}
	decision := service.classify(observation)
	if !decision.Compatible() || string(decision.ManifestID) != selection.ManifestID {
		return runtimeContext{}, fmt.Errorf("%w: %w", ErrChanged, ErrRuntimeChanged)
	}
	engine, manifest, err := service.engineFactory(decision.ManifestID)
	if err != nil {
		return runtimeContext{}, err
	}
	return runtimeContext{
		selection: selection, observation: observation, manifestID: decision.ManifestID,
		manifest: manifest, engine: engine,
		fingerprint: acmeruntime.ReviewFingerprint(observation, selection.ManifestID),
	}, nil
}

func cloneDiagnostics(source []Diagnostic) []Diagnostic {
	result := slices.Clone(source)
	for index := range result {
		result[index].Bindings = slices.Clone(result[index].Bindings)
	}
	return result
}
