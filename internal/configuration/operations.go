package configuration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/sgurden-certleap/AcmeMux/internal/compatibility"
	"github.com/sgurden-certleap/AcmeMux/internal/integrations"
	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

type evaluation struct {
	view      View
	runtime   runtimeContext
	sources   *workspace.SourceSet
	documents *dotenvDocuments
}

func (evaluation *evaluation) close() {
	if evaluation == nil {
		return
	}
	if evaluation.documents != nil {
		evaluation.documents.close()
	}
	if evaluation.sources != nil {
		evaluation.sources.Close()
	}
}

type preparedCandidate struct {
	state        PreviewState
	resultState  State
	inspection   nativeconfig.Inspection
	diagnostics  []Diagnostic
	summary      []nativeconfig.ChangeSummary
	yaml         []byte
	replacements []workspace.Replacement
	token        string
	execution    bool
}

func (candidate *preparedCandidate) close() {
	if candidate == nil {
		return
	}
	clear(candidate.yaml)
	candidate.yaml = nil
	clearReplacements(candidate.replacements)
	candidate.replacements = nil
	clear(candidate.diagnostics)
	candidate.diagnostics = nil
	clear(candidate.summary)
	candidate.summary = nil
}

func (service *Service) Snapshot(ctx context.Context) (View, error) {
	lease, err := service.acquire(ctx, workspace.PurposeRead)
	if err != nil {
		return View{}, err
	}
	view, operationErr := service.snapshotLocked(ctx, lease)
	releaseErr := lease.Release()
	if operationErr != nil {
		return View{}, operationErr
	}
	if releaseErr != nil {
		return View{}, fmt.Errorf("%w: release native configuration read", ErrUnavailable)
	}
	return view, nil
}

func (service *Service) Preview(ctx context.Context, baseToken string, changes []nativeconfig.Change) (Preview, error) {
	lease, err := service.acquire(ctx, workspace.PurposePreview)
	if err != nil {
		return Preview{}, err
	}
	evaluated, operationErr := service.evaluateLocked(ctx, lease)
	if operationErr != nil {
		_ = lease.Release()
		return Preview{}, operationErr
	}
	defer evaluated.close()
	if !tokenMatches(evaluated.view.Source.BaseRevisionToken, baseToken) {
		_ = lease.Release()
		return Preview{}, ErrChanged
	}
	if !evaluated.view.Editing {
		preview := Preview{
			State: PreviewInvalid, BaseRevisionToken: evaluated.view.Source.BaseRevisionToken,
			ResultingState: evaluated.view.State, BaseInspection: evaluated.view.Inspection,
			Inspection:  evaluated.view.Inspection,
			Diagnostics: cloneDiagnostics(evaluated.view.Diagnostics), Execution: false,
		}
		if releaseErr := lease.Release(); releaseErr != nil {
			return Preview{}, fmt.Errorf("%w: release native configuration preview", ErrUnavailable)
		}
		return preview, nil
	}
	candidate, operationErr := service.prepareCandidate(ctx, lease, evaluated, changes)
	if operationErr != nil {
		_ = lease.Release()
		return Preview{}, operationErr
	}
	defer candidate.close()
	preview := Preview{
		State: candidate.state, BaseRevisionToken: evaluated.view.Source.BaseRevisionToken,
		ReviewedPreviewToken: candidate.token, ResultingState: candidate.resultState,
		BaseInspection: evaluated.view.Inspection, Inspection: candidate.inspection,
		Summary:     slices.Clone(candidate.summary),
		Diagnostics: cloneDiagnostics(candidate.diagnostics), Execution: candidate.execution,
	}
	if releaseErr := lease.Release(); releaseErr != nil {
		return Preview{}, fmt.Errorf("%w: release native configuration preview", ErrUnavailable)
	}
	return preview, nil
}

func (service *Service) Save(
	ctx context.Context,
	baseToken string,
	changes []nativeconfig.Change,
	reviewedPreviewToken string,
	guard workspace.CommitGuard,
) (View, error) {
	if guard == nil {
		return View{}, ErrInvalid
	}
	lease, err := service.acquire(ctx, workspace.PurposeSave)
	if err != nil {
		return View{}, err
	}
	evaluated, operationErr := service.evaluateLocked(ctx, lease)
	if operationErr != nil {
		_ = lease.Release()
		return View{}, operationErr
	}
	if !tokenMatches(evaluated.view.Source.BaseRevisionToken, baseToken) || !evaluated.view.Editing {
		evaluated.close()
		_ = lease.Release()
		return View{}, ErrChanged
	}
	candidate, operationErr := service.prepareCandidate(ctx, lease, evaluated, changes)
	if operationErr != nil {
		evaluated.close()
		_ = lease.Release()
		return View{}, operationErr
	}
	if candidate.state != PreviewReviewRequired || !tokenMatches(candidate.token, reviewedPreviewToken) {
		candidate.close()
		evaluated.close()
		_ = lease.Release()
		return View{}, ErrChanged
	}
	expectedRuntime := evaluated.runtime.fingerprint
	commitGuard := func(guardContext context.Context) error {
		if err := guard(guardContext); err != nil {
			return err
		}
		current, err := service.loadRuntime(guardContext)
		if err != nil || current.fingerprint != expectedRuntime {
			return ErrChanged
		}
		return nil
	}
	_, operationErr = service.transactions.Commit(ctx, lease, workspace.CommitPlan{
		Sources: evaluated.sources, CandidateConfiguration: candidate.yaml,
		Replacements: candidate.replacements,
	}, commitGuard)
	candidate.close()
	evaluated.close()
	if operationErr != nil {
		_ = lease.Release()
		return View{}, operationErr
	}
	view, operationErr := service.snapshotLocked(ctx, lease)
	releaseErr := lease.Release()
	if operationErr != nil {
		return View{}, operationErr
	}
	if releaseErr != nil {
		return View{}, fmt.Errorf("%w: release native configuration save", ErrUnavailable)
	}
	return view, nil
}

// ResolveRecovery either completes a freshly classified automatic outcome or
// explicitly adopts current applied/partial/ambiguous files after native
// validation. No staged file is ever replayed into an active path.
func (service *Service) ResolveRecovery(
	ctx context.Context,
	baseToken string,
	resolution workspace.RecoveryResolution,
	guard workspace.CommitGuard,
) (View, error) {
	if guard == nil || (resolution != workspace.ResolutionDiscardUnapplied &&
		resolution != workspace.ResolutionFinalizeApplied && resolution != workspace.ResolutionAdoptCurrent) {
		return View{}, ErrInvalid
	}
	lease, err := service.acquire(ctx, workspace.PurposeRecovery)
	if err != nil {
		return View{}, err
	}
	recovery, err := service.transactions.InspectRecovery(ctx, lease)
	if err != nil {
		_ = lease.Release()
		return View{}, fmt.Errorf("%w: inspect native edit recovery", ErrUnavailable)
	}
	runtime, err := service.loadRuntime(ctx)
	if err != nil {
		_ = lease.Release()
		return View{}, err
	}
	if !tokenMatches(service.recoveryToken(runtime.fingerprint, recovery), baseToken) {
		_ = lease.Release()
		return View{}, ErrChanged
	}
	expectedRuntime := runtime.fingerprint
	commitGuard := func(guardContext context.Context) error {
		if err := guard(guardContext); err != nil {
			return err
		}
		current, err := service.loadRuntime(guardContext)
		if err != nil || current.fingerprint != expectedRuntime {
			return ErrChanged
		}
		return nil
	}
	var validator workspace.RecoveryValidator
	if resolution == workspace.ResolutionFinalizeApplied || resolution == workspace.ResolutionAdoptCurrent {
		validator = func(_ context.Context, sources *workspace.SourceSet) error {
			var inspection nativeconfig.Inspection
			var inspectErr error
			if recovery.Bootstrap {
				inspection, inspectErr = runtime.engine.InspectCreation(sources.Configuration.Content)
			} else {
				inspection, inspectErr = runtime.engine.Inspect(sources.Configuration.Content)
			}
			if inspectErr != nil {
				return ErrInvalid
			}
			documents := loadDotenvDocuments(inspection, sources, false)
			defer documents.close()
			inspection = applyDotenvPresence(inspection, documents, false)
			state, editing, _ := configurationState(inspection, documents)
			if !editing || state == StateInvalid {
				return ErrInvalid
			}
			return nil
		}
	}
	_, operationErr := service.transactions.ResolveRecovery(ctx, lease, resolution, commitGuard, validator)
	if operationErr != nil {
		_ = lease.Release()
		switch {
		case errors.Is(operationErr, workspace.ErrSourceChanged), errors.Is(operationErr, workspace.ErrInvalidEdit):
			return View{}, ErrChanged
		case errors.Is(operationErr, ErrChanged), errors.Is(operationErr, ErrInvalid):
			return View{}, operationErr
		default:
			return View{}, fmt.Errorf("%w: resolve native edit recovery", ErrUnavailable)
		}
	}
	view, operationErr := service.snapshotLocked(ctx, lease)
	releaseErr := lease.Release()
	if operationErr != nil {
		return View{}, operationErr
	}
	if releaseErr != nil {
		return View{}, fmt.Errorf("%w: release native recovery", ErrUnavailable)
	}
	return view, nil
}

func (service *Service) acquire(ctx context.Context, purpose workspace.Purpose) (*workspace.Lease, error) {
	lease, err := service.coordinator.TryAcquire(ctx, purpose)
	if errors.Is(err, workspace.ErrWorkspaceBusy) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, fmt.Errorf("%w: acquire native workspace", ErrUnavailable)
	}
	return lease, nil
}

func (service *Service) snapshotLocked(ctx context.Context, lease *workspace.Lease) (View, error) {
	evaluated, err := service.evaluateLocked(ctx, lease)
	if err == nil {
		defer evaluated.close()
		return evaluated.view, nil
	}
	if errors.Is(err, workspace.ErrNoSelection) {
		runtime, runtimeErr := service.loadRuntime(ctx)
		if runtimeErr != nil {
			return View{}, runtimeErr
		}
		return View{
			State: StateCreationRequired,
			Source: Source{
				BaseRevisionToken: service.creationBaseToken(runtime), DotenvPaths: []string{},
				RuntimeManifestID: runtime.manifestID,
			},
			Diagnostics: []Diagnostic{},
		}, nil
	}
	if !errors.Is(err, workspace.ErrRecoveryRequired) {
		return View{}, err
	}
	recovery, recoveryErr := service.transactions.InspectRecovery(ctx, lease)
	if recoveryErr != nil {
		return View{}, fmt.Errorf("%w: inspect native edit recovery", ErrUnavailable)
	}
	runtime, runtimeErr := service.loadRuntime(ctx)
	if runtimeErr != nil {
		return View{}, runtimeErr
	}
	source := Source{
		BaseRevisionToken: service.recoveryToken(runtime.fingerprint, recovery),
		RuntimeManifestID: compatibilityManifestID(runtime.selection.ManifestID),
		ConfigurationPath: recovery.ConfigurationPath, DotenvPaths: []string{},
	}
	for _, file := range recovery.Files {
		switch file.Role {
		case workspace.RoleDotenv:
			source.DotenvPaths = append(source.DotenvPaths, file.Path)
		}
	}
	sort.Strings(source.DotenvPaths)
	source.DotenvPaths = slices.Compact(source.DotenvPaths)
	copyOfRecovery := recovery
	copyOfRecovery.Files = slices.Clone(recovery.Files)
	return View{
		State: StateRecoveryRequired, Source: source, Recovery: &copyOfRecovery,
		Diagnostics: []Diagnostic{{
			Code: CodeRecoveryRequired, Severity: SeverityBlocking, Role: RoleRecovery,
		}},
	}, nil
}

func compatibilityManifestID(value string) compatibility.ManifestID {
	return compatibility.ManifestID(value)
}

func (service *Service) evaluateLocked(ctx context.Context, lease *workspace.Lease) (*evaluation, error) {
	sources, err := service.transactions.Snapshot(ctx, lease)
	if err != nil {
		if errors.Is(err, workspace.ErrRecoveryRequired) {
			return nil, err
		}
		if errors.Is(err, workspace.ErrNoSelection) {
			return nil, err
		}
		if errors.Is(err, workspace.ErrSourceChanged) {
			return nil, ErrChanged
		}
		return nil, fmt.Errorf("%w: read native sources", ErrUnavailable)
	}
	result := &evaluation{sources: sources}
	complete := false
	defer func() {
		if !complete {
			result.close()
		}
	}()
	runtime, err := service.loadRuntime(ctx)
	if err != nil {
		return nil, err
	}
	result.runtime = runtime
	baseToken := service.sourceToken(runtime, sources)
	source := Source{
		BaseRevisionToken: baseToken, ConfigurationPath: sources.Configuration.Path,
		DotenvPaths: make([]string, len(sources.Dotenv)), RuntimeManifestID: runtime.manifestID,
	}
	for index := range sources.Dotenv {
		source.DotenvPaths[index] = sources.Dotenv[index].Path
	}
	sort.Strings(source.DotenvPaths)
	source.DotenvPaths = slices.Compact(source.DotenvPaths)

	inspection, inspectErr := runtime.engine.Inspect(sources.Configuration.Content)
	if inspectErr != nil {
		result.view = View{
			State: StateInvalid, Source: source, Diagnostics: []Diagnostic{diagnosticForNativeError(inspectErr)},
		}
		complete = true
		return result, nil
	}
	documents := loadDotenvDocuments(inspection, sources, false)
	result.documents = documents
	inspection = applyDotenvPresence(inspection, documents, false)
	diagnostics := diagnosticsForInspection(inspection)
	diagnostics = appendDiagnostics(diagnostics, documents.diagnostics...)
	state, editing, execution := configurationState(inspection, documents)
	result.view = View{
		State: state, Source: source, Inspection: inspection, Diagnostics: diagnostics,
		Editing: editing, Execution: execution,
	}
	complete = true
	return result, nil
}

func (service *Service) prepareCandidate(
	ctx context.Context,
	lease *workspace.Lease,
	evaluated *evaluation,
	changes []nativeconfig.Change,
) (*preparedCandidate, error) {
	candidate, err := evaluated.runtime.engine.Preview(evaluated.sources.Configuration.Content, changes)
	if err != nil {
		return nil, fmt.Errorf("%w: native configuration preview", ErrInvalid)
	}
	defer candidate.Clear()
	yamlCandidate := candidate.YAML()
	prepared := &preparedCandidate{yaml: yamlCandidate, summary: slices.Clone(candidate.Summary)}
	complete := false
	defer func() {
		if !complete {
			prepared.close()
		}
	}()
	documents, externalReplacements, externalImpacts, externalErr := applyExternalChanges(
		candidate.Inspection, evaluated.sources, candidate.ExternalChanges(),
	)
	if documents != nil {
		defer documents.close()
	}
	if externalErr != nil {
		prepared.state = PreviewInvalid
		prepared.resultState = StateInvalid
		if documents != nil {
			prepared.diagnostics = cloneDiagnostics(documents.diagnostics)
		}
		if len(prepared.diagnostics) == 0 {
			prepared.diagnostics = []Diagnostic{{
				Code: CodeDotenvMalformed, Severity: SeverityBlocking, Role: RoleDotenv,
			}}
		}
		complete = true
		return prepared, nil
	}
	prepared.summary = slices.DeleteFunc(prepared.summary, func(summary nativeconfig.ChangeSummary) bool {
		return summary.Target == integrations.TargetDotenv
	})
	prepared.summary = append(prepared.summary, externalImpacts...)
	prepared.replacements = externalReplacements
	if !bytes.Equal(yamlCandidate, evaluated.sources.Configuration.Content) {
		prepared.replacements = append([]workspace.Replacement{{
			Role: workspace.RoleConfiguration, Path: evaluated.sources.Configuration.Path,
			Content: slices.Clone(yamlCandidate),
		}}, prepared.replacements...)
	}
	if len(prepared.replacements) == 0 {
		prepared.state = PreviewUnchanged
		prepared.resultState = evaluated.view.State
		prepared.inspection = evaluated.view.Inspection
		prepared.diagnostics = cloneDiagnostics(evaluated.view.Diagnostics)
		prepared.summary = nil
		complete = true
		return prepared, nil
	}
	inspection := applyDotenvPresence(candidate.Inspection, documents, true)
	diagnostics := diagnosticsForInspection(inspection)
	diagnostics = appendDiagnostics(diagnostics, documents.diagnostics...)
	state, editing, execution := configurationState(inspection, documents)
	prepared.inspection = inspection
	prepared.resultState = state
	prepared.execution = execution
	prepared.diagnostics = diagnostics
	if !editing || state == StateInvalid {
		prepared.state = PreviewInvalid
		complete = true
		return prepared, nil
	}
	if _, err := service.transactions.AuditCandidate(ctx, lease, evaluated.sources, yamlCandidate, prepared.replacements); err != nil {
		prepared.state = PreviewInvalid
		prepared.resultState = StateInvalid
		prepared.execution = false
		prepared.diagnostics = appendBoundedDiagnostic(prepared.diagnostics, Diagnostic{
			Code: CodeUnsafePath, Severity: SeverityBlocking, Role: RoleFilesystem,
		})
		complete = true
		return prepared, nil
	}
	prepared.state = PreviewReviewRequired
	prepared.token = service.previewToken(evaluated.view.Source.BaseRevisionToken, changes, yamlCandidate, prepared.replacements)
	complete = true
	return prepared, nil
}

func configurationState(inspection nativeconfig.Inspection, documents *dotenvDocuments) (State, bool, bool) {
	if !inspection.SchemaValid || !inspection.SemanticValid || documents == nil || documents.invalid {
		return StateInvalid, false, false
	}
	unsupported := documents.unsupported
	constraint := false
	for _, issue := range inspection.Issues {
		if issue.Class == nativeconfig.IssueUnsupported || issue.Class == nativeconfig.IssueUnknown {
			unsupported = true
		}
		if issue.Class == nativeconfig.IssueConstraint {
			constraint = true
		}
	}
	state := StateReady
	if constraint {
		state = StateInvalid
	} else if unsupported {
		state = StateUnsupported
	}
	return state, inspection.Replaceable && !documents.invalid, inspection.Executable && !documents.invalid && !documents.unsupported
}

func diagnosticsForInspection(inspection nativeconfig.Inspection) []Diagnostic {
	result := make([]Diagnostic, 0, len(inspection.Issues))
	for _, issue := range inspection.Issues {
		diagnostic := Diagnostic{
			Severity: SeverityBlocking, Role: RoleConfiguration,
			Line: issue.Line, Column: issue.Column,
		}
		switch issue.Class {
		case nativeconfig.IssueSchema:
			diagnostic.Code = CodeSchemaValidationFailed
			diagnostic.Role = RoleSchema
		case nativeconfig.IssueSemantic:
			diagnostic.Code = CodeSemanticValidationFailed
			diagnostic.Role = RoleSemantic
		case nativeconfig.IssueConstraint:
			diagnostic.Code = CodeSemanticValidationFailed
			diagnostic.Role = RoleSemantic
		case nativeconfig.IssueUnknown:
			diagnostic.Code = CodeUnknownField
		case nativeconfig.IssueUnsupported:
			diagnostic.Code = unsupportedDiagnosticCode(issue.Path)
		}
		result = appendBoundedDiagnostic(result, diagnostic)
	}
	return result
}

func unsupportedDiagnosticCode(path string) DiagnosticCode {
	switch {
	case path == "/servers" || strings.HasPrefix(path, "/servers/"):
		return CodeUnsupportedCA
	case path == "/hooks" || strings.HasPrefix(path, "/hooks/"):
		return CodeUnsupportedHooks
	case path == "/log" || strings.HasPrefix(path, "/log/") || strings.Contains(path, "/pfx"):
		return CodeUnsupportedOutput
	case strings.Contains(path, "/provider"):
		return CodeUnsupportedProvider
	case path == "/challenges" || strings.HasPrefix(path, "/challenges/"):
		return CodeUnsupportedChallenge
	default:
		return CodeUnsupportedContent
	}
}

func diagnosticForNativeError(err error) Diagnostic {
	code := CodeDocumentMalformed
	switch nativeconfig.CodeOf(err) {
	case nativeconfig.ErrorSourceEmpty:
		code = CodeDocumentEmpty
	case nativeconfig.ErrorSourceTooLarge:
		code = CodeDocumentTooLarge
	case nativeconfig.ErrorInvalidUTF8:
		code = CodeInvalidUTF8
	case nativeconfig.ErrorMultipleDocuments:
		code = CodeMultipleDocuments
	case nativeconfig.ErrorStructureComplex:
		code = CodeDocumentTooComplex
	case nativeconfig.ErrorAliasUnsupported:
		code = CodeYAMLAliasUnsupported
	case nativeconfig.ErrorMergeUnsupported:
		code = CodeYAMLMergeUnsupported
	case nativeconfig.ErrorTagUnsupported:
		code = CodeYAMLTagUnsupported
	case nativeconfig.ErrorDuplicateKey:
		code = CodeDuplicateKey
	}
	return Diagnostic{Code: code, Severity: SeverityBlocking, Role: RoleConfiguration}
}

func appendDiagnostics(destination []Diagnostic, source ...Diagnostic) []Diagnostic {
	for _, diagnostic := range source {
		destination = appendBoundedDiagnostic(destination, diagnostic)
	}
	return destination
}
