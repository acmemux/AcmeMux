package configuration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/sgurden-certleap/AcmeMux/internal/nativeconfig"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

var emptyCreationYAML = []byte("{}\n")

type preparedCreation struct {
	candidate      *preparedCandidate
	baseInspection nativeconfig.Inspection
	audit          workspace.BootstrapAudit
}

func (prepared *preparedCreation) close() {
	if prepared != nil && prepared.candidate != nil {
		prepared.candidate.close()
	}
}

// PreviewCreation synthesizes and audits a complete native YAML candidate
// while proving that every active target is still absent.
func (service *Service) PreviewCreation(ctx context.Context, baseToken string, request CreationRequest) (Preview, error) {
	lease, err := service.acquire(ctx, workspace.PurposePreview)
	if err != nil {
		return Preview{}, err
	}
	runtime, currentToken, operationErr := service.creationRuntimeLocked(ctx, lease)
	if operationErr != nil {
		_ = lease.Release()
		return Preview{}, operationErr
	}
	if !tokenMatches(currentToken, baseToken) {
		_ = lease.Release()
		return Preview{}, ErrChanged
	}
	prepared, operationErr := service.prepareCreation(ctx, lease, runtime, currentToken, request)
	if operationErr != nil {
		_ = lease.Release()
		return Preview{}, operationErr
	}
	defer prepared.close()
	preview := Preview{
		State: prepared.candidate.state, BaseRevisionToken: currentToken,
		ReviewedPreviewToken: prepared.candidate.token, ResultingState: prepared.candidate.resultState,
		BaseInspection: prepared.baseInspection, Inspection: prepared.candidate.inspection,
		Summary:     slices.Clone(prepared.candidate.summary),
		Diagnostics: cloneDiagnostics(prepared.candidate.diagnostics), Execution: prepared.candidate.execution,
	}
	if releaseErr := lease.Release(); releaseErr != nil {
		return Preview{}, fmt.Errorf("%w: release native configuration creation preview", ErrUnavailable)
	}
	return preview, nil
}

// Create replays the exact logical request, source/runtime review, and
// no-follow filesystem audit before activating the reviewed candidate.
func (service *Service) Create(
	ctx context.Context,
	baseToken string,
	request CreationRequest,
	reviewedPreviewToken string,
	guard workspace.CommitGuard,
) (View, error) {
	if guard == nil {
		return View{}, ErrInvalid
	}
	lease, err := service.acquire(ctx, workspace.PurposeBootstrap)
	if err != nil {
		return View{}, err
	}
	runtime, currentToken, operationErr := service.creationRuntimeLocked(ctx, lease)
	if operationErr != nil {
		_ = lease.Release()
		return View{}, operationErr
	}
	if !tokenMatches(currentToken, baseToken) {
		_ = lease.Release()
		return View{}, ErrChanged
	}
	prepared, operationErr := service.prepareCreation(ctx, lease, runtime, currentToken, request)
	if operationErr != nil {
		_ = lease.Release()
		return View{}, operationErr
	}
	if prepared.candidate.state != PreviewReviewRequired ||
		!tokenMatches(prepared.candidate.token, reviewedPreviewToken) {
		prepared.close()
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
	_, operationErr = service.transactions.Bootstrap(ctx, lease, workspace.BootstrapPlan{
		Request: workspace.BootstrapRequest{
			WorkingDirectory: request.WorkingDirectory, ConfigurationPath: request.ConfigurationPath,
		},
		CandidateConfiguration: prepared.candidate.yaml,
		Replacements:           prepared.candidate.replacements,
	}, commitGuard)
	prepared.close()
	if operationErr != nil {
		_ = lease.Release()
		switch {
		case errors.Is(operationErr, workspace.ErrSourceChanged), errors.Is(operationErr, workspace.ErrInvalidEdit):
			return View{}, ErrChanged
		case errors.Is(operationErr, ErrChanged), errors.Is(operationErr, ErrInvalid):
			return View{}, operationErr
		default:
			return View{}, fmt.Errorf("%w: create native configuration", ErrUnavailable)
		}
	}
	view, operationErr := service.snapshotLocked(ctx, lease)
	releaseErr := lease.Release()
	if operationErr != nil {
		return View{}, operationErr
	}
	if releaseErr != nil {
		return View{}, fmt.Errorf("%w: release native configuration creation", ErrUnavailable)
	}
	return view, nil
}

func (service *Service) creationRuntimeLocked(ctx context.Context, lease *workspace.Lease) (runtimeContext, string, error) {
	sources, err := service.transactions.Snapshot(ctx, lease)
	if err == nil {
		sources.Close()
		return runtimeContext{}, "", ErrChanged
	}
	if !errors.Is(err, workspace.ErrNoSelection) {
		if errors.Is(err, workspace.ErrRecoveryRequired) || errors.Is(err, workspace.ErrSourceChanged) {
			return runtimeContext{}, "", ErrChanged
		}
		return runtimeContext{}, "", fmt.Errorf("%w: inspect native creation state", ErrUnavailable)
	}
	runtime, err := service.loadRuntime(ctx)
	if err != nil {
		return runtimeContext{}, "", err
	}
	return runtime, service.creationBaseToken(runtime), nil
}

func (service *Service) prepareCreation(
	ctx context.Context,
	lease *workspace.Lease,
	runtime runtimeContext,
	baseToken string,
	request CreationRequest,
) (*preparedCreation, error) {
	baseInspection, err := runtime.engine.Inspect(emptyCreationYAML)
	if err != nil {
		return nil, fmt.Errorf("%w: initialize native creation candidate", ErrUnavailable)
	}
	candidate, err := runtime.engine.Preview(emptyCreationYAML, request.Changes)
	if err != nil {
		return nil, fmt.Errorf("%w: native configuration creation preview", ErrInvalid)
	}
	defer candidate.Clear()
	if len(candidate.ExternalChanges()) != 0 {
		return nil, fmt.Errorf("%w: native creation cannot introduce external credential files", ErrInvalid)
	}
	prepared := &preparedCreation{
		candidate: &preparedCandidate{
			yaml: candidate.YAML(), summary: slices.Clone(candidate.Summary),
		},
		baseInspection: baseInspection,
	}
	complete := false
	defer func() {
		if !complete {
			prepared.close()
		}
	}()
	inspection, err := runtime.engine.InspectCreation(prepared.candidate.yaml)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect native creation candidate", ErrInvalid)
	}
	documents := &dotenvDocuments{byPath: make(map[string]*dotenvDocument)}
	state, editing, execution := configurationState(inspection, documents)
	prepared.candidate.inspection = inspection
	prepared.candidate.resultState = state
	prepared.candidate.execution = execution
	prepared.candidate.diagnostics = diagnosticsForInspection(inspection)
	if !editing || state == StateInvalid {
		prepared.candidate.state = PreviewInvalid
		complete = true
		return prepared, nil
	}
	configurationPath := request.ConfigurationPath
	if configurationPath == "" {
		configurationPath = filepath.Join(request.WorkingDirectory, ".lego.yml")
	}
	prepared.candidate.replacements = []workspace.Replacement{{
		Role: workspace.RoleConfiguration, Path: configurationPath,
		Content: slices.Clone(prepared.candidate.yaml),
	}}
	audit, err := service.transactions.AuditBootstrap(ctx, lease, workspace.BootstrapRequest{
		WorkingDirectory: request.WorkingDirectory, ConfigurationPath: request.ConfigurationPath,
	}, prepared.candidate.yaml, prepared.candidate.replacements)
	if err != nil {
		prepared.candidate.state = PreviewInvalid
		prepared.candidate.resultState = StateInvalid
		prepared.candidate.execution = false
		prepared.candidate.diagnostics = appendBoundedDiagnostic(prepared.candidate.diagnostics, Diagnostic{
			Code: CodeUnsafePath, Severity: SeverityBlocking, Role: RoleFilesystem,
		})
		complete = true
		return prepared, nil
	}
	prepared.audit = audit
	prepared.candidate.state = PreviewReviewRequired
	prepared.candidate.token = service.creationPreviewToken(
		baseToken, request, prepared.candidate.yaml, prepared.candidate.replacements, audit,
	)
	if bytes.Equal(prepared.candidate.yaml, emptyCreationYAML) {
		prepared.candidate.state = PreviewInvalid
		prepared.candidate.token = ""
	}
	complete = true
	return prepared, nil
}
