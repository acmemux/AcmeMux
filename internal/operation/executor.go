package operation

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sgurden-certleap/AcmeMux/internal/broker"
	"github.com/sgurden-certleap/AcmeMux/internal/configuration"
	"github.com/sgurden-certleap/AcmeMux/internal/inventory"
	"github.com/sgurden-certleap/AcmeMux/internal/jobs"
	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

const maximumPersistedOutput = 256 << 10

type executor struct {
	coordinator         Coordinator
	configuration       Configuration
	workspaceSelections WorkspaceSelections
	workspaceInspector  WorkspaceInspector
	prepareRuntime      RuntimePreparer
	broker              BrokerRunner
	inventory           InventoryReader
}

func (executor *executor) Execute(ctx context.Context, _ string, request jobs.Request, report jobs.PhaseReporter) jobs.Result {
	reviewedCertificates := requestedCertificates(request)
	lease, err := executor.coordinator.TryAcquire(ctx, workspace.PurposeManualRun)
	if err != nil {
		_ = report(jobs.PhaseRefreshingInventory)
		code := "workspace_unavailable"
		if errors.Is(err, workspace.ErrWorkspaceBusy) {
			code = "workspace_busy"
		}
		return jobs.Result{
			State: jobs.StateNotAttempted, Code: code,
			Inventory: jobs.InventoryResult{State: jobs.InventoryUnavailable, Code: code},
			Items:     itemResults(reviewedCertificates, jobs.ItemNotAttempted, code),
		}
	}
	defer func() { _ = lease.Release() }()

	plan, planErr := executor.configuration.PrepareExecution(ctx, lease)
	if planErr != nil {
		code := executionPreparationCode(planErr)
		return executor.finishWithoutRun(ctx, report, lease, "", reviewedCertificates, code)
	}
	defer func() { plan.Close() }()
	certificates := slices.Clone(plan.Intent.Certificates)
	for index := range certificates {
		certificates[index].Domains = slices.Clone(certificates[index].Domains)
	}
	storagePath := plan.Intent.StoragePath
	if request.ReviewedEvidenceSHA256 != plan.ReviewedEvidenceSHA256 {
		plan.Close()
		return executor.finishWithoutRun(ctx, report, lease, storagePath, reviewedCertificates, "reviewed_source_changed")
	}

	beforeInventory, beforeResult := executor.refreshInventory(ctx, lease, storagePath)
	if beforeResult.State != jobs.InventoryRefreshed {
		plan.Close()
		code := beforeResult.Code
		if code == "" {
			code = "inventory_preflight_failed"
		}
		return executor.finishWithoutRun(ctx, report, lease, storagePath, certificates, code)
	}
	confirmation, confirmationErr := executor.configuration.PrepareExecution(ctx, lease)
	if confirmationErr != nil {
		if confirmation != nil {
			confirmation.Close()
		}
		plan.Close()
		return executor.finishWithoutRun(ctx, report, lease, storagePath, certificates, executionPreparationCode(confirmationErr))
	}
	if confirmation.ReviewedEvidenceSHA256 != plan.ReviewedEvidenceSHA256 {
		confirmation.Close()
		plan.Close()
		return executor.finishWithoutRun(ctx, report, lease, storagePath, certificates, "reviewed_source_changed")
	}
	plan.Close()
	plan = confirmation

	prepared, prepareErr := executor.prepareRuntime(ctx)
	if prepareErr != nil || prepared == nil {
		plan.Close()
		return executor.finishWithoutRun(ctx, report, lease, storagePath, certificates, "runtime_incompatible")
	}
	preparedOwned := true
	defer func() {
		if preparedOwned {
			_ = prepared.Close()
		}
	}()
	if err := report(jobs.PhaseExecuting); err != nil {
		plan.Close()
		return jobs.Result{
			State: jobs.StateAmbiguous, Code: "phase_persistence_failed",
			Inventory: jobs.InventoryResult{State: jobs.InventoryUnavailable, Code: "phase_persistence_failed"},
			Items:     itemResults(certificates, jobs.ItemNotAttempted, "phase_persistence_failed"),
		}
	}
	preparedOwned = false
	environment := make([]broker.Variable, len(plan.Environment))
	for index := range plan.Environment {
		environment[index] = broker.Variable{Name: plan.Environment[index].Name, Value: plan.Environment[index].Value, Sensitive: plan.Environment[index].Sensitive}
	}
	brokerResult, brokerErr := executor.broker.Run(ctx, broker.Request{
		Prepared: prepared, WorkingDirectory: plan.Intent.WorkingDirectory,
		ConfigurationPath: plan.Intent.ConfigurationPath, Environment: environment, ObservedSecrets: plan.ObservedSecrets,
	})
	for index := range environment {
		environment[index].Value = nil
	}
	plan.Close()
	phaseErr := report(jobs.PhaseRefreshingInventory)
	afterInventory, inventoryResult := executor.refreshInventory(ctx, lease, storagePath)
	postPlan, postErr := executor.configuration.PrepareExecution(ctx, lease)
	postChangeCode := ""
	if postErr != nil {
		switch {
		case errors.Is(postErr, configuration.ErrRuntimeChanged):
			postChangeCode = "runtime_changed_after_run"
		case errors.Is(postErr, configuration.ErrInvalid):
			postChangeCode = "configuration_changed_after_run"
		default:
			postChangeCode = "workspace_changed_after_run"
		}
	} else if postPlan == nil || postPlan.ReviewedEvidenceSHA256 != request.ReviewedEvidenceSHA256 {
		postChangeCode = "workspace_changed_after_run"
	}
	if postPlan != nil {
		postPlan.Close()
	}
	classified := classifyExecution(
		brokerResult, brokerErr, certificates, beforeInventory, afterInventory,
		inventoryResult, postChangeCode,
	)
	if phaseErr != nil {
		classified.State = jobs.StateAmbiguous
		classified.Code = "phase_persistence_failed"
		classified.MayHaveChanged = brokerResult.Started || brokerResult.MayHaveChanged
		for index := range classified.Items {
			if classified.Items[index].State != jobs.ItemCompleted {
				classified.Items[index].State = jobs.ItemAmbiguous
				classified.Items[index].Code = "phase_persistence_failed"
			}
		}
	}
	return classified
}

func (executor *executor) Reconcile(ctx context.Context, _ string) jobs.InventoryResult {
	lease, err := executor.coordinator.Acquire(ctx, workspace.PurposeManualRun)
	if err != nil {
		code := "workspace_unavailable"
		if errors.Is(err, workspace.ErrWorkspaceBusy) {
			code = "workspace_busy"
		}
		return jobs.InventoryResult{State: jobs.InventoryUnavailable, Code: code}
	}
	defer func() { _ = lease.Release() }()
	_, result := executor.refreshInventory(ctx, lease, "")
	return result
}

func (executor *executor) finishWithoutRun(
	ctx context.Context,
	report jobs.PhaseReporter,
	lease *workspace.Lease,
	storagePath string,
	certificates []configuration.ExecutionCertificate,
	code string,
) jobs.Result {
	if err := report(jobs.PhaseRefreshingInventory); err != nil {
		code = "phase_persistence_failed"
	}
	_, result := executor.refreshInventory(ctx, lease, storagePath)
	state := jobs.StateNotAttempted
	if code == "runtime_incompatible" || code == "configuration_incompatible" {
		state = jobs.StateIncompatible
	}
	return jobs.Result{
		State: state, Code: code, Inventory: result,
		Items: itemResults(certificates, jobs.ItemNotAttempted, code),
	}
}

func (executor *executor) refreshInventory(
	ctx context.Context,
	lease *workspace.Lease,
	storagePath string,
) ([]inventory.Certificate, jobs.InventoryResult) {
	selection, err := executor.workspaceSelections.Load(ctx)
	if err != nil {
		return nil, unavailableInventory("workspace_selection_unavailable")
	}
	current, err := executor.workspaceInspector.Verify(ctx, selection.Review)
	if err != nil {
		return nil, unavailableInventory("workspace_changed")
	}
	if storagePath == "" {
		storagePath = current.Storage.Path
	} else if current.Storage.Path != storagePath {
		return nil, unavailableInventory("workspace_changed")
	}
	prepared, err := executor.prepareRuntime(ctx)
	if err != nil || prepared == nil {
		return nil, unavailableInventory("runtime_incompatible")
	}
	certificates, err := executor.inventory.Read(ctx, prepared, storagePath)
	if err != nil {
		code := string(inventory.CodeOf(err))
		if code == "" || len(code) > 54 {
			code = "inventory_unavailable"
		} else {
			code = "inventory_" + code
		}
		return nil, unavailableInventory(code)
	}
	if _, err := executor.workspaceInspector.Verify(ctx, current); err != nil {
		return nil, unavailableInventory("workspace_changed")
	}
	count := len(certificates)
	return certificates, jobs.InventoryResult{
		State: jobs.InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
	}
}

func unavailableInventory(code string) jobs.InventoryResult {
	return jobs.InventoryResult{State: jobs.InventoryUnavailable, Code: code}
}

func executionPreparationCode(err error) string {
	switch {
	case errors.Is(err, configuration.ErrRuntimeChanged):
		return "runtime_incompatible"
	case errors.Is(err, workspace.ErrRecoveryRequired):
		return "recovery_required"
	case errors.Is(err, workspace.ErrNoSelection):
		return "workspace_unselected"
	case errors.Is(err, workspace.ErrSourceChanged), errors.Is(err, configuration.ErrChanged):
		return "workspace_changed"
	case errors.Is(err, configuration.ErrInvalid):
		return "configuration_incompatible"
	default:
		return "preflight_unavailable"
	}
}

func requestedCertificates(request jobs.Request) []configuration.ExecutionCertificate {
	result := make([]configuration.ExecutionCertificate, len(request.Items))
	for index, name := range request.Items {
		result[index].Name = name
	}
	return result
}

func itemResults(certificates []configuration.ExecutionCertificate, state jobs.ItemState, code string) []jobs.ItemResult {
	result := make([]jobs.ItemResult, len(certificates))
	for index, certificate := range certificates {
		result[index] = jobs.ItemResult{Name: certificate.Name, State: state, Code: code}
	}
	return result
}

func classifyExecution(
	result broker.Result,
	runErr error,
	certificates []configuration.ExecutionCertificate,
	before []inventory.Certificate,
	after []inventory.Certificate,
	inventoryResult jobs.InventoryResult,
	postChangeCode string,
) jobs.Result {
	output, truncated := operationOutput(result)
	changed := changedCertificateNames(before, after)
	if runErr != nil {
		state := jobs.StateNotAttempted
		itemState := jobs.ItemNotAttempted
		mayHaveChanged := result.Started || result.MayHaveChanged
		if mayHaveChanged {
			state = jobs.StateAmbiguous
			itemState = jobs.ItemAmbiguous
		}
		items := itemResults(certificates, itemState, brokerFailureCode(runErr))
		if mayHaveChanged && inventoryResult.State == jobs.InventoryRefreshed {
			for index, certificate := range certificates {
				if changed[certificate.Name] {
					items[index].State = jobs.ItemCompleted
					items[index].Code = "native_artifact_changed"
				}
			}
		}
		return jobs.Result{
			State: state, Code: brokerFailureCode(runErr), MayHaveChanged: mayHaveChanged,
			Inventory: inventoryResult, Output: output, OutputTruncated: truncated,
			Items: items,
		}
	}
	failedRenewal := failedRenewalCertificate(result, certificates, changed, inventoryResult)
	items := make([]jobs.ItemResult, 0, len(certificates))
	completed := 0
	for _, certificate := range certificates {
		state, code := jobs.ItemAmbiguous, "execution_outcome_ambiguous"
		if result.Outcome == broker.OutcomeSucceeded {
			state, code = jobs.ItemCompleted, "evaluated"
			completed++
		} else if changed[certificate.Name] {
			state, code = jobs.ItemCompleted, "native_artifact_changed"
			completed++
		} else if certificate.Name == failedRenewal {
			state, code = jobs.ItemFailed, "upstream_renewal_failed"
		}
		items = append(items, jobs.ItemResult{Name: certificate.Name, State: state, Code: code})
	}
	state, code := jobs.StateFailed, "execution_failed"
	switch result.Outcome {
	case broker.OutcomeSucceeded:
		state, code = jobs.StateSucceeded, "execution_succeeded"
	case broker.OutcomeFailed:
		if completed > 0 && completed < len(items) {
			state, code = jobs.StatePartial, "execution_partial"
		}
	case broker.OutcomeTimedOut:
		state, code = jobs.StateTimedOut, "execution_timed_out"
	case broker.OutcomeInterrupted:
		state, code = jobs.StateInterrupted, "execution_interrupted"
	case broker.OutcomeOutputLimit:
		state, code = jobs.StateAmbiguous, "execution_output_limit"
	case broker.OutcomeAmbiguous:
		state, code = jobs.StateAmbiguous, "execution_ambiguous"
	}
	if postChangeCode != "" {
		state, code = jobs.StateAmbiguous, postChangeCode
		for index := range items {
			if items[index].State != jobs.ItemCompleted {
				items[index].State = jobs.ItemAmbiguous
				items[index].Code = postChangeCode
			}
		}
	}
	return jobs.Result{
		State: state, Code: code, MayHaveChanged: result.MayHaveChanged,
		Inventory: inventoryResult, Output: output, OutputTruncated: truncated, Items: items,
	}
}

// failedRenewalCertificate recognizes only the exact supported-upstream
// renewal-attempt marker, which includes the native certificate ID before the
// ACME request. Fresh-obtain failures lack an ID and remain ambiguous. A
// changed artifact always wins as completed, and missing/truncated inventory
// or output evidence disables this refinement.
func failedRenewalCertificate(
	result broker.Result,
	certificates []configuration.ExecutionCertificate,
	changed map[string]bool,
	inventoryResult jobs.InventoryResult,
) string {
	if result.Outcome != broker.OutcomeFailed || result.OutputDiscarded ||
		inventoryResult.State != jobs.InventoryRefreshed {
		return ""
	}
	known := make(map[string]struct{}, len(certificates))
	for _, certificate := range certificates {
		if !changed[certificate.Name] {
			known[certificate.Name] = struct{}{}
		}
	}
	var failed string
	for _, line := range strings.Split(result.Stdout+"\n"+result.Stderr, "\n") {
		name, ok := parseRenewalAttempt(line)
		if !ok {
			continue
		}
		if _, exists := known[name]; exists {
			failed = name
		}
	}
	return failed
}

// parseRenewalAttempt accepts only the selected upstream default logger's
// structured INFO record. Remote ACME problem text is rendered as a quoted
// error attribute on an ERR record and must never become certificate evidence.
func parseRenewalAttempt(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) != 6 || fields[1] != "INF" || fields[2] != "Trying" || fields[3] != "renewal." ||
		!strings.HasPrefix(fields[4], "cert-name=") || !strings.HasPrefix(fields[5], "time-remaining=") {
		return "", false
	}
	if _, err := time.Parse(time.RFC3339Nano, fields[0]); err != nil {
		return "", false
	}
	if _, err := time.ParseDuration(strings.TrimPrefix(fields[5], "time-remaining=")); err != nil {
		return "", false
	}
	name := strings.TrimPrefix(fields[4], "cert-name=")
	if name == "" {
		return "", false
	}
	return name, true
}

func brokerFailureCode(err error) string {
	code := broker.CodeOf(err)
	if code == "" {
		return "broker_unavailable"
	}
	return "broker_" + string(code)
}

func changedCertificateNames(before, after []inventory.Certificate) map[string]bool {
	previous := make(map[string]inventory.Certificate, len(before))
	for _, certificate := range before {
		previous[certificate.Name] = certificate
	}
	result := make(map[string]bool)
	for _, certificate := range after {
		prior, found := previous[certificate.Name]
		if !found || !sameCertificate(prior, certificate) {
			result[certificate.Name] = true
		}
	}
	return result
}

func sameCertificate(left, right inventory.Certificate) bool {
	return left.Name == right.Name && slices.Equal(left.DNSNames, right.DNSNames) &&
		left.Issuer == right.Issuer && left.ExpiresAt.Equal(right.ExpiresAt) &&
		left.NativePath == right.NativePath && left.Artifact == right.Artifact
}

func operationOutput(result broker.Result) (string, bool) {
	if result.OutputDiscarded {
		return "", true
	}
	var builder strings.Builder
	if result.Stdout != "" {
		builder.WriteString("[stdout]\n")
		builder.WriteString(result.Stdout)
	}
	if result.Stderr != "" {
		if builder.Len() != 0 && !strings.HasSuffix(builder.String(), "\n") {
			builder.WriteByte('\n')
		}
		builder.WriteString("[stderr]\n")
		builder.WriteString(result.Stderr)
	}
	value := builder.String()
	if len(value) <= maximumPersistedOutput {
		return value, false
	}
	value = value[:maximumPersistedOutput]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value, true
}
