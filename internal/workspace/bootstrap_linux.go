//go:build linux

package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

// AuditBootstrap proves that a missing configuration and every candidate
// reference can be created without weakening the adopted workspace policy.
func (manager *TransactionManager) AuditBootstrap(
	ctx context.Context,
	lease *Lease,
	request BootstrapRequest,
	candidateConfiguration []byte,
	replacements []Replacement,
) (BootstrapAudit, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return BootstrapAudit{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	return manager.auditBootstrap(ctx, request, candidateConfiguration, replacements, false)
}

func (manager *TransactionManager) auditBootstrap(
	ctx context.Context,
	request BootstrapRequest,
	candidateConfiguration []byte,
	replacements []Replacement,
	journalExpected bool,
) (BootstrapAudit, error) {
	if _, err := manager.selections.Load(ctx); err == nil {
		return BootstrapAudit{}, fmt.Errorf("%w: a workspace is already selected", ErrSourceChanged)
	} else if !errors.Is(err, ErrNoSelection) {
		return BootstrapAudit{}, err
	}
	if _, err := manager.journal.Load(ctx); err == nil && !journalExpected {
		return BootstrapAudit{}, ErrRecoveryRequired
	} else if err != nil && !errors.Is(err, ErrNoEditJournal) {
		return BootstrapAudit{}, fmt.Errorf("inspect native bootstrap journal: %w", err)
	} else if journalExpected && errors.Is(err, ErrNoEditJournal) {
		return BootstrapAudit{}, fmt.Errorf("%w: native bootstrap journal disappeared", ErrSourceChanged)
	}
	if err := validateSelectedPath(request.WorkingDirectory); err != nil {
		return BootstrapAudit{}, err
	}
	if request.ConfigurationPath != "" {
		if err := validateSelectedPath(request.ConfigurationPath); err != nil {
			return BootstrapAudit{}, err
		}
	}
	if len(candidateConfiguration) == 0 || int64(len(candidateConfiguration)) > manager.inspector.policy.MaxConfigurationBytes {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap candidate size is invalid", ErrInvalidEdit)
	}

	workingRequirements := pathRequirements{expected: PathTypeDirectory, requireRead: true, requireSearch: true}
	working := auditPath(ctx, request.WorkingDirectory, RoleWorkingDirectory, "", workingRequirements, manager.inspector.policy)
	if !working.evidence.Safe || hasBlockingDiagnostics(working.diagnostics) {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap working directory is unsafe", ErrInvalidEdit)
	}
	workingConfirmation := auditPath(ctx, request.WorkingDirectory, RoleWorkingDirectory, "", workingRequirements, manager.inspector.policy)
	if !workingConfirmation.evidence.Safe || !samePathPlacementEvidence(working.evidence, workingConfirmation.evidence) {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap working directory changed", ErrSourceChanged)
	}

	configurationPath := request.ConfigurationPath
	source := ConfigurationExplicit
	alternateConfiguration := CandidatePath{}
	if configurationPath == "" {
		source = ConfigurationConventionalYML
		configurationPath = filepath.Join(request.WorkingDirectory, ".lego.yml")
		alternate := filepath.Join(request.WorkingDirectory, ".lego.yaml")
		missing, _, alternateErr := manager.auditMissingTarget(ctx, alternate, RoleConfiguration, "")
		if alternateErr != nil || missing.Evidence.Type != PathTypeMissing {
			return BootstrapAudit{}, fmt.Errorf("%w: conventional configuration precedence changed", ErrSourceChanged)
		}
		alternateConfiguration = missing
	}
	configuration, configurationParent, err := manager.auditMissingTarget(ctx, configurationPath, RoleConfiguration, "")
	if err != nil {
		return BootstrapAudit{}, err
	}

	replacementMap, err := validateBootstrapReplacements(configurationPath, candidateConfiguration, replacements)
	if err != nil {
		return BootstrapAudit{}, err
	}
	references, diagnostics := parseNativeReferences(candidateConfiguration, configurationPath, request.WorkingDirectory, manager.inspector.policy)
	if hasBlockingDiagnostics(diagnostics) {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap configuration references are invalid", ErrInvalidEdit)
	}
	audit := BootstrapAudit{
		ConfigurationSource: source, WorkingDirectory: working.evidence,
		Configuration: configuration, AlternateConfiguration: alternateConfiguration,
		ConfigurationParent: configurationParent,
	}
	storageRequirements := pathRequirements{expected: PathTypeDirectory, requireRead: true, requireWrite: true, requireSearch: true}
	storage := auditPath(ctx, references.storage.resolved, RoleStorage, references.storage.raw, storageRequirements, manager.inspector.policy)
	if !storage.evidence.Safe || hasBlockingDiagnostics(storage.diagnostics) {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap storage must already be safe and writable", ErrInvalidEdit)
	}
	audit.Storage = storage.evidence

	for _, reference := range references.dotenv {
		replacement, planned := replacementMap[reference.resolved]
		if !planned || replacement.Role != RoleDotenv {
			return BootstrapAudit{}, fmt.Errorf("%w: bootstrap dotenv must be an exact missing replacement", ErrInvalidEdit)
		}
		path, _, pathErr := manager.auditMissingTarget(ctx, reference.resolved, RoleDotenv, reference.raw)
		if pathErr != nil {
			return BootstrapAudit{}, pathErr
		}
		audit.Dotenv = append(audit.Dotenv, path)
		delete(replacementMap, reference.resolved)
	}
	delete(replacementMap, configurationPath)
	if len(replacementMap) != 0 {
		return BootstrapAudit{}, fmt.Errorf("%w: bootstrap replacement is not referenced by candidate YAML", ErrInvalidEdit)
	}

	webrootRequirements := pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}
	for _, reference := range references.webroots {
		path := auditPath(ctx, reference.resolved, RoleWebroot, reference.raw, webrootRequirements, manager.inspector.policy)
		if !path.evidence.Safe || hasBlockingDiagnostics(path.diagnostics) {
			return BootstrapAudit{}, fmt.Errorf("%w: bootstrap webroot must already be safe and writable", ErrInvalidEdit)
		}
		audit.Webroots = append(audit.Webroots, path.evidence)
	}
	return audit, nil
}

func (manager *TransactionManager) auditMissingTarget(
	ctx context.Context,
	target string,
	role PathRole,
	reference string,
) (CandidatePath, PathEvidence, error) {
	if err := validateSelectedPath(target); err != nil {
		return CandidatePath{}, PathEvidence{}, fmt.Errorf("%w: bootstrap target path", ErrInvalidEdit)
	}
	parentPath := filepath.Dir(target)
	parentRequirements := pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}
	parent := auditPath(ctx, parentPath, RoleWorkspace, "", parentRequirements, manager.inspector.policy)
	if !parent.evidence.Safe || hasBlockingDiagnostics(parent.diagnostics) {
		return CandidatePath{}, PathEvidence{}, fmt.Errorf("%w: bootstrap target parent is unsafe", ErrInvalidEdit)
	}
	missing := auditPath(ctx, target, role, reference, pathRequirements{expected: PathTypeRegular}, manager.inspector.policy)
	if missing.evidence.Exists || missing.evidence.Type != PathTypeMissing {
		return CandidatePath{}, PathEvidence{}, fmt.Errorf("%w: bootstrap target already exists", ErrSourceChanged)
	}
	confirmedParent := auditPath(ctx, parentPath, RoleWorkspace, "", parentRequirements, manager.inspector.policy)
	confirmedMissing := auditPath(ctx, target, role, reference, pathRequirements{expected: PathTypeRegular}, manager.inspector.policy)
	if !confirmedParent.evidence.Safe || !samePathPlacementEvidence(parent.evidence, confirmedParent.evidence) ||
		confirmedMissing.evidence.Exists || confirmedMissing.evidence.Type != PathTypeMissing ||
		!samePathAncestorEvidence(missing.evidence, confirmedMissing.evidence) {
		return CandidatePath{}, PathEvidence{}, fmt.Errorf("%w: bootstrap target changed during audit", ErrSourceChanged)
	}
	return CandidatePath{
		Role: role, Reference: reference, Path: target, WillCreate: true, Evidence: missing.evidence,
	}, parent.evidence, nil
}

func validateBootstrapReplacements(configurationPath string, candidate []byte, replacements []Replacement) (map[string]Replacement, error) {
	if len(replacements) == 0 || len(replacements) > maximumEditFiles {
		return nil, fmt.Errorf("%w: bootstrap replacement count is invalid", ErrInvalidEdit)
	}
	result := make(map[string]Replacement, len(replacements))
	configurationCount := 0
	for _, replacement := range replacements {
		if replacement.Role != RoleConfiguration && replacement.Role != RoleDotenv {
			return nil, fmt.Errorf("%w: bootstrap replacement role is invalid", ErrInvalidEdit)
		}
		if err := validateSelectedPath(replacement.Path); err != nil {
			return nil, fmt.Errorf("%w: bootstrap replacement target is invalid", ErrInvalidEdit)
		}
		limit := maximumDotenvBytes
		if replacement.Role == RoleConfiguration {
			configurationCount++
			limit = maximumConfigurationBytes
			if replacement.Path != configurationPath || !bytes.Equal(replacement.Content, candidate) {
				return nil, fmt.Errorf("%w: bootstrap configuration replacement disagrees with candidate", ErrInvalidEdit)
			}
		}
		if int64(len(replacement.Content)) > limit {
			return nil, fmt.Errorf("%w: bootstrap replacement exceeds its size limit", ErrInvalidEdit)
		}
		if _, duplicate := result[replacement.Path]; duplicate {
			return nil, fmt.Errorf("%w: bootstrap replacement target is duplicated", ErrInvalidEdit)
		}
		result[replacement.Path] = replacement
	}
	if configurationCount != 1 {
		return nil, fmt.Errorf("%w: bootstrap requires one configuration replacement", ErrInvalidEdit)
	}
	return result, nil
}

// Bootstrap creates and adopts a missing configuration through the durable
// edit journal. No stage is ever replayed after an interruption.
func (manager *TransactionManager) Bootstrap(
	ctx context.Context,
	lease *Lease,
	plan BootstrapPlan,
	guard CommitGuard,
) (Selection, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return Selection{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	if guard == nil {
		return Selection{}, fmt.Errorf("%w: bootstrap guard is required", ErrInvalidEdit)
	}
	candidate := append([]byte(nil), plan.CandidateConfiguration...)
	defer clear(candidate)
	replacements := cloneReplacements(plan.Replacements)
	defer clearReplacements(replacements)
	audit, err := manager.auditBootstrap(ctx, plan.Request, candidate, replacements, false)
	if err != nil {
		return Selection{}, err
	}
	sortReplacements(replacements)
	transactionID, err := NewTransactionID()
	if err != nil {
		return Selection{}, err
	}
	prepared, journal, err := manager.prepareBootstrapJournal(ctx, transactionID, audit, replacements)
	if err != nil {
		return Selection{}, err
	}
	defer closePrepared(prepared)
	if err := manager.journal.Create(ctx, journal); err != nil {
		return Selection{}, err
	}
	journalCreated := true
	abortBeforeReplacement := func(cause error) (Selection, error) {
		if journalCreated {
			if cleanupErr := manager.discardPrepared(ctx, journal, prepared); cleanupErr != nil {
				return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, cause)
			}
			journalCreated = false
		}
		return Selection{}, cause
	}
	if err := manager.inject(FailureAfterJournal, -1); err != nil {
		return Selection{}, fmt.Errorf("%w: injected after bootstrap journal", ErrRecoveryRequired)
	}
	for index := range prepared {
		if err := manager.stageCandidate(ctx, transactionID, &prepared[index]); err != nil {
			return abortBeforeReplacement(err)
		}
		if err := manager.inject(FailureAfterStage, index); err != nil {
			return Selection{}, fmt.Errorf("%w: injected after bootstrap staging", ErrRecoveryRequired)
		}
	}
	if err := manager.recheckBootstrap(ctx, plan.Request, candidate, replacements, audit, prepared); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalPrepared); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.inject(FailureAfterPrepared, -1); err != nil {
		return Selection{}, fmt.Errorf("%w: injected after bootstrap prepare", ErrRecoveryRequired)
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalReplacing); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := guard(ctx); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.recheckBootstrap(ctx, plan.Request, candidate, replacements, audit, prepared); err != nil {
		return abortBeforeReplacement(err)
	}
	for index := range prepared {
		if err := manager.inject(FailureBeforeReplace, index); err != nil {
			return Selection{}, fmt.Errorf("%w: injected during bootstrap replacement", ErrRecoveryRequired)
		}
		if err := manager.activateCandidate(ctx, transactionID, &prepared[index]); err != nil {
			return Selection{}, fmt.Errorf("%w: bootstrap replacement: %w", ErrRecoveryRequired, err)
		}
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalFinalizing); err != nil {
		return Selection{}, fmt.Errorf("%w: record bootstrap finalization", ErrRecoveryRequired)
	}
	journalCreated = false
	if err := manager.inject(FailureBeforeFinalize, -1); err != nil {
		return Selection{}, fmt.Errorf("%w: injected before bootstrap finalization", ErrRecoveryRequired)
	}
	selection, err := manager.inspectBootstrapCommitted(ctx, plan.Request, audit, candidate, replacements)
	if err != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, err)
	}
	if err := manager.selections.FinalizeEdit(ctx, selection, transactionID); err != nil {
		return Selection{}, fmt.Errorf("%w: finalize bootstrapped workspace", ErrRecoveryRequired)
	}
	return selection, nil
}

func (manager *TransactionManager) prepareBootstrapJournal(
	ctx context.Context,
	transactionID string,
	audit BootstrapAudit,
	replacements []Replacement,
) ([]preparedReplacement, Journal, error) {
	prepared := make([]preparedReplacement, 0, len(replacements))
	journal := Journal{
		TransactionID: transactionID, Phase: JournalStaging,
		WorkingDirectory: audit.WorkingDirectory.Path, ConfigurationPath: audit.Configuration.Path,
		Bootstrap: true, ConfigurationSource: audit.ConfigurationSource, CreatedAt: manager.now().UTC(),
	}
	for index, replacement := range replacements {
		parent, parentID, err := manager.openReplacementParent(ctx, replacement.Path)
		if err != nil {
			closePrepared(prepared)
			return nil, Journal{}, err
		}
		entry := preparedReplacement{
			replacement: replacement, ordinal: index, parent: parent, parentID: parentID,
			stage: fmt.Sprintf(".acmemux-edit-%s-%03d", transactionID, index),
		}
		stageMissing, stageErr := missingAt(parent, entry.stage)
		cleanupMissing, cleanupErr := missingAt(parent, cleanupBasename(entry.stage))
		targetMissing, targetErr := missingAt(parent, filepath.Base(replacement.Path))
		if stageErr != nil || cleanupErr != nil || targetErr != nil || !stageMissing || !cleanupMissing || !targetMissing {
			_ = parent.Close()
			closePrepared(prepared)
			return nil, Journal{}, fmt.Errorf("%w: bootstrap target or stage changed", ErrSourceChanged)
		}
		prepared = append(prepared, entry)
		journal.Files = append(journal.Files, JournalFile{
			Ordinal: index, Role: replacement.Role, TargetPath: replacement.Path,
			ParentPath: filepath.Dir(replacement.Path), StageBasename: entry.stage, Parent: parentID,
		})
	}
	if journal.CreatedAt.IsZero() {
		closePrepared(prepared)
		return nil, Journal{}, errors.New("native edit clock returned zero time")
	}
	return prepared, journal, nil
}

func (manager *TransactionManager) recheckBootstrap(
	ctx context.Context,
	request BootstrapRequest,
	candidate []byte,
	replacements []Replacement,
	reviewed BootstrapAudit,
	prepared []preparedReplacement,
) error {
	current, err := manager.auditBootstrap(ctx, request, candidate, replacements, true)
	if err != nil || BootstrapFingerprint(current) != BootstrapFingerprint(reviewed) {
		return fmt.Errorf("%w: bootstrap evidence changed", ErrSourceChanged)
	}
	for index := range prepared {
		entry := &prepared[index]
		parentStat, statErr := fstat(int(entry.parent.Fd()))
		if statErr != nil || !sameDirectoryIdentity(entry.parentID, identityFromStat(parentStat)) {
			return fmt.Errorf("%w: bootstrap replacement parent changed", ErrSourceChanged)
		}
		missing, missingErr := missingAt(entry.parent, filepath.Base(entry.replacement.Path))
		if missingErr != nil || !missing {
			return fmt.Errorf("%w: bootstrap target appeared", ErrSourceChanged)
		}
		staged, stagedErr := fingerprintAt(ctx, entry.parent, entry.stage, maximumFileLimit(entry.replacement.Role))
		if stagedErr != nil || !sameFingerprintContent(entry.candidate, staged, true) {
			return fmt.Errorf("%w: bootstrap candidate changed", ErrSourceChanged)
		}
	}
	return nil
}

func (manager *TransactionManager) inspectBootstrapCommitted(
	ctx context.Context,
	request BootstrapRequest,
	audit BootstrapAudit,
	candidate []byte,
	replacements []Replacement,
) (Selection, error) {
	if _, err := manager.selections.Load(ctx); err == nil {
		return Selection{}, fmt.Errorf("%w: a workspace was selected during bootstrap", ErrSourceChanged)
	} else if !errors.Is(err, ErrNoSelection) {
		return Selection{}, err
	}
	if audit.ConfigurationSource == ConfigurationConventionalYML {
		alternate, _, err := manager.auditMissingTarget(
			ctx, filepath.Join(request.WorkingDirectory, ".lego.yaml"), RoleConfiguration, "",
		)
		if err != nil || !samePathAncestorEvidence(audit.AlternateConfiguration.Evidence, alternate.Evidence) {
			return Selection{}, fmt.Errorf("%w: conventional configuration precedence changed", ErrSourceChanged)
		}
	}
	inspectRequest := Request{WorkingDirectory: request.WorkingDirectory}
	if audit.ConfigurationSource == ConfigurationExplicit {
		inspectRequest.ConfigurationPath = audit.Configuration.Path
	}
	review, err := manager.inspector.Inspect(ctx, inspectRequest)
	if err != nil || !review.Adoptable || review.Configuration.Path != audit.Configuration.Path {
		return Selection{}, errors.New("bootstrapped workspace did not pass fresh inspection")
	}
	if !samePathPlacementEvidence(audit.WorkingDirectory, review.WorkingDirectory) ||
		!samePathAncestorEvidence(audit.Configuration.Evidence, review.Configuration) ||
		!samePathPlacementEvidence(audit.Storage, review.Storage) ||
		!samePathPlacementEvidenceSlice(audit.Webroots, review.Webroots) || len(audit.Dotenv) != len(review.DotenvFiles) {
		return Selection{}, fmt.Errorf("%w: bootstrapped workspace evidence changed", ErrSourceChanged)
	}
	reviewedAt := manager.now().UTC()
	if reviewedAt.Before(review.ObservedAt) {
		reviewedAt = review.ObservedAt
	}
	selection := Selection{Review: review, ReviewedAt: reviewedAt}
	sources, err := manager.snapshotSelection(ctx, selection)
	if err != nil {
		return Selection{}, err
	}
	defer sources.Close()
	replacementMap := make(map[string]Replacement, len(replacements))
	for _, replacement := range replacements {
		replacementMap[replacement.Path] = replacement
	}
	configuration, present := replacementMap[sources.Configuration.Path]
	if !present || configuration.Role != RoleConfiguration || !bytes.Equal(configuration.Content, candidate) ||
		sources.Configuration.Fingerprint.SHA256 != sha256Bytes(candidate) {
		return Selection{}, errors.New("active bootstrap configuration differs from candidate")
	}
	delete(replacementMap, sources.Configuration.Path)
	for index, source := range sources.Dotenv {
		if index >= len(audit.Dotenv) || audit.Dotenv[index].Path != source.Path ||
			!samePathAncestorEvidence(audit.Dotenv[index].Evidence, review.DotenvFiles[index]) {
			return Selection{}, fmt.Errorf("%w: bootstrap dotenv evidence changed", ErrSourceChanged)
		}
		replacement, exists := replacementMap[source.Path]
		if !exists || replacement.Role != RoleDotenv || source.Fingerprint.SHA256 != sha256Bytes(replacement.Content) {
			return Selection{}, errors.New("active bootstrap dotenv differs from candidate")
		}
		delete(replacementMap, source.Path)
	}
	if len(replacementMap) != 0 {
		return Selection{}, errors.New("bootstrap replacement is absent from fresh workspace")
	}
	return selection, nil
}
