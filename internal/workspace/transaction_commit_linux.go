//go:build linux

package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type preparedReplacement struct {
	replacement      Replacement
	ordinal          int
	parent           *os.File
	parentID         FileIdentity
	stage            string
	original         SourceFingerprint
	candidate        SourceFingerprint
	existed          bool
	activated        bool
	cleanupUncertain bool
}

// Commit performs one journaled per-file atomic edit and returns freshly
// inspected workspace evidence. It never describes multiple renames as a
// single filesystem transaction.
func (manager *TransactionManager) Commit(
	ctx context.Context,
	lease *Lease,
	plan CommitPlan,
	guard CommitGuard,
) (Selection, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return Selection{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	if guard == nil {
		return Selection{}, fmt.Errorf("%w: commit guard is required", ErrInvalidEdit)
	}
	if _, err := manager.journal.Load(ctx); err == nil {
		return Selection{}, ErrRecoveryRequired
	} else if !errors.Is(err, ErrNoEditJournal) {
		return Selection{}, fmt.Errorf("inspect native edit journal: %w", err)
	}
	candidateConfiguration := append([]byte(nil), plan.CandidateConfiguration...)
	defer clear(candidateConfiguration)
	replacements := cloneReplacements(plan.Replacements)
	defer clearReplacements(replacements)
	candidateAudit, err := manager.AuditCandidate(ctx, lease, plan.Sources, candidateConfiguration, replacements)
	if err != nil {
		return Selection{}, err
	}
	sortReplacements(replacements)
	transactionID, err := NewTransactionID()
	if err != nil {
		return Selection{}, err
	}
	prepared, journal, err := manager.prepareJournal(ctx, transactionID, plan.Sources, replacements)
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
		return Selection{}, fmt.Errorf("%w: injected after journal", ErrRecoveryRequired)
	}
	for index := range prepared {
		if err := manager.stageCandidate(ctx, transactionID, &prepared[index]); err != nil {
			return abortBeforeReplacement(err)
		}
		if err := manager.inject(FailureAfterStage, index); err != nil {
			return Selection{}, fmt.Errorf("%w: injected after staging file %d", ErrRecoveryRequired, index)
		}
	}
	if err := manager.recheckSources(ctx, plan.Sources, prepared); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalPrepared); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.inject(FailureAfterPrepared, -1); err != nil {
		return Selection{}, fmt.Errorf("%w: injected after prepare", ErrRecoveryRequired)
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalReplacing); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := guard(ctx); err != nil {
		return abortBeforeReplacement(err)
	}
	if err := manager.recheckSources(ctx, plan.Sources, prepared); err != nil {
		return abortBeforeReplacement(err)
	}
	workingRequirements := pathRequirements{expected: PathTypeDirectory, requireRead: true, requireSearch: true}
	working := auditPath(ctx, plan.Sources.Selection.Review.WorkingDirectory.Path, RoleWorkingDirectory, "", workingRequirements, manager.inspector.policy)
	if !working.evidence.Safe || hasBlockingDiagnostics(working.diagnostics) ||
		!samePathPlacementEvidence(plan.Sources.Selection.Review.WorkingDirectory, working.evidence) {
		return abortBeforeReplacement(fmt.Errorf("%w: reviewed working directory changed during authorization", ErrSourceChanged))
	}
	confirmedAudit, err := manager.AuditCandidate(ctx, lease, plan.Sources, candidateConfiguration, replacements)
	if err != nil || !sameCandidateAudit(candidateAudit, confirmedAudit) {
		return abortBeforeReplacement(fmt.Errorf("%w: candidate path evidence changed during authorization", ErrSourceChanged))
	}
	replaced := 0
	for index := range prepared {
		if err := manager.inject(FailureBeforeReplace, index); err != nil {
			if replaced == 0 {
				return Selection{}, fmt.Errorf("%w: injected before replacement", ErrRecoveryRequired)
			}
			return Selection{}, fmt.Errorf("%w: injected during replacement", ErrRecoveryRequired)
		}
		if err := manager.activateCandidate(ctx, transactionID, &prepared[index]); err != nil {
			if replaced == 0 && !prepared[index].activated {
				return abortBeforeReplacement(err)
			}
			return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, err)
		}
		replaced++
	}
	if err := manager.journal.SetPhase(ctx, transactionID, JournalFinalizing); err != nil {
		return Selection{}, fmt.Errorf("%w: record finalization phase", ErrRecoveryRequired)
	}
	journalCreated = false // FinalizeEdit owns clearing from this point.
	if err := manager.inject(FailureBeforeFinalize, -1); err != nil {
		return Selection{}, fmt.Errorf("%w: injected before finalization", ErrRecoveryRequired)
	}
	selection, err := manager.inspectCommitted(ctx, plan.Sources, candidateAudit, candidateConfiguration, replacements)
	if err != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, err)
	}
	if err := manager.selections.FinalizeEdit(ctx, selection, transactionID); err != nil {
		return Selection{}, fmt.Errorf("%w: finalize edited workspace", ErrRecoveryRequired)
	}
	return selection, nil
}

func (manager *TransactionManager) prepareJournal(
	ctx context.Context,
	transactionID string,
	sources *SourceSet,
	replacements []Replacement,
) ([]preparedReplacement, Journal, error) {
	prepared := make([]preparedReplacement, 0, len(replacements))
	journal := Journal{
		TransactionID: transactionID, Phase: JournalStaging,
		WorkingDirectory:    sources.Selection.Review.WorkingDirectory.Path,
		ConfigurationPath:   sources.Selection.Review.Configuration.Path,
		ConfigurationSource: sources.Selection.Review.ConfigurationSource,
		CreatedAt:           manager.now().UTC(),
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
		cleanupMissing, cleanupErr := missingAt(parent, cleanupBasename(entry.stage))
		if cleanupErr != nil || !cleanupMissing {
			_ = parent.Close()
			closePrepared(prepared)
			return nil, Journal{}, fmt.Errorf("%w: native edit cleanup name is occupied", ErrSourceChanged)
		}
		if source, exists := sourceForPath(sources, replacement.Path); exists {
			entry.existed = true
			entry.original = source.Fingerprint
		} else {
			missing, err := missingAt(parent, filepath.Base(replacement.Path))
			if err != nil || !missing {
				_ = parent.Close()
				closePrepared(prepared)
				return nil, Journal{}, fmt.Errorf("%w: replacement target was not part of the reviewed sources", ErrInvalidEdit)
			}
		}
		prepared = append(prepared, entry)
		journal.Files = append(journal.Files, JournalFile{
			Ordinal: index, Role: replacement.Role, TargetPath: replacement.Path,
			ParentPath: filepath.Dir(replacement.Path), StageBasename: entry.stage,
			Original: entry.original.Identity, Parent: parentID,
		})
	}
	if journal.CreatedAt.IsZero() {
		closePrepared(prepared)
		return nil, Journal{}, errors.New("native edit clock returned zero time")
	}
	return prepared, journal, nil
}

func (manager *TransactionManager) openReplacementParent(ctx context.Context, target string) (*os.File, FileIdentity, error) {
	parentPath := filepath.Dir(target)
	requirements := pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}
	audited := auditPath(ctx, parentPath, RoleWorkspace, "", requirements, manager.inspector.policy)
	if !audited.evidence.Safe || hasBlockingDiagnostics(audited.diagnostics) {
		return nil, FileIdentity{}, fmt.Errorf("%w: replacement parent is unsafe", ErrInvalidEdit)
	}
	fd, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, FileIdentity{}, fmt.Errorf("open replacement parent: %w", err)
	}
	file := os.NewFile(uintptr(fd), parentPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, FileIdentity{}, errors.New("retain replacement parent")
	}
	stat, err := fstat(fd)
	if err != nil || stat.Dev != audited.evidence.Device || stat.Ino != audited.evidence.Inode ||
		stat.Mode != audited.evidence.Mode || stat.Uid != audited.evidence.UID || stat.Gid != audited.evidence.GID {
		_ = file.Close()
		return nil, FileIdentity{}, fmt.Errorf("%w: replacement parent changed while opened", ErrSourceChanged)
	}
	return file, identityFromStat(stat), nil
}

func (manager *TransactionManager) stageCandidate(ctx context.Context, transactionID string, prepared *preparedReplacement) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Openat(int(prepared.parent.Fd()), prepared.stage,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create restrictive native edit candidate: %w", err)
	}
	file := os.NewFile(uintptr(fd), prepared.stage)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("retain native edit candidate")
	}
	failed := true
	defer func() {
		if failed {
			// Never unlink a staging basename from this error path: another
			// process may have exchanged the directory entry while this exact
			// inode remained open. Scrub the retained inode through its file
			// descriptor, record its final in-memory identity for the normal
			// journaled discard path, and fail closed if cleanup cannot prove
			// ownership later.
			scrubbed, scrubErr := scrubOpenFile(file)
			if scrubErr == nil {
				prepared.candidate = SourceFingerprint{
					Path: prepared.replacement.Path, Identity: scrubbed,
					SHA256: sha256Bytes(nil),
				}
			}
			syncErr := syncDirectory(prepared.parent)
			if scrubErr != nil || syncErr != nil {
				prepared.cleanupUncertain = true
			}
			result = errors.Join(result, scrubErr, syncErr)
		}
		closeErr := file.Close()
		result = errors.Join(result, closeErr)
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return fmt.Errorf("restrict native edit candidate: %w", err)
	}
	if err := manager.inject(FailureBeforeStageWrite, prepared.ordinal); err != nil {
		return err
	}
	if err := writeAll(file, prepared.replacement.Content); err != nil {
		return fmt.Errorf("write native edit candidate: %w", err)
	}
	if err := manager.inject(FailureBeforeStageSync, prepared.ordinal); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("synchronize native edit candidate: %w", err)
	}
	stat, err := fstat(fd)
	if err != nil {
		return fmt.Errorf("inspect native edit candidate: %w", err)
	}
	identity := identityFromStat(stat)
	if !validCandidateIdentity(identity) || identity.Size != int64(len(prepared.replacement.Content)) {
		return errors.New("staged native edit candidate evidence is invalid")
	}
	prepared.candidate = SourceFingerprint{
		Path: prepared.replacement.Path, Identity: identity,
		SHA256: sha256Bytes(prepared.replacement.Content),
	}
	if err := manager.inject(FailureBeforeStageDirSync, prepared.ordinal); err != nil {
		return err
	}
	if err := syncDirectory(prepared.parent); err != nil {
		return fmt.Errorf("synchronize native edit candidate directory: %w", err)
	}
	if err := manager.journal.MarkCandidate(ctx, transactionID, prepared.ordinal, identity); err != nil {
		return err
	}
	failed = false
	return nil
}

func (manager *TransactionManager) recheckSources(ctx context.Context, sources *SourceSet, prepared []preparedReplacement) error {
	for _, source := range sources.Files() {
		current, err := manager.readSource(ctx, pathEvidenceForSource(sources.Selection.Review, source.Path), sourceLimit(source.Role))
		if err != nil {
			return err
		}
		matched := sameSourceFingerprint(source.Fingerprint, current.Fingerprint)
		clear(current.Content)
		if !matched {
			return fmt.Errorf("%w: native source content or metadata", ErrSourceChanged)
		}
	}
	for _, entry := range prepared {
		parentStat, err := fstat(int(entry.parent.Fd()))
		if err != nil || !sameDirectoryIdentity(entry.parentID, identityFromStat(parentStat)) {
			return fmt.Errorf("%w: replacement parent", ErrSourceChanged)
		}
		if !entry.existed {
			missing, err := missingAt(entry.parent, filepath.Base(entry.replacement.Path))
			if err != nil || !missing {
				return fmt.Errorf("%w: new replacement target", ErrSourceChanged)
			}
		}
		candidate, err := fingerprintAt(ctx, entry.parent, entry.stage, maximumFileLimit(entry.replacement.Role))
		if err != nil || !sameFingerprintContent(entry.candidate, candidate, true) {
			return fmt.Errorf("%w: staged candidate", ErrSourceChanged)
		}
	}
	return nil
}

func sameDirectoryIdentity(expected, current FileIdentity) bool {
	return expected.Exists && current.Exists && expected.Device == current.Device &&
		expected.Inode == current.Inode && expected.Mode == current.Mode &&
		expected.UID == current.UID && expected.GID == current.GID &&
		expected.NLink == current.NLink
}

func (manager *TransactionManager) activateCandidate(ctx context.Context, transactionID string, prepared *preparedReplacement) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parentFD := int(prepared.parent.Fd())
	target := filepath.Base(prepared.replacement.Path)
	flags := uint(0)
	if prepared.existed {
		flags = unix.RENAME_EXCHANGE
	} else {
		flags = unix.RENAME_NOREPLACE
	}
	if err := unix.Renameat2(parentFD, prepared.stage, parentFD, target, flags); err != nil {
		return fmt.Errorf("atomically activate native edit candidate: %w", err)
	}
	prepared.activated = true
	if err := manager.inject(FailureAfterRename, prepared.ordinal); err != nil {
		return err
	}
	active, activeErr := fingerprintAt(ctx, prepared.parent, target, maximumFileLimit(prepared.replacement.Role))
	activeMatches := activeErr == nil && sameFingerprintContent(prepared.candidate, active, false)
	if !activeMatches {
		return errors.New("active native edit candidate changed during replacement")
	}
	placedOriginal := SourceFingerprint{}
	if prepared.existed {
		displaced, displacedErr := fingerprintAt(ctx, prepared.parent, prepared.stage, maximumFileLimit(prepared.replacement.Role))
		if displacedErr != nil || !sameFingerprintContent(prepared.original, displaced, false) {
			// Exchange back only while the active candidate still has the retained
			// candidate inode. This restores external work without overwriting it.
			if rollbackCurrent, err := fingerprintAt(ctx, prepared.parent, target, maximumFileLimit(prepared.replacement.Role)); err == nil && sameFingerprintContent(prepared.candidate, rollbackCurrent, false) {
				if rollbackErr := unix.Renameat2(parentFD, prepared.stage, parentFD, target, unix.RENAME_EXCHANGE); rollbackErr == nil {
					if syncErr := syncDirectory(prepared.parent); syncErr == nil {
						prepared.activated = false
					}
				}
			}
			return fmt.Errorf("%w: displaced target did not match reviewed source", ErrSourceChanged)
		}
		placedOriginal = displaced
	}
	if err := manager.journal.MarkPlacement(
		ctx, transactionID, prepared.ordinal, active.Identity, placedOriginal.Identity,
	); err != nil {
		return err
	}
	prepared.candidate.Identity = active.Identity
	prepared.original.Identity = placedOriginal.Identity
	if err := manager.inject(FailureAfterReplace, prepared.ordinal); err != nil {
		return err
	}
	if err := manager.inject(FailureBeforeActiveSync, prepared.ordinal); err != nil {
		return err
	}
	if err := syncDirectory(prepared.parent); err != nil {
		return fmt.Errorf("synchronize active native edit directory: %w", err)
	}
	if err := manager.inject(FailureAfterDirectorySync, prepared.ordinal); err != nil {
		return err
	}
	placedCandidate, candidateErr := fingerprintAt(ctx, prepared.parent, target, maximumFileLimit(prepared.replacement.Role))
	if candidateErr != nil || !sameFingerprintContent(prepared.candidate, placedCandidate, false) {
		return fmt.Errorf("%w: active candidate changed before applied record", ErrSourceChanged)
	}
	confirmedOriginal := SourceFingerprint{}
	if prepared.existed {
		confirmedOriginal, candidateErr = fingerprintAt(ctx, prepared.parent, prepared.stage, maximumFileLimit(prepared.replacement.Role))
		if candidateErr != nil || !sameFingerprintContent(prepared.original, confirmedOriginal, false) {
			return fmt.Errorf("%w: displaced source changed before applied record", ErrSourceChanged)
		}
	}
	if err := manager.journal.MarkApplied(
		ctx,
		transactionID,
		prepared.ordinal,
		placedCandidate.Identity,
		confirmedOriginal.Identity,
	); err != nil {
		return err
	}
	if err := manager.inject(FailureAfterAppliedRecord, prepared.ordinal); err != nil {
		return err
	}
	if prepared.existed {
		if err := manager.inject(FailureBeforeOldUnlink, prepared.ordinal); err != nil {
			return err
		}
		if err := manager.removeOwnedFingerprintAt(
			ctx,
			prepared.parent,
			prepared.stage,
			prepared.original,
			maximumFileLimit(prepared.replacement.Role),
			prepared.ordinal,
		); err != nil {
			return fmt.Errorf("%w: displaced native source cleanup: %w", ErrSourceChanged, err)
		}
		if err := manager.inject(FailureBeforeOldDirSync, prepared.ordinal); err != nil {
			return err
		}
		if err := syncDirectory(prepared.parent); err != nil {
			return fmt.Errorf("synchronize displaced native source removal: %w", err)
		}
	}
	return nil
}

func (manager *TransactionManager) inspectCommitted(
	ctx context.Context,
	priorSources *SourceSet,
	candidateAudit CandidateAudit,
	candidateConfiguration []byte,
	replacements []Replacement,
) (Selection, error) {
	if priorSources == nil || priorSources.closed {
		return Selection{}, errors.New("reviewed source set is unavailable")
	}
	prior := priorSources.Selection
	request := Request{WorkingDirectory: prior.Review.WorkingDirectory.Path}
	if prior.Review.ConfigurationSource == ConfigurationExplicit {
		request.ConfigurationPath = prior.Review.Configuration.Path
	}
	review, err := manager.inspector.Inspect(ctx, request)
	if err != nil || !review.Adoptable {
		return Selection{}, errors.New("edited workspace did not pass fresh inspection")
	}
	if !samePathPlacementEvidence(prior.Review.WorkingDirectory, review.WorkingDirectory) ||
		!samePathPlacementEvidence(candidateAudit.Storage, review.Storage) ||
		!samePathPlacementEvidenceSlice(candidateAudit.Webroots, review.Webroots) {
		return Selection{}, fmt.Errorf("%w: candidate workspace path evidence changed during commit", ErrSourceChanged)
	}
	if len(candidateAudit.Dotenv) != len(review.DotenvFiles) {
		return Selection{}, fmt.Errorf("%w: candidate dotenv reference set changed during commit", ErrSourceChanged)
	}
	reviewedAt := manager.now().UTC()
	if reviewedAt.Before(review.ObservedAt) {
		reviewedAt = review.ObservedAt
	}
	selection := Selection{Review: review, ReviewedAt: reviewedAt}
	currentSources, err := manager.snapshotSelection(ctx, selection)
	if err != nil {
		return Selection{}, err
	}
	defer currentSources.Close()
	replacementByPath := make(map[string]Replacement, len(replacements))
	validatedReplacementByPath := make(map[string]Replacement, len(replacements))
	replacedPaths := make(map[string]struct{}, len(replacements))
	for _, replacement := range replacements {
		replacementByPath[replacement.Path] = replacement
		replacedPaths[replacement.Path] = struct{}{}
	}
	if replacement, changed := replacementByPath[currentSources.Configuration.Path]; changed {
		if replacement.Role != RoleConfiguration || !bytes.Equal(replacement.Content, candidateConfiguration) ||
			currentSources.Configuration.Fingerprint.SHA256 != sha256Bytes(replacement.Content) {
			return Selection{}, errors.New("active configuration differs from the validated candidate")
		}
		delete(replacementByPath, currentSources.Configuration.Path)
	} else if !sameSourceFingerprint(priorSources.Configuration.Fingerprint, currentSources.Configuration.Fingerprint) {
		return Selection{}, fmt.Errorf("%w: unmodified configuration changed during commit", ErrSourceChanged)
	}
	seenReviewed := make(map[string]struct{}, len(currentSources.Dotenv))
	for index, current := range currentSources.Dotenv {
		expectedPath := candidateAudit.Dotenv[index]
		currentEvidence := review.DotenvFiles[index]
		if expectedPath.Path != current.Path || expectedPath.Path != currentEvidence.Path ||
			expectedPath.Reference != currentEvidence.Reference ||
			!samePathAncestorEvidence(expectedPath.Evidence, currentEvidence) {
			return Selection{}, fmt.Errorf("%w: candidate dotenv path evidence changed during commit", ErrSourceChanged)
		}
		if replacement, changed := replacementByPath[current.Path]; changed {
			if replacement.Role != RoleDotenv || current.Fingerprint.SHA256 != sha256Bytes(replacement.Content) {
				return Selection{}, errors.New("edited dotenv differs from the validated candidate")
			}
			validatedReplacementByPath[current.Path] = replacement
			delete(replacementByPath, current.Path)
			continue
		}
		if replacement, alreadyValidated := validatedReplacementByPath[current.Path]; alreadyValidated {
			// Multiple native challenge entries may intentionally reference the
			// same dotenv path. The service emits one replacement per canonical
			// path, while workspace evidence retains every logical reference.
			if replacement.Role != RoleDotenv || current.Fingerprint.SHA256 != sha256Bytes(replacement.Content) {
				return Selection{}, errors.New("shared edited dotenv differs from the validated candidate")
			}
			continue
		}
		prior, present := sourceForPath(priorSources, current.Path)
		if !present || prior.Role != RoleDotenv || !sameSourceFingerprint(prior.Fingerprint, current.Fingerprint) {
			return Selection{}, fmt.Errorf("%w: unmodified dotenv changed during commit", ErrSourceChanged)
		}
		seenReviewed[current.Path] = struct{}{}
	}
	for _, prior := range priorSources.Dotenv {
		if _, replaced := replacedPaths[prior.Path]; replaced {
			continue
		}
		if _, present := seenReviewed[prior.Path]; present {
			continue
		}
		// A candidate may intentionally stop referencing a reviewed dotenv.
		// It is no longer part of the fresh SourceSet, but it still belongs to
		// the reviewed pre-commit boundary and therefore must remain unchanged
		// through finalization.
		current, readErr := manager.readSource(
			ctx,
			pathEvidenceForSource(priorSources.Selection.Review, prior.Path),
			sourceLimit(prior.Role),
		)
		if readErr != nil {
			return Selection{}, fmt.Errorf("%w: unreferenced reviewed dotenv", ErrSourceChanged)
		}
		matched := sameSourceFingerprint(prior.Fingerprint, current.Fingerprint)
		clear(current.Content)
		if !matched {
			return Selection{}, fmt.Errorf("%w: unreferenced reviewed dotenv changed during commit", ErrSourceChanged)
		}
	}
	if len(replacementByPath) != 0 {
		return Selection{}, errors.New("edited target is absent from fresh workspace evidence")
	}
	return selection, nil
}

func sameCandidateAudit(left, right CandidateAudit) bool {
	if !samePathPlacementEvidence(left.Storage, right.Storage) ||
		!samePathPlacementEvidenceSlice(left.Webroots, right.Webroots) || len(left.Dotenv) != len(right.Dotenv) {
		return false
	}
	for index := range left.Dotenv {
		if left.Dotenv[index].Role != right.Dotenv[index].Role ||
			left.Dotenv[index].Reference != right.Dotenv[index].Reference ||
			left.Dotenv[index].Path != right.Dotenv[index].Path ||
			left.Dotenv[index].Exists != right.Dotenv[index].Exists ||
			left.Dotenv[index].WillCreate != right.Dotenv[index].WillCreate ||
			!samePathPlacementEvidence(left.Dotenv[index].Evidence, right.Dotenv[index].Evidence) {
			return false
		}
	}
	return true
}

func samePathPlacementEvidence(left, right PathEvidence) bool {
	if left.Type == PathTypeDirectory {
		left.Size = 0
		left.ModifiedAt = time.Time{}
		left.ChangedAt = time.Time{}
	}
	if right.Type == PathTypeDirectory {
		right.Size = 0
		right.ModifiedAt = time.Time{}
		right.ChangedAt = time.Time{}
	}
	return samePathEvidence(left, right)
}

func samePathPlacementEvidenceSlice(left, right []PathEvidence) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !samePathPlacementEvidence(left[index], right[index]) {
			return false
		}
	}
	return true
}

func samePathAncestorEvidence(left, right PathEvidence) bool {
	if left.Role != right.Role || left.Reference != right.Reference || left.Path != right.Path {
		return false
	}
	leftComponents := ancestorComponents(left)
	rightComponents := ancestorComponents(right)
	if len(leftComponents) != len(rightComponents) {
		return false
	}
	for index := range leftComponents {
		leftComponent := leftComponents[index]
		rightComponent := rightComponents[index]
		leftComponent.NLink = 0
		rightComponent.NLink = 0
		if leftComponent != rightComponent {
			return false
		}
	}
	return true
}

func ancestorComponents(evidence PathEvidence) []ComponentEvidence {
	components := evidence.Components
	if len(components) != 0 && components[len(components)-1].Path == evidence.Path {
		components = components[:len(components)-1]
	}
	return components
}

func (manager *TransactionManager) discardPrepared(ctx context.Context, journal Journal, prepared []preparedReplacement) error {
	var cleanupError error
	for index := range prepared {
		entry := &prepared[index]
		if entry.parent == nil {
			continue
		}
		if entry.cleanupUncertain {
			cleanupError = errors.New("native edit staging cleanup durability is uncertain")
			continue
		}
		basename, exists, err := ownedStageBasename(entry.parent, entry.stage)
		if err != nil {
			cleanupError = err
			continue
		}
		if !exists {
			continue
		}
		if !entry.candidate.Identity.Exists {
			cleanupError = errors.New("native edit staging identity is unavailable")
			continue
		}
		if err := manager.removeOwnedFingerprintAt(
			ctx,
			entry.parent,
			basename,
			entry.candidate,
			maximumFileLimit(entry.replacement.Role),
			entry.ordinal,
		); err != nil {
			cleanupError = err
		}
	}
	if cleanupError != nil {
		return cleanupError
	}
	return manager.journal.Clear(ctx, journal.TransactionID)
}

func closePrepared(values []preparedReplacement) {
	for index := range values {
		if values[index].parent != nil {
			_ = values[index].parent.Close()
			values[index].parent = nil
		}
		values[index].original = SourceFingerprint{}
		values[index].candidate = SourceFingerprint{}
	}
}

func (manager *TransactionManager) inject(point FailurePoint, ordinal int) error {
	if manager.injector == nil {
		return nil
	}
	return manager.injector(point, ordinal)
}

func missingAt(parent *os.File, basename string) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), basename, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return true, nil
	}
	return false, err
}

func fingerprintAt(ctx context.Context, parent *os.File, basename string, limit int64) (SourceFingerprint, error) {
	file, fingerprint, err := openFingerprintAt(ctx, parent, basename, limit)
	if err != nil {
		return SourceFingerprint{}, err
	}
	if err := file.Close(); err != nil {
		return SourceFingerprint{}, err
	}
	return fingerprint, nil
}

func openFingerprintAt(ctx context.Context, parent *os.File, basename string, limit int64) (*os.File, SourceFingerprint, error) {
	if err := ctx.Err(); err != nil {
		return nil, SourceFingerprint{}, err
	}
	fd, err := unix.Openat(int(parent.Fd()), basename, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, SourceFingerprint{}, err
	}
	file := os.NewFile(uintptr(fd), basename)
	if file == nil {
		_ = unix.Close(fd)
		return nil, SourceFingerprint{}, errors.New("retain native source")
	}
	before, err := fstat(fd)
	if err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || before.Size < 0 || before.Size > limit {
		_ = file.Close()
		return nil, SourceFingerprint{}, errors.New("native source metadata is invalid")
	}
	contents, err := io.ReadAll(io.LimitReader(&contextReader{context: ctx, reader: file}, limit+1))
	if err != nil || int64(len(contents)) != before.Size {
		clear(contents)
		_ = file.Close()
		return nil, SourceFingerprint{}, errors.New("native source could not be read consistently")
	}
	after, err := fstat(fd)
	if err != nil || !sameStableStat(before, after) {
		clear(contents)
		_ = file.Close()
		return nil, SourceFingerprint{}, fmt.Errorf("%w: native source changed while read", ErrSourceChanged)
	}
	digest := sha256Bytes(contents)
	clear(contents)
	return file, SourceFingerprint{Identity: identityFromStat(before), SHA256: digest}, nil
}

func cleanupBasename(stage string) string { return stage + ".remove" }

// ownedStageBasename returns the one journal-owned staging location. Cleanup
// first renames a stage to its transaction-bound quarantine name; a crash can
// therefore be resumed without scanning or trusting unrelated directory
// entries.
func ownedStageBasename(parent *os.File, stage string) (string, bool, error) {
	stageMissing, err := missingAt(parent, stage)
	if err != nil {
		return "", false, err
	}
	cleanup := cleanupBasename(stage)
	cleanupMissing, err := missingAt(parent, cleanup)
	if err != nil {
		return "", false, err
	}
	if !stageMissing && !cleanupMissing {
		return "", false, fmt.Errorf("%w: both stage and cleanup entries exist", ErrSourceChanged)
	}
	if !stageMissing {
		return stage, true, nil
	}
	if !cleanupMissing {
		return cleanup, true, nil
	}
	return "", false, nil
}

func (manager *TransactionManager) removeOwnedFingerprintAt(
	ctx context.Context,
	parent *os.File,
	basename string,
	expected SourceFingerprint,
	limit int64,
	ordinal int,
) error {
	file, current, err := openFingerprintAt(ctx, parent, basename, limit)
	if err != nil {
		return err
	}
	defer file.Close()
	if !sameFingerprintContent(expected, current, false) {
		return fmt.Errorf("%w: cleanup entry is not the retained source", ErrSourceChanged)
	}
	return manager.scrubAndRemoveOpen(parent, basename, file, current.Identity, ordinal)
}

func (manager *TransactionManager) removeOwnedIdentityAt(parent *os.File, basename string, expected FileIdentity, ordinal int) error {
	fd, err := unix.Openat(int(parent.Fd()), basename, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), basename)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("retain native cleanup source")
	}
	defer file.Close()
	stat, err := fstat(fd)
	if err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 {
		return errors.New("native cleanup source metadata is invalid")
	}
	current := identityFromStat(stat)
	if !samePlacement(expected, current) {
		return fmt.Errorf("%w: cleanup entry is not the retained source", ErrSourceChanged)
	}
	return manager.scrubAndRemoveOpen(parent, basename, file, current, ordinal)
}

// scrubAndRemoveOpen atomically moves the current directory entry to the
// transaction-bound cleanup name, verifies that it is the inode retained by
// the caller, and only then destroys confidential bytes through that inode-
// bound descriptor. A pre-move substitution is preserved and reported instead
// of unlinked. The final unlink operates only on the
// freshly-verified quarantine entry; uncooperative writers sharing the
// service UID remain inside the documented service-UID trust boundary.
func (manager *TransactionManager) scrubAndRemoveOpen(parent *os.File, basename string, file *os.File, expected FileIdentity, ordinal int) error {
	quarantine := cleanupBasename(basename)
	if filepath.Ext(basename) == ".remove" {
		quarantine = basename
	} else if err := unix.Renameat2(
		int(parent.Fd()), basename,
		int(parent.Fd()), quarantine,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("quarantine native cleanup source: %w", err)
	} else if err := manager.inject(FailureAfterCleanupRename, ordinal); err != nil {
		return err
	}
	placed, exists, err := identityAt(parent, quarantine)
	if err != nil || !exists || placed.Device != expected.Device || placed.Inode != expected.Inode {
		if quarantine != basename {
			_ = unix.Renameat2(int(parent.Fd()), quarantine, int(parent.Fd()), basename, unix.RENAME_NOREPLACE)
		}
		return fmt.Errorf("%w: cleanup entry changed during quarantine", ErrSourceChanged)
	}
	// Destruction starts only after the atomic move proved that the quarantined
	// name and retained descriptor still identify the reviewed inode.
	scrubbed, err := scrubOpenFile(file)
	if err != nil {
		return err
	}
	if scrubbed.Device != expected.Device || scrubbed.Inode != expected.Inode {
		return fmt.Errorf("%w: retained cleanup descriptor changed", ErrSourceChanged)
	}
	if err := manager.inject(FailureAfterCleanupScrub, ordinal); err != nil {
		return err
	}
	placed, exists, err = identityAt(parent, quarantine)
	if err != nil || !exists || placed.Device != scrubbed.Device || placed.Inode != scrubbed.Inode || placed.Size != 0 {
		return fmt.Errorf("%w: cleanup entry changed after quarantine", ErrSourceChanged)
	}
	if err := unix.Unlinkat(int(parent.Fd()), quarantine, 0); err != nil {
		return fmt.Errorf("remove quarantined native source: %w", err)
	}
	if err := manager.inject(FailureAfterCleanupUnlink, ordinal); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func scrubOpenFile(file *os.File) (FileIdentity, error) {
	if file == nil {
		return FileIdentity{}, errors.New("native cleanup source is unavailable")
	}
	if err := unix.Fchmod(int(file.Fd()), 0o600); err != nil {
		return FileIdentity{}, fmt.Errorf("make native cleanup source writable: %w", err)
	}
	writerFD, err := unix.Open(
		"/proc/self/fd/"+strconv.FormatUint(uint64(file.Fd()), 10),
		unix.O_WRONLY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return FileIdentity{}, fmt.Errorf("open retained native cleanup source for scrubbing: %w", err)
	}
	defer unix.Close(writerFD)
	if err := unix.Ftruncate(writerFD, 0); err != nil {
		return FileIdentity{}, fmt.Errorf("truncate native cleanup source: %w", err)
	}
	if err := unix.Fsync(writerFD); err != nil {
		return FileIdentity{}, fmt.Errorf("synchronize scrubbed native cleanup source: %w", err)
	}
	stat, err := fstat(writerFD)
	if err != nil {
		return FileIdentity{}, err
	}
	return identityFromStat(stat), nil
}

func sameFingerprintContent(expected, current SourceFingerprint, compareTimes bool) bool {
	return sameFileIdentity(expected.Identity, current.Identity, compareTimes) && expected.SHA256 == current.SHA256
}

func sha256Bytes(contents []byte) [32]byte { return sha256.Sum256(contents) }

func syncDirectory(directory *os.File) error {
	if directory == nil {
		return errors.New("directory is unavailable")
	}
	return unix.Fsync(int(directory.Fd()))
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) != 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}

func pathEvidenceForSource(review Review, path string) PathEvidence {
	return pathEvidenceForPath(review, path)
}

func pathEvidenceForPath(review Review, path string) PathEvidence {
	for _, evidence := range review.AllPaths() {
		if evidence.Path == path {
			return evidence
		}
	}
	return PathEvidence{}
}

func sourceLimit(role PathRole) int64 { return maximumFileLimit(role) }

func maximumFileLimit(role PathRole) int64 {
	if role == RoleConfiguration {
		return maximumConfigurationBytes
	}
	return maximumDotenvBytes
}
