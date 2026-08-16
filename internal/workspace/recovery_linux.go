//go:build linux

package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// InspectRecovery classifies every durable journal target without modifying
// or replaying any native file.
func (manager *TransactionManager) InspectRecovery(ctx context.Context, lease *Lease) (Recovery, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return Recovery{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	journal, err := manager.journal.Load(ctx)
	if err != nil {
		return Recovery{}, err
	}
	recovery := Recovery{
		TransactionID: journal.TransactionID, WorkingDirectory: journal.WorkingDirectory,
		ConfigurationPath: journal.ConfigurationPath, Phase: journal.Phase,
	}
	applied, unapplied, ambiguous := 0, 0, 0
	for _, file := range journal.Files {
		state := manager.classifyRecoveryFile(ctx, file)
		recovery.Files = append(recovery.Files, RecoveryFile{
			Ordinal: file.Ordinal, Role: file.Role, Path: file.TargetPath, State: state,
		})
		switch state {
		case RecoveryFileApplied:
			applied++
		case RecoveryFileUnapplied, RecoveryFileUnstaged:
			unapplied++
		default:
			ambiguous++
		}
	}
	switch {
	case ambiguous != 0:
		recovery.State = RecoveryAmbiguous
	case applied == len(recovery.Files):
		recovery.State = RecoveryApplied
	case unapplied == len(recovery.Files):
		recovery.State = RecoveryUnapplied
	default:
		recovery.State = RecoveryPartial
	}
	return recovery, nil
}

func (manager *TransactionManager) classifyRecoveryFile(ctx context.Context, file JournalFile) RecoveryFileState {
	if err := ctx.Err(); err != nil {
		return RecoveryFileAmbiguous
	}
	parent, parentID, err := manager.openReplacementParent(ctx, file.TargetPath)
	if err != nil {
		return RecoveryFileAmbiguous
	}
	defer parent.Close()
	if parentID.Device != file.Parent.Device || parentID.Inode != file.Parent.Inode {
		return RecoveryFileAmbiguous
	}
	target, targetExists, targetErr := identityAt(parent, filepath.Base(file.TargetPath))
	stageBasename, stageExists, stageErr := ownedStageBasename(parent, file.StageBasename)
	stage := FileIdentity{}
	if stageErr == nil && stageExists {
		stage, stageExists, stageErr = identityAt(parent, stageBasename)
	}
	if targetErr != nil || stageErr != nil {
		return RecoveryFileAmbiguous
	}
	// The cleanup quarantine is a durable crash boundary, not an ordinary
	// staged placement. It may already have been scrubbed and its rename can
	// change ctime, so only explicit current-file adoption after host review
	// may clear it.
	if stageExists && stageBasename == cleanupBasename(file.StageBasename) {
		return RecoveryFileAmbiguous
	}
	if !file.CandidateReady {
		if !stageExists && originalPlacement(file.Original, target, targetExists) && !file.Applied {
			return RecoveryFileUnstaged
		}
		return RecoveryFileAmbiguous
	}
	targetCandidate := targetExists && samePlacement(file.Candidate, target)
	stageCandidate := stageExists && samePlacement(file.Candidate, stage)
	targetOriginal := originalPlacement(file.Original, target, targetExists)
	stageOriginal := file.Original.Exists && stageExists && samePlacement(file.Original, stage)
	if targetOriginal && !stageExists && !file.Applied {
		return RecoveryFileUnstaged
	}
	if targetCandidate && !stageCandidate && (!stageExists || stageOriginal) {
		return RecoveryFileApplied
	}
	if targetOriginal && stageCandidate && !file.Applied {
		return RecoveryFileUnapplied
	}
	return RecoveryFileAmbiguous
}

// ResolveRecovery applies an explicit non-replay resolution. Applied or
// repaired current files must pass the caller's native validation again.
func (manager *TransactionManager) ResolveRecovery(
	ctx context.Context,
	lease *Lease,
	resolution RecoveryResolution,
	guard CommitGuard,
	validator RecoveryValidator,
) (Selection, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return Selection{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	if guard == nil {
		return Selection{}, fmt.Errorf("%w: recovery commit guard is required", ErrInvalidEdit)
	}
	recovery, err := manager.InspectRecovery(ctx, lease)
	if err != nil {
		return Selection{}, err
	}
	journal, err := manager.journal.Load(ctx)
	if err != nil || journal.TransactionID != recovery.TransactionID {
		return Selection{}, fmt.Errorf("%w: recovery journal changed", ErrSourceChanged)
	}
	switch resolution {
	case ResolutionDiscardUnapplied:
		if recovery.State != RecoveryUnapplied {
			return Selection{}, fmt.Errorf("%w: only a wholly unapplied edit can be discarded", ErrInvalidEdit)
		}
		selection, err := manager.selections.Load(ctx)
		if err != nil {
			return Selection{}, err
		}
		if _, err := manager.inspector.Verify(ctx, selection.Review); err != nil {
			return Selection{}, fmt.Errorf("%w: active workspace changed before discard", ErrSourceChanged)
		}
		if err := guard(ctx); err != nil {
			return Selection{}, err
		}
		if err := manager.removeRecoveryStages(ctx, journal, false); err != nil {
			return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, err)
		}
		if _, err := manager.inspector.Verify(ctx, selection.Review); err != nil {
			return Selection{}, fmt.Errorf("%w: active workspace changed during discard", ErrSourceChanged)
		}
		if err := manager.journal.Clear(ctx, journal.TransactionID); err != nil {
			return Selection{}, fmt.Errorf("%w: clear discarded edit", ErrRecoveryRequired)
		}
		return selection, nil
	case ResolutionFinalizeApplied:
		if recovery.State != RecoveryApplied {
			return Selection{}, fmt.Errorf("%w: edit is not wholly applied", ErrInvalidEdit)
		}
	case ResolutionAdoptCurrent:
		// Explicitly accepts a current set repaired outside AcmeMux; it never
		// moves an unapplied stage into an active path.
		if recovery.State != RecoveryApplied && recovery.State != RecoveryPartial && recovery.State != RecoveryAmbiguous {
			return Selection{}, fmt.Errorf("%w: only an applied, partial, or ambiguous edit can adopt current files", ErrInvalidEdit)
		}
	default:
		return Selection{}, fmt.Errorf("%w: recovery resolution is unknown", ErrInvalidEdit)
	}
	if validator == nil {
		return Selection{}, fmt.Errorf("%w: recovery validator is required", ErrInvalidEdit)
	}
	validated, sources, err := manager.readRecoveryCurrent(ctx, journal)
	if err != nil {
		return Selection{}, err
	}
	defer sources.Close()
	prior, err := manager.selections.Load(ctx)
	if err != nil {
		return Selection{}, err
	}
	if resolution == ResolutionFinalizeApplied && !samePreEditRecoveryBoundary(prior.Review, validated.Review, journal) {
		return Selection{}, fmt.Errorf("%w: current workspace differs from the pre-edit review", ErrSourceChanged)
	}
	if err := validator(ctx, sources); err != nil {
		return Selection{}, err
	}
	confirmed, confirmedSources, err := manager.readRecoveryCurrent(ctx, journal)
	if err != nil {
		return Selection{}, err
	}
	if !sameSourceSets(sources, confirmedSources) {
		confirmedSources.Close()
		return Selection{}, fmt.Errorf("%w: active files changed after recovery validation", ErrSourceChanged)
	}
	confirmedSources.Close()
	validated = confirmed
	if err := guard(ctx); err != nil {
		return Selection{}, err
	}
	if resolution == ResolutionFinalizeApplied {
		freshRecovery, err := manager.InspectRecovery(ctx, lease)
		if err != nil || freshRecovery.TransactionID != journal.TransactionID || freshRecovery.State != RecoveryApplied {
			return Selection{}, fmt.Errorf("%w: applied recovery placement changed before finalization", ErrSourceChanged)
		}
	}
	freshJournal, err := manager.journal.Load(ctx)
	if err != nil || freshJournal.TransactionID != journal.TransactionID {
		return Selection{}, fmt.Errorf("%w: recovery journal changed before finalization", ErrSourceChanged)
	}
	guardedSelection, guardedSources, err := manager.readRecoveryCurrent(ctx, journal)
	if err != nil {
		return Selection{}, err
	}
	if !sameSourceSets(sources, guardedSources) {
		guardedSources.Close()
		return Selection{}, fmt.Errorf("%w: active files changed during recovery authorization", ErrSourceChanged)
	}
	guardedSources.Close()
	validated = guardedSelection
	if resolution == ResolutionFinalizeApplied && !samePreEditRecoveryBoundary(prior.Review, guardedSelection.Review, journal) {
		return Selection{}, fmt.Errorf("%w: pre-edit workspace boundary changed during recovery authorization", ErrSourceChanged)
	}
	if err := manager.removeRecoveryStages(ctx, journal, true); err != nil {
		return Selection{}, fmt.Errorf("%w: %w", ErrRecoveryRequired, err)
	}
	finalSelection, finalSources, err := manager.readRecoveryCurrent(ctx, journal)
	if err != nil {
		return Selection{}, err
	}
	if !sameSourceSets(sources, finalSources) {
		finalSources.Close()
		return Selection{}, fmt.Errorf("%w: active files changed during recovery cleanup", ErrSourceChanged)
	}
	finalSources.Close()
	validated = finalSelection
	if resolution == ResolutionFinalizeApplied && !samePreEditRecoveryBoundary(prior.Review, finalSelection.Review, journal) {
		return Selection{}, fmt.Errorf("%w: pre-edit workspace boundary changed during recovery cleanup", ErrSourceChanged)
	}
	if err := manager.selections.FinalizeEdit(ctx, validated, journal.TransactionID); err != nil {
		return Selection{}, fmt.Errorf("%w: finalize recovered workspace", ErrRecoveryRequired)
	}
	return validated, nil
}

// samePreEditRecoveryBoundary lets FinalizeApplied accept only the exact
// source targets named by the durable journal as changed. Every other reviewed
// filesystem object remains bound to the selection that existed before the
// edit. A candidate that intentionally changes storage, webroots, or source
// membership must use the explicit AdoptCurrent path after fresh review.
func samePreEditRecoveryBoundary(prior, current Review, journal Journal) bool {
	if prior.ConfigurationSource != current.ConfigurationSource ||
		!samePathPlacementEvidence(prior.WorkingDirectory, current.WorkingDirectory) ||
		!samePathPlacementEvidence(prior.Storage, current.Storage) ||
		!samePathPlacementEvidenceSlice(prior.Webroots, current.Webroots) {
		return false
	}
	targets := make(map[string]struct{}, len(journal.Files))
	for _, file := range journal.Files {
		targets[file.TargetPath] = struct{}{}
	}
	if !sameRecoveryPathUnlessTargeted(prior.Configuration, current.Configuration, targets) {
		return false
	}
	priorDotenv := make(map[string]PathEvidence, len(prior.DotenvFiles))
	for _, evidence := range prior.DotenvFiles {
		priorDotenv[evidence.Path] = evidence
	}
	currentDotenv := make(map[string]PathEvidence, len(current.DotenvFiles))
	for _, evidence := range current.DotenvFiles {
		currentDotenv[evidence.Path] = evidence
	}
	for path, evidence := range priorDotenv {
		currentEvidence, exists := currentDotenv[path]
		if _, targeted := targets[path]; targeted {
			if exists && !samePathAncestorEvidence(evidence, currentEvidence) {
				return false
			}
			continue
		}
		if !exists || !samePathPlacementEvidence(evidence, currentEvidence) {
			return false
		}
	}
	for path, evidence := range currentDotenv {
		priorEvidence, exists := priorDotenv[path]
		if _, targeted := targets[path]; targeted {
			if exists && !samePathAncestorEvidence(priorEvidence, evidence) {
				return false
			}
			continue
		}
		if !exists || !samePathPlacementEvidence(priorEvidence, evidence) {
			return false
		}
	}
	return true
}

func sameRecoveryPathUnlessTargeted(prior, current PathEvidence, targets map[string]struct{}) bool {
	if prior.Path != current.Path {
		return false
	}
	if _, targeted := targets[prior.Path]; targeted {
		return samePathAncestorEvidence(prior, current)
	}
	return samePathPlacementEvidence(prior, current)
}

func (manager *TransactionManager) readRecoveryCurrent(ctx context.Context, journal Journal) (Selection, *SourceSet, error) {
	prior, err := manager.selections.Load(ctx)
	if err != nil {
		return Selection{}, nil, err
	}
	request := Request{WorkingDirectory: journal.WorkingDirectory}
	if prior.Review.ConfigurationSource == ConfigurationExplicit {
		request.ConfigurationPath = journal.ConfigurationPath
	}
	review, err := manager.inspector.Inspect(ctx, request)
	if err != nil || !review.Adoptable || review.Configuration.Path != journal.ConfigurationPath {
		return Selection{}, nil, fmt.Errorf("%w: current recovery workspace is not safely adoptable", ErrRecoveryRequired)
	}
	reviewedAt := manager.now().UTC()
	if reviewedAt.Before(review.ObservedAt) {
		reviewedAt = review.ObservedAt
	}
	selection := Selection{Review: review, ReviewedAt: reviewedAt}
	sources, err := manager.snapshotSelection(ctx, selection)
	if err != nil {
		return Selection{}, nil, err
	}
	return selection, sources, nil
}

func (manager *TransactionManager) removeRecoveryStages(ctx context.Context, journal Journal, allowOriginal bool) error {
	for _, file := range journal.Files {
		if err := ctx.Err(); err != nil {
			return err
		}
		parent, parentID, err := manager.openReplacementParent(ctx, file.TargetPath)
		if err != nil {
			return err
		}
		if parentID.Device != file.Parent.Device || parentID.Inode != file.Parent.Inode {
			_ = parent.Close()
			return fmt.Errorf("%w: recovery parent changed", ErrSourceChanged)
		}
		stageBasename, exists, err := ownedStageBasename(parent, file.StageBasename)
		stage := FileIdentity{}
		if err == nil && exists {
			stage, exists, err = identityAt(parent, stageBasename)
		}
		if err != nil {
			_ = parent.Close()
			return err
		}
		if exists {
			candidate := file.CandidateReady && samePlacement(file.Candidate, stage)
			original := allowOriginal && file.Original.Exists && samePlacement(file.Original, stage)
			if !candidate && !original {
				_ = parent.Close()
				return fmt.Errorf("%w: recovery staging file is unrecognized", ErrSourceChanged)
			}
			expected := file.Candidate
			if original {
				expected = file.Original
			}
			if err := manager.removeOwnedIdentityAt(parent, stageBasename, expected, file.Ordinal); err != nil {
				_ = parent.Close()
				return err
			}
		}
		// Synchronize even when the staging entry is absent. A journal can
		// represent an earlier cleanup whose directory synchronization failed.
		if err := syncDirectory(parent); err != nil {
			_ = parent.Close()
			return err
		}
		if err := parent.Close(); err != nil {
			return err
		}
	}
	return nil
}

func identityAt(parent *os.File, basename string) (FileIdentity, bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), basename, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return FileIdentity{}, false, nil
	}
	if err != nil {
		return FileIdentity{}, false, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Nlink != 1 {
		return FileIdentity{}, true, errors.New("recovery path is not a single-link regular file")
	}
	return FileIdentity{
		Exists: true, Device: stat.Dev, Inode: stat.Ino, Mode: stat.Mode,
		UID: stat.Uid, GID: stat.Gid, NLink: stat.Nlink, Size: stat.Size,
		ModifiedAt: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC(),
		ChangedAt:  time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC(),
	}, true, nil
}

func originalPlacement(original, current FileIdentity, currentExists bool) bool {
	if !original.Exists {
		return !currentExists
	}
	return currentExists && samePlacement(original, current)
}

func samePlacement(expected, current FileIdentity) bool {
	return expected.Exists && current.Exists && expected.Device == current.Device && expected.Inode == current.Inode &&
		expected.Mode == current.Mode && expected.UID == current.UID && expected.GID == current.GID &&
		expected.NLink == current.NLink && expected.Size == current.Size &&
		expected.ModifiedAt.Equal(current.ModifiedAt) && expected.ChangedAt.Equal(current.ChangedAt)
}

func sameSourceSets(left, right *SourceSet) bool {
	if left == nil || right == nil || len(left.Dotenv) != len(right.Dotenv) ||
		ReviewFingerprint(left.Selection.Review) != ReviewFingerprint(right.Selection.Review) ||
		!sameSourceFingerprint(left.Configuration.Fingerprint, right.Configuration.Fingerprint) {
		return false
	}
	for index := range left.Dotenv {
		if !sameSourceFingerprint(left.Dotenv[index].Fingerprint, right.Dotenv[index].Fingerprint) {
			return false
		}
	}
	return true
}
