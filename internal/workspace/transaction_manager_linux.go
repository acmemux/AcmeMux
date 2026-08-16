//go:build linux

package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"syscall"
	"time"
)

// TransactionManager owns verified native source reads, candidate reference
// audits, journaled replacement, and explicit recovery.
type TransactionManager struct {
	inspector   *Inspector
	selections  *Store
	journal     *JournalStore
	coordinator *Coordinator
	now         func() time.Time
	injector    FailureInjector
	timeout     time.Duration
}

// NewTransactionManager constructs the one native workspace transaction
// boundary. All dependencies must refer to the same service and state store.
func NewTransactionManager(
	inspector *Inspector,
	selections *Store,
	journal *JournalStore,
	coordinator *Coordinator,
	options ...TransactionOption,
) (*TransactionManager, error) {
	if inspector == nil || selections == nil || journal == nil || coordinator == nil {
		return nil, errors.New("native edit transaction dependencies are required")
	}
	configuration := transactionOptions{now: time.Now, timeout: maximumTransactionTime}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("native edit transaction option is nil")
		}
		if err := option(&configuration); err != nil {
			return nil, err
		}
	}
	return &TransactionManager{
		inspector: inspector, selections: selections, journal: journal, coordinator: coordinator,
		now: configuration.now, injector: configuration.injector, timeout: configuration.timeout,
	}, nil
}

func (manager *TransactionManager) boundedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, manager.timeout)
}

// Snapshot reads the exact adopted YAML and dotenv sources under a valid
// shared workspace lease. A pending journal blocks all ordinary access.
func (manager *TransactionManager) Snapshot(ctx context.Context, lease *Lease) (*SourceSet, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return nil, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	if _, err := manager.journal.Load(ctx); err == nil {
		return nil, ErrRecoveryRequired
	} else if !errors.Is(err, ErrNoEditJournal) {
		return nil, fmt.Errorf("inspect native edit recovery state: %w", err)
	}
	selection, err := manager.selections.Load(ctx)
	if err != nil {
		return nil, err
	}
	return manager.snapshotSelection(ctx, selection)
}

func (manager *TransactionManager) snapshotSelection(ctx context.Context, selection Selection) (*SourceSet, error) {
	current, err := manager.inspector.Verify(ctx, selection.Review)
	if err != nil {
		return nil, fmt.Errorf("%w: workspace evidence", ErrSourceChanged)
	}
	sources := &SourceSet{}
	complete := false
	defer func() {
		if !complete {
			sources.Close()
		}
	}()
	configuration, err := manager.readSource(ctx, current.Configuration, manager.inspector.policy.MaxConfigurationBytes)
	if err != nil {
		return nil, err
	}
	sources.Configuration = configuration
	for _, evidence := range current.DotenvFiles {
		file, readErr := manager.readSource(ctx, evidence, maximumDotenvBytes)
		if readErr != nil {
			err = readErr
			return nil, readErr
		}
		sources.Dotenv = append(sources.Dotenv, file)
	}
	confirmed, err := manager.inspector.Verify(ctx, current)
	if err != nil {
		return nil, fmt.Errorf("%w: workspace changed after source read", ErrSourceChanged)
	}
	if !samePathEvidence(current.Configuration, confirmed.Configuration) ||
		!samePathEvidenceSlice(current.DotenvFiles, confirmed.DotenvFiles) {
		return nil, fmt.Errorf("%w: source evidence changed after read", ErrSourceChanged)
	}
	reviewedAt := manager.now().UTC()
	if reviewedAt.Before(confirmed.ObservedAt) {
		reviewedAt = confirmed.ObservedAt
	}
	sources.Selection = Selection{Review: confirmed, ReviewedAt: reviewedAt}
	complete = true
	return sources, nil
}

func (manager *TransactionManager) readSource(ctx context.Context, reviewed PathEvidence, limit int64) (SourceFile, error) {
	requirements := pathRequirements{
		expected: PathTypeRegular, confidential: true, requireRead: true,
		requireParentSwap: true, readHandle: true,
	}
	audited := auditPath(ctx, reviewed.Path, reviewed.Role, reviewed.Reference, requirements, manager.inspector.policy)
	if audited.file != nil {
		defer audited.file.Close()
	}
	if !audited.evidence.Safe || hasBlockingDiagnostics(audited.diagnostics) ||
		!samePathEvidence(reviewed, audited.evidence) || audited.file == nil {
		return SourceFile{}, fmt.Errorf("%w: %s source evidence", ErrSourceChanged, reviewed.Role)
	}
	before, err := fstat(int(audited.file.Fd()))
	if err != nil {
		return SourceFile{}, fmt.Errorf("read %s source metadata", reviewed.Role)
	}
	if _, err := audited.file.Seek(0, io.SeekStart); err != nil {
		return SourceFile{}, fmt.Errorf("read %s source", reviewed.Role)
	}
	reader := io.LimitReader(&contextReader{context: ctx, reader: audited.file}, limit+1)
	contents, err := io.ReadAll(reader)
	if err != nil {
		return SourceFile{}, fmt.Errorf("read %s source", reviewed.Role)
	}
	if int64(len(contents)) > limit {
		clear(contents)
		return SourceFile{}, fmt.Errorf("%w: %s source exceeds its size limit", ErrInvalidEdit, reviewed.Role)
	}
	after, err := fstat(int(audited.file.Fd()))
	if err != nil || !sameStableStat(before, after) || int64(len(contents)) != before.Size {
		clear(contents)
		return SourceFile{}, fmt.Errorf("%w: %s changed while read", ErrSourceChanged, reviewed.Role)
	}
	confirmation := auditPath(ctx, reviewed.Path, reviewed.Role, reviewed.Reference, requirements, manager.inspector.policy)
	if confirmation.file != nil {
		_ = confirmation.file.Close()
	}
	if !samePathEvidence(audited.evidence, confirmation.evidence) {
		clear(contents)
		return SourceFile{}, fmt.Errorf("%w: %s path changed after read", ErrSourceChanged, reviewed.Role)
	}
	return SourceFile{
		Role: reviewed.Role, Path: reviewed.Path, Reference: reviewed.Reference, Content: contents,
		Fingerprint: SourceFingerprint{
			Path: reviewed.Path, Identity: identityFromStat(before), SHA256: sha256.Sum256(contents),
		},
	}, nil
}

// AuditCandidate resolves candidate YAML references and proves that every
// target is already safe or is an exact missing dotenv replacement whose
// parent can create a private regular file.
func (manager *TransactionManager) AuditCandidate(
	ctx context.Context,
	lease *Lease,
	sources *SourceSet,
	candidateConfiguration []byte,
	replacements []Replacement,
) (CandidateAudit, error) {
	if err := manager.ready(ctx, lease); err != nil {
		return CandidateAudit{}, err
	}
	ctx, cancel := manager.boundedContext(ctx)
	defer cancel()
	if sources == nil || sources.closed || sources.Configuration.Path == "" ||
		!sources.Configuration.Fingerprint.Identity.Exists {
		return CandidateAudit{}, fmt.Errorf("%w: source snapshot is unavailable", ErrInvalidEdit)
	}
	if len(candidateConfiguration) == 0 || int64(len(candidateConfiguration)) > manager.inspector.policy.MaxConfigurationBytes {
		return CandidateAudit{}, fmt.Errorf("%w: candidate configuration size is invalid", ErrInvalidEdit)
	}
	replacementMap, err := validateReplacementSet(sources, candidateConfiguration, replacements)
	if err != nil {
		return CandidateAudit{}, err
	}
	references, diagnostics := parseNativeReferences(candidateConfiguration,
		sources.Selection.Review.Configuration.Path,
		sources.Selection.Review.WorkingDirectory.Path,
		manager.inspector.policy,
	)
	if hasBlockingDiagnostics(diagnostics) {
		code := CodeConfigurationMalformed
		if len(diagnostics) != 0 {
			code = diagnostics[0].Code
		}
		return CandidateAudit{}, fmt.Errorf("%w: candidate configuration %s", ErrInvalidEdit, code)
	}
	audit := CandidateAudit{}
	storageRequirements := pathRequirements{
		expected: PathTypeDirectory, requireRead: true, requireWrite: true, requireSearch: true,
	}
	storage := auditPath(ctx, references.storage.resolved, RoleStorage, references.storage.raw, storageRequirements, manager.inspector.policy)
	if err := ctx.Err(); err != nil {
		return CandidateAudit{}, err
	}
	if !storage.evidence.Safe || hasBlockingDiagnostics(storage.diagnostics) {
		return CandidateAudit{}, fmt.Errorf("%w: candidate storage path", ErrInvalidEdit)
	}
	audit.Storage = storage.evidence

	dotenvRequirements := pathRequirements{
		expected: PathTypeRegular, confidential: true, requireRead: true, requireParentSwap: true,
	}
	allowedDotenv := make(map[string]struct{}, len(references.dotenv))
	for _, reference := range references.dotenv {
		allowedDotenv[reference.resolved] = struct{}{}
		pathAudit := auditPath(ctx, reference.resolved, RoleDotenv, reference.raw, dotenvRequirements, manager.inspector.policy)
		if err := ctx.Err(); err != nil {
			return CandidateAudit{}, err
		}
		candidatePath := CandidatePath{
			Role: RoleDotenv, Reference: reference.raw, Path: reference.resolved,
			Evidence: pathAudit.evidence,
		}
		switch {
		case pathAudit.evidence.Exists && pathAudit.evidence.Safe && !hasBlockingDiagnostics(pathAudit.diagnostics):
			reviewedSource, reviewed := sourceForPath(sources, reference.resolved)
			if !reviewed || reviewedSource.Role != RoleDotenv {
				return CandidateAudit{}, fmt.Errorf("%w: referenced dotenv was not part of the reviewed source set", ErrInvalidEdit)
			}
			candidatePath.Exists = true
		case !pathAudit.evidence.Exists:
			replacement, planned := replacementMap[reference.resolved]
			if !planned || replacement.Role != RoleDotenv {
				return CandidateAudit{}, fmt.Errorf("%w: referenced dotenv is missing", ErrInvalidEdit)
			}
			if err := manager.auditCreatableTarget(ctx, reference.resolved); err != nil {
				return CandidateAudit{}, err
			}
			candidatePath.WillCreate = true
		default:
			return CandidateAudit{}, fmt.Errorf("%w: candidate dotenv path", ErrInvalidEdit)
		}
		audit.Dotenv = append(audit.Dotenv, candidatePath)
	}
	for path, replacement := range replacementMap {
		if replacement.Role == RoleDotenv {
			if _, present := allowedDotenv[path]; !present {
				return CandidateAudit{}, fmt.Errorf("%w: dotenv replacement is not referenced by candidate YAML", ErrInvalidEdit)
			}
		}
	}
	webrootRequirements := pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}
	for _, reference := range references.webroots {
		pathAudit := auditPath(ctx, reference.resolved, RoleWebroot, reference.raw, webrootRequirements, manager.inspector.policy)
		if err := ctx.Err(); err != nil {
			return CandidateAudit{}, err
		}
		if !pathAudit.evidence.Safe || hasBlockingDiagnostics(pathAudit.diagnostics) {
			return CandidateAudit{}, fmt.Errorf("%w: candidate webroot path", ErrInvalidEdit)
		}
		audit.Webroots = append(audit.Webroots, pathAudit.evidence)
	}
	return audit, nil
}

func (manager *TransactionManager) auditCreatableTarget(ctx context.Context, target string) error {
	if err := validateSelectedPath(target); err != nil {
		return fmt.Errorf("%w: candidate target path", ErrInvalidEdit)
	}
	parentPath := filepath.Dir(target)
	requirements := pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}
	parent := auditPath(ctx, parentPath, RoleDotenv, "", requirements, manager.inspector.policy)
	if err := ctx.Err(); err != nil {
		return err
	}
	if !parent.evidence.Safe || hasBlockingDiagnostics(parent.diagnostics) {
		return fmt.Errorf("%w: candidate target parent", ErrInvalidEdit)
	}
	// Recheck absence without following a newly introduced final symlink.
	final := auditPath(ctx, target, RoleDotenv, "", pathRequirements{expected: PathTypeRegular}, manager.inspector.policy)
	if err := ctx.Err(); err != nil {
		return err
	}
	if final.evidence.Exists || final.evidence.Type != PathTypeMissing {
		return fmt.Errorf("%w: missing candidate target changed", ErrSourceChanged)
	}
	return nil
}

func validateReplacementSet(sources *SourceSet, candidate []byte, replacements []Replacement) (map[string]Replacement, error) {
	if len(replacements) == 0 || len(replacements) > maximumEditFiles {
		return nil, fmt.Errorf("%w: replacement count is invalid", ErrInvalidEdit)
	}
	result := make(map[string]Replacement, len(replacements))
	configurationSeen := false
	for _, replacement := range replacements {
		if replacement.Role != RoleConfiguration && replacement.Role != RoleDotenv {
			return nil, fmt.Errorf("%w: replacement role is invalid", ErrInvalidEdit)
		}
		if err := validateSelectedPath(replacement.Path); err != nil {
			return nil, fmt.Errorf("%w: replacement target is invalid", ErrInvalidEdit)
		}
		if source, exists := sourceForPath(sources, replacement.Path); exists && source.Role != replacement.Role {
			return nil, fmt.Errorf("%w: replacement role disagrees with the reviewed source", ErrInvalidEdit)
		}
		limit := maximumDotenvBytes
		if replacement.Role == RoleConfiguration {
			if len(replacement.Content) == 0 {
				return nil, fmt.Errorf("%w: configuration replacement is empty", ErrInvalidEdit)
			}
			configurationSeen = true
			limit = maximumConfigurationBytes
			if replacement.Path != sources.Configuration.Path || !bytes.Equal(replacement.Content, candidate) {
				return nil, fmt.Errorf("%w: configuration replacement disagrees with candidate", ErrInvalidEdit)
			}
		}
		if int64(len(replacement.Content)) > limit {
			return nil, fmt.Errorf("%w: replacement exceeds its size limit", ErrInvalidEdit)
		}
		if _, duplicate := result[replacement.Path]; duplicate {
			return nil, fmt.Errorf("%w: replacement target is duplicated", ErrInvalidEdit)
		}
		result[replacement.Path] = replacement
	}
	configurationChanged := !bytes.Equal(candidate, sources.Configuration.Content)
	if configurationChanged != configurationSeen {
		return nil, fmt.Errorf("%w: candidate configuration replacement is inconsistent", ErrInvalidEdit)
	}
	return result, nil
}

func (manager *TransactionManager) ready(ctx context.Context, lease *Lease) error {
	if manager == nil || manager.inspector == nil || manager.selections == nil || manager.journal == nil || manager.coordinator == nil {
		return errors.New("native edit transaction manager is not initialized")
	}
	if ctx == nil {
		return errors.New("native edit transaction context is required")
	}
	if !manager.coordinator.owns(lease) {
		return errors.New("valid native workspace lease is required")
	}
	return ctx.Err()
}

func identityFromStat(stat syscall.Stat_t) FileIdentity {
	return FileIdentity{
		Exists: true, Device: stat.Dev, Inode: stat.Ino, Mode: stat.Mode,
		UID: stat.Uid, GID: stat.Gid, NLink: stat.Nlink, Size: stat.Size,
		ModifiedAt: time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC(),
		ChangedAt:  time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec).UTC(),
	}
}

func sameFileIdentity(left, right FileIdentity, compareTimes bool) bool {
	if left.Exists != right.Exists || left.Device != right.Device || left.Inode != right.Inode ||
		left.Mode != right.Mode || left.UID != right.UID || left.GID != right.GID ||
		left.NLink != right.NLink || left.Size != right.Size {
		return false
	}
	return !compareTimes || left.ModifiedAt.Equal(right.ModifiedAt) && left.ChangedAt.Equal(right.ChangedAt)
}

func sameSourceFingerprint(left, right SourceFingerprint) bool {
	return left.Path == right.Path && sameFileIdentity(left.Identity, right.Identity, true) && left.SHA256 == right.SHA256
}

func sortReplacements(values []Replacement) {
	sort.Slice(values, func(left, right int) bool {
		if values[left].Role != values[right].Role {
			return values[left].Role == RoleDotenv
		}
		return values[left].Path < values[right].Path
	})
}

func clearReplacements(values []Replacement) {
	for index := range values {
		clear(values[index].Content)
		values[index].Content = nil
	}
}

func cloneReplacements(values []Replacement) []Replacement {
	result := make([]Replacement, len(values))
	for index, value := range values {
		result[index] = cloneReplacement(value)
	}
	return result
}

func sourceForPath(sources *SourceSet, path string) (SourceFile, bool) {
	if sources.Configuration.Path == path {
		return sources.Configuration, true
	}
	index := slices.IndexFunc(sources.Dotenv, func(source SourceFile) bool { return source.Path == path })
	if index < 0 {
		return SourceFile{}, false
	}
	return sources.Dotenv[index], true
}
