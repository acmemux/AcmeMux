//go:build linux

package workspace

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"path/filepath"
)

// ExternalFile is a bounded, no-follow snapshot of a cloud credential source.
// Callers own Content and must clear it as soon as the operation plan closes.
type ExternalFile struct {
	Evidence    PathEvidence
	Content     []byte
	Fingerprint SourceFingerprint
}

func (file *ExternalFile) Close() {
	if file == nil {
		return
	}
	clear(file.Content)
	file.Content = nil
	file.Fingerprint = SourceFingerprint{}
}

// ReadExternalCredential snapshots one explicitly selected confidential file
// under the same owner, traversal, hard-link, and permission rules as native
// dotenv credentials. It never follows a symbolic link.
func (inspector *Inspector) ReadExternalCredential(ctx context.Context, path string, limit int64) (ExternalFile, error) {
	if inspector == nil || ctx == nil || limit <= 0 || limit > maximumConfigurationBytes {
		return ExternalFile{}, &Error{Code: CodeInvalidPolicy, Detail: "external credential inspection is invalid"}
	}
	if err := validateSelectedPath(path); err != nil {
		return ExternalFile{}, err
	}
	requirements := pathRequirements{expected: PathTypeRegular, confidential: true, requireRead: true, readHandle: true}
	audited := auditPath(ctx, path, RoleCloudCredential, "", requirements, inspector.policy)
	if audited.file != nil {
		defer audited.file.Close()
	}
	if !audited.evidence.Safe || hasBlockingDiagnostics(audited.diagnostics) || audited.file == nil {
		return ExternalFile{}, fmt.Errorf("%w: cloud credential source", ErrSourceChanged)
	}
	before, err := fstat(int(audited.file.Fd()))
	if err != nil {
		return ExternalFile{}, fmt.Errorf("%w: cloud credential metadata", ErrSourceChanged)
	}
	if _, err := audited.file.Seek(0, io.SeekStart); err != nil {
		return ExternalFile{}, fmt.Errorf("%w: cloud credential read", ErrSourceChanged)
	}
	content, err := io.ReadAll(io.LimitReader(&contextReader{context: ctx, reader: audited.file}, limit+1))
	if err != nil || int64(len(content)) > limit {
		clear(content)
		return ExternalFile{}, fmt.Errorf("%w: cloud credential size", ErrSourceChanged)
	}
	after, err := fstat(int(audited.file.Fd()))
	if err != nil || !sameStableStat(before, after) || int64(len(content)) != before.Size {
		clear(content)
		return ExternalFile{}, fmt.Errorf("%w: cloud credential changed", ErrSourceChanged)
	}
	confirmation := auditPath(ctx, path, RoleCloudCredential, "", requirements, inspector.policy)
	if confirmation.file != nil {
		_ = confirmation.file.Close()
	}
	if !samePathEvidence(audited.evidence, confirmation.evidence) {
		clear(content)
		return ExternalFile{}, fmt.Errorf("%w: cloud credential path changed", ErrSourceChanged)
	}
	return ExternalFile{Evidence: audited.evidence, Content: content, Fingerprint: SourceFingerprint{
		Path: path, Identity: identityFromStat(before), SHA256: sha256.Sum256(content),
	}}, nil
}

// AuditExternalDirectory verifies an explicitly selected cloud cache or token
// directory without granting write access or discovering a default HOME.
func (inspector *Inspector) AuditExternalDirectory(ctx context.Context, path string) (PathEvidence, error) {
	if inspector == nil || ctx == nil {
		return PathEvidence{}, &Error{Code: CodeContextRequired}
	}
	if err := validateSelectedPath(path); err != nil {
		return PathEvidence{}, err
	}
	requirements := pathRequirements{expected: PathTypeDirectory, requireRead: true, requireSearch: true}
	audited := auditPath(ctx, path, RoleCloudDirectory, "", requirements, inspector.policy)
	if !audited.evidence.Safe || hasBlockingDiagnostics(audited.diagnostics) {
		return PathEvidence{}, fmt.Errorf("%w: cloud directory", ErrSourceChanged)
	}
	var diagnostics []Diagnostic
	confirmed := inspector.confirmPath(ctx, audited, requirements, &diagnostics)
	if !confirmed.Safe {
		return PathEvidence{}, fmt.Errorf("%w: cloud directory changed", ErrSourceChanged)
	}
	return confirmed, nil
}

// AuditExternalExecutable verifies the exact helper selected through a
// single-directory PATH. Group/other-writable helpers and traversal are denied.
func (inspector *Inspector) AuditExternalExecutable(ctx context.Context, path string) (PathEvidence, error) {
	if inspector == nil || ctx == nil {
		return PathEvidence{}, &Error{Code: CodeContextRequired}
	}
	if err := validateSelectedPath(path); err != nil {
		return PathEvidence{}, err
	}
	if filepath.Base(path) == string(filepath.Separator) {
		return PathEvidence{}, &Error{Code: CodePathRequired}
	}
	requirements := pathRequirements{expected: PathTypeRegular, requireRead: true}
	audited := auditPath(ctx, path, RoleCloudHelper, "", requirements, inspector.policy)
	if !audited.evidence.Safe || hasBlockingDiagnostics(audited.diagnostics) || !serviceCanExecute(audited.evidence, inspector.policy) {
		return PathEvidence{}, fmt.Errorf("%w: cloud helper", ErrSourceChanged)
	}
	var diagnostics []Diagnostic
	confirmed := inspector.confirmPath(ctx, audited, requirements, &diagnostics)
	if !confirmed.Safe || !serviceCanExecute(confirmed, inspector.policy) {
		return PathEvidence{}, fmt.Errorf("%w: cloud helper changed", ErrSourceChanged)
	}
	return confirmed, nil
}

func serviceCanExecute(evidence PathEvidence, policy Policy) bool {
	permissions := evidence.Mode & 0o777
	bits := uint32(permissions & 0o007)
	if evidence.UID == policy.EffectiveUID {
		bits = uint32((permissions >> 6) & 0o7)
	} else {
		for _, gid := range policy.EffectiveGIDs {
			if evidence.GID == gid {
				bits = uint32((permissions >> 3) & 0o7)
				break
			}
		}
	}
	return bits&0o1 != 0
}
