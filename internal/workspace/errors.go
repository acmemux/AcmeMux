package workspace

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCode is a stable, non-secret workspace diagnostic classification.
type ErrorCode string

const (
	CodeInvalidPolicy                 ErrorCode = "invalid_policy"
	CodeContextRequired               ErrorCode = "context_required"
	CodePathRequired                  ErrorCode = "path_required"
	CodePathNotAbsolute               ErrorCode = "path_not_absolute"
	CodePathNotCanonical              ErrorCode = "path_not_canonical"
	CodePathTooLong                   ErrorCode = "path_too_long"
	CodePathTooDeep                   ErrorCode = "path_too_deep"
	CodePathMissing                   ErrorCode = "path_missing"
	CodePathUnavailable               ErrorCode = "path_unavailable"
	CodeSymlinkNotAllowed             ErrorCode = "symlink_not_allowed"
	CodeComponentNotDirectory         ErrorCode = "component_not_directory"
	CodePathTypeUnsafe                ErrorCode = "path_type_unsafe"
	CodePathOwnerUntrusted            ErrorCode = "path_owner_untrusted"
	CodePathPermissionsUnsafe         ErrorCode = "path_permissions_unsafe"
	CodePathHardlinkUnsafe            ErrorCode = "path_hardlink_unsafe"
	CodePathNotReadable               ErrorCode = "path_not_readable"
	CodePathReadOnly                  ErrorCode = "path_read_only"
	CodePathNotSearchable             ErrorCode = "path_not_searchable"
	CodeConfigurationMissing          ErrorCode = "configuration_missing"
	CodeConfigurationPrecedence       ErrorCode = "configuration_precedence"
	CodeConfigurationTooLarge         ErrorCode = "configuration_too_large"
	CodeConfigurationMalformed        ErrorCode = "configuration_malformed"
	CodeConfigurationDuplicateKey     ErrorCode = "configuration_duplicate_key"
	CodeConfigurationTooComplex       ErrorCode = "configuration_too_complex"
	CodeConfigurationReferenceInvalid ErrorCode = "configuration_reference_invalid"
	CodeChangedDuringInspection       ErrorCode = "changed_during_inspection"
	CodeInspectionCanceled            ErrorCode = "inspection_canceled"
	CodeReviewEvidenceChanged         ErrorCode = "review_evidence_changed"
	CodeReviewEvidenceLimit           ErrorCode = "review_evidence_limit"
)

// Error reports a bounded workspace inspection failure.
type Error struct {
	Code   ErrorCode
	Path   string
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := string(e.Code)
	if e.Path != "" {
		message += ": " + e.Path
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

func (e *Error) Unwrap() error { return e.Cause }

// VerificationError exposes the fresh evidence after a reviewed workspace
// changes without authorizing callers to continue with stale evidence.
type VerificationError struct {
	Reviewed Review
	Current  Review
	Changes  []string
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", CodeReviewEvidenceChanged, strings.Join(e.Changes, ", "))
}

// CodeOf returns the first stable workspace code in an error chain.
func CodeOf(err error) ErrorCode {
	var verification *VerificationError
	if errors.As(err, &verification) {
		return CodeReviewEvidenceChanged
	}
	var workspaceError *Error
	if errors.As(err, &workspaceError) {
		return workspaceError.Code
	}
	return ""
}
