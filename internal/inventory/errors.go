package inventory

import "errors"

// ErrorCode is a stable, non-secret inventory diagnostic classification.
type ErrorCode string

const (
	CodeInvalidPolicy        ErrorCode = "invalid_policy"
	CodePathRequired         ErrorCode = "path_required"
	CodePathNotAbsolute      ErrorCode = "path_not_absolute"
	CodePathNotCanonical     ErrorCode = "path_not_canonical"
	CodePathTooLong          ErrorCode = "path_too_long"
	CodePathUnavailable      ErrorCode = "path_unavailable"
	CodeSymlink              ErrorCode = "symlink_not_allowed"
	CodeNotDirectory         ErrorCode = "not_directory"
	CodeNotRegular           ErrorCode = "not_regular"
	CodeUntrustedOwner       ErrorCode = "untrusted_owner"
	CodeUnsafePermissions    ErrorCode = "unsafe_permissions"
	CodeNotReadable          ErrorCode = "not_readable"
	CodeHardLink             ErrorCode = "hard_link_not_allowed"
	CodeArtifactSize         ErrorCode = "artifact_size_invalid"
	CodeNeutralNotPrivate    ErrorCode = "neutral_directory_not_private"
	CodeConfigurationPresent ErrorCode = "neutral_configuration_present"
	CodeTreeEntryLimit       ErrorCode = "tree_entry_limit"
	CodeTreeDepthLimit       ErrorCode = "tree_depth_limit"
	CodeCertificateLimit     ErrorCode = "certificate_limit"
	CodeExecutionBusy        ErrorCode = "inventory_busy"
	CodeExecutionTimeout     ErrorCode = "inventory_timeout"
	CodeExecutionCanceled    ErrorCode = "inventory_canceled"
	CodeOutputLimit          ErrorCode = "inventory_output_limit"
	CodeExecutionFailed      ErrorCode = "inventory_command_failed"
	CodeMalformedOutput      ErrorCode = "malformed_inventory_output"
	CodeDuplicate            ErrorCode = "duplicate_inventory_entry"
	CodePathOutsideStorage   ErrorCode = "certificate_path_outside_storage"
	CodeArtifactsChanged     ErrorCode = "inventory_artifacts_changed"
	CodePreparedCloseFailed  ErrorCode = "prepared_executable_close_failed"
)

// Error reports a bounded failure without including child stderr or artifact
// contents. Cause is available for programmatic inspection only.
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

// Unwrap retains a low-level cause without placing its text in Error().
func (e *Error) Unwrap() error { return e.Cause }

// CodeOf returns the first inventory code in an error chain.
func CodeOf(err error) ErrorCode {
	var inventoryError *Error
	if errors.As(err, &inventoryError) {
		return inventoryError.Code
	}
	return ""
}
