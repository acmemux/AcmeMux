package runtime

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCode is a stable, non-secret diagnostic classification.
type ErrorCode string

const (
	CodeInvalidPolicy           ErrorCode = "invalid_policy"
	CodePathRequired            ErrorCode = "path_required"
	CodePathNotAbsolute         ErrorCode = "path_not_absolute"
	CodePathNotCanonical        ErrorCode = "path_not_canonical"
	CodePathTooLong             ErrorCode = "path_too_long"
	CodePathUnavailable         ErrorCode = "path_unavailable"
	CodeSymlink                 ErrorCode = "symlink_not_allowed"
	CodeNotRegular              ErrorCode = "not_regular"
	CodeEmptyExecutable         ErrorCode = "empty_executable"
	CodeExecutableTooLarge      ErrorCode = "executable_too_large"
	CodeUntrustedOwner          ErrorCode = "untrusted_owner"
	CodeUnsafePermissions       ErrorCode = "unsafe_permissions"
	CodeUnsafeCapabilities      ErrorCode = "unsafe_capabilities"
	CodeNotExecutable           ErrorCode = "not_executable"
	CodeFingerprintFailed       ErrorCode = "fingerprint_failed"
	CodeChangedDuringInspection ErrorCode = "changed_during_inspection"
	CodeInspectionTimeout       ErrorCode = "inspection_timeout"
	CodeInspectionCanceled      ErrorCode = "inspection_canceled"
	CodeInspectionBusy          ErrorCode = "inspection_busy"
	CodeProbeTimeout            ErrorCode = "probe_timeout"
	CodeProbeCanceled           ErrorCode = "probe_canceled"
	CodeProbeOutputLimit        ErrorCode = "probe_output_limit"
	CodeProbeFailed             ErrorCode = "probe_failed"
	CodeMalformedVersion        ErrorCode = "malformed_version_output"
	CodeExecutableNotQualified  ErrorCode = "executable_not_qualified"
	CodeBuildIdentityMismatch   ErrorCode = "build_identity_mismatch"
	CodeUnsupportedPlatform     ErrorCode = "unsupported_platform"
	CodePlatformMismatch        ErrorCode = "platform_mismatch"
	CodeReplacement             ErrorCode = "executable_replaced"
	CodeCompatibilityChanged    ErrorCode = "compatibility_changed"
	CodePreparedClosed          ErrorCode = "prepared_executable_closed"
)

// Error reports a bounded runtime trust failure.
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

// Unwrap exposes the underlying operating-system or context error without
// placing its potentially noisy text in the stable diagnostic.
func (e *Error) Unwrap() error { return e.Cause }

// CodeOf returns the first runtime diagnostic code in an error chain.
func CodeOf(err error) ErrorCode {
	var replacementError *ReplacementError
	if errors.As(err, &replacementError) {
		return CodeReplacement
	}
	var runtimeError *Error
	if errors.As(err, &runtimeError) {
		return runtimeError.Code
	}
	return ""
}

// ReplacementError lists the material observations that no longer match the
// administrator-reviewed executable.
type ReplacementError struct {
	Path    string
	Current Observation
	Changes []string
	Cause   error
}

func (e *ReplacementError) Error() string {
	return fmt.Sprintf("%s: %s: %s", CodeReplacement, e.Path, strings.Join(e.Changes, ", "))
}

// Unwrap retains the specific reason a replacement could not be inspected.
func (e *ReplacementError) Unwrap() error { return e.Cause }
