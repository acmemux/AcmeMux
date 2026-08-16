package broker

import "errors"

// ErrorCode is a stable, value-free broker failure classification.
type ErrorCode string

const (
	CodeInvalidPolicy       ErrorCode = "invalid_policy"
	CodeInvalidRequest      ErrorCode = "invalid_request"
	CodeInvalidPath         ErrorCode = "invalid_path"
	CodeInvalidEnvironment  ErrorCode = "invalid_environment"
	CodeRedactionFailed     ErrorCode = "redaction_failed"
	CodeProcessBoundary     ErrorCode = "process_boundary_unavailable"
	CodeStartFailed         ErrorCode = "start_failed"
	CodePreparedCloseFailed ErrorCode = "prepared_close_failed"
)

// Error reports a bounded broker failure. Cause remains available for
// programmatic inspection but is deliberately omitted from Error so child
// diagnostics and input-derived operating-system text cannot reach logs or
// persistence accidentally.
type Error struct {
	Code   ErrorCode
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

func (e *Error) Unwrap() error { return e.Cause }

// CodeOf returns the first stable broker code in an error chain.
func CodeOf(err error) ErrorCode {
	var brokerError *Error
	if errors.As(err, &brokerError) {
		return brokerError.Code
	}
	return ""
}
