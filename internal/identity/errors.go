package identity

import "errors"

var (
	// ErrUninitialized means the local administrator has not been bootstrapped.
	ErrUninitialized = errors.New("administrator is not initialized")
	// ErrAlreadyInitialized means the singleton administrator already exists.
	ErrAlreadyInitialized = errors.New("administrator is already initialized")
	// ErrInvalidCredentials deliberately covers every remote sign-in failure.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrInvalidSession deliberately covers missing, malformed, forged, reset,
	// revoked, and otherwise unusable session identifiers.
	ErrInvalidSession = errors.New("invalid session")
	// ErrSessionExpired distinguishes a known session whose bounded lifetime
	// elapsed so the browser can present an accurate state.
	ErrSessionExpired = errors.New("session expired")
	// ErrPasswordRejected means a new local password does not meet the bounded
	// password policy. It is never returned by remote password verification.
	ErrPasswordRejected = errors.New("password does not meet policy")
	// ErrVerifierUnsupported means persisted password-verifier data cannot be
	// verified safely. A local password reset is the recovery path.
	ErrVerifierUnsupported = errors.New("password verifier is unsupported")
)
