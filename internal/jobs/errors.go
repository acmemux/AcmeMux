package jobs

import "errors"

var (
	// ErrActive reports that the singleton latest result is still queued,
	// running, or awaiting restart reconciliation and cannot be replaced.
	ErrActive = errors.New("a native workspace operation is already active")
	// ErrNotFound reports that no latest operation exists.
	ErrNotFound = errors.New("no native workspace operation exists")
	// ErrNoQueued reports that the durable queue currently has no work.
	ErrNoQueued = errors.New("no native workspace operation is queued")
	// ErrInvalid identifies malformed application-internal job data.
	ErrInvalid = errors.New("native workspace operation data is invalid")
	// ErrStateChanged reports a stale worker transition.
	ErrStateChanged = errors.New("native workspace operation state changed")
	// ErrWorkerRunning reports a second Run call on the one worker.
	ErrWorkerRunning = errors.New("native workspace operation worker is already running")
)
