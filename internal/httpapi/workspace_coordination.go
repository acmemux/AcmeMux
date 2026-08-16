package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/sgurden-certleap/AcmeMux/internal/workspace"
)

// WorkspaceLeaseFunc acquires the single native-workspace lease shared by
// configuration edits, inventory, and operations that replace their selected
// runtime or workspace. The returned release function must be idempotent.
type WorkspaceLeaseFunc func(context.Context, workspace.Purpose) (func() error, error)

// NativeEditJournal is the read-only recovery marker surface shared by
// selection mutations. The concrete workspace.JournalStore contains no native
// configuration bytes or secrets.
type NativeEditJournal interface {
	Load(context.Context) (workspace.Journal, error)
}

func acquireWorkspaceLease(
	response http.ResponseWriter,
	request *http.Request,
	acquire WorkspaceLeaseFunc,
	purpose workspace.Purpose,
) (func() error, bool) {
	release, err := acquire(request.Context(), purpose)
	if err != nil {
		if errors.Is(err, workspace.ErrWorkspaceBusy) {
			response.Header().Set("Retry-After", "1")
			writeAPIError(response, http.StatusTooManyRequests, "service_busy", "Another native workspace action is in progress.")
			return nil, false
		}
		writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Native workspace coordination is unavailable.")
		return nil, false
	}
	if release == nil {
		writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Native workspace coordination is unavailable.")
		return nil, false
	}
	return release, true
}

// requireClearNativeEditJournal must run while the caller owns the shared
// workspace lease. That lease prevents the recovery state from changing
// between this check and the guarded selection mutation.
func requireClearNativeEditJournal(
	response http.ResponseWriter,
	request *http.Request,
	journal NativeEditJournal,
) bool {
	_, err := journal.Load(request.Context())
	switch {
	case errors.Is(err, workspace.ErrNoEditJournal):
		return true
	case err == nil:
		writeAPIError(
			response,
			http.StatusConflict,
			"recovery_required",
			"Resolve the interrupted native configuration edit before changing the selected runtime or workspace.",
		)
	default:
		writeAPIError(response, http.StatusServiceUnavailable, "service_unavailable", "Native edit recovery status is unavailable.")
	}
	return false
}
