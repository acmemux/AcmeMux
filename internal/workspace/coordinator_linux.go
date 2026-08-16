//go:build linux

package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Coordinator serializes every native workspace read, edit, inventory, and
// run in-process and across overlapping AcmeMux processes through flock.
type Coordinator struct {
	path     string
	identity FileIdentity
	gate     chan struct{}
}

// Lease is an exclusive workspace lease. Release is idempotent.
type Lease struct {
	coordinator *Coordinator
	file        *os.File
	purpose     Purpose
	released    atomic.Bool
	once        sync.Once
}

// NewCoordinator creates or verifies a restrictive service-owned lock file.
func NewCoordinator(lockPath string) (*Coordinator, error) {
	if err := validateSelectedPath(lockPath); err != nil {
		return nil, fmt.Errorf("workspace lock path: %w", err)
	}
	if filepath.Base(lockPath) == "." || filepath.Base(lockPath) == string(filepath.Separator) {
		return nil, errors.New("workspace lock path must name a file")
	}
	policy := DefaultPolicy()
	rootUID, err := filesystemRootUID()
	if err != nil {
		return nil, fmt.Errorf("inspect workspace lock ancestry: %w", err)
	}
	policy.trustedRootUID = rootUID
	parent := auditPath(context.Background(), filepath.Dir(lockPath), RoleWorkspace, "",
		pathRequirements{expected: PathTypeDirectory, requireWrite: true, requireSearch: true}, policy)
	if !parent.evidence.Safe || hasBlockingDiagnostics(parent.diagnostics) {
		return nil, errors.New("workspace lock parent is unsafe")
	}
	file, err := openWorkspaceLock(lockPath)
	if err != nil {
		return nil, err
	}
	stat, err := fstat(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("inspect workspace lock: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close workspace lock: %w", err)
	}
	return &Coordinator{path: lockPath, identity: identityFromStat(stat), gate: make(chan struct{}, 1)}, nil
}

// Acquire waits until the lease is available or the context is canceled.
func (coordinator *Coordinator) Acquire(ctx context.Context, purpose Purpose) (*Lease, error) {
	return coordinator.acquire(ctx, purpose, false)
}

// TryAcquire returns ErrWorkspaceBusy instead of waiting.
func (coordinator *Coordinator) TryAcquire(ctx context.Context, purpose Purpose) (*Lease, error) {
	return coordinator.acquire(ctx, purpose, true)
}

func (coordinator *Coordinator) acquire(ctx context.Context, purpose Purpose, nonblocking bool) (*Lease, error) {
	if coordinator == nil || coordinator.gate == nil || coordinator.path == "" {
		return nil, errors.New("workspace coordinator is not initialized")
	}
	if ctx == nil {
		return nil, errors.New("workspace lease context is required")
	}
	if !validPurpose(purpose) {
		return nil, errors.New("workspace lease purpose is invalid")
	}
	if nonblocking {
		select {
		case coordinator.gate <- struct{}{}:
		default:
			return nil, ErrWorkspaceBusy
		}
	} else {
		select {
		case coordinator.gate <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	releaseGate := true
	defer func() {
		if releaseGate {
			<-coordinator.gate
		}
	}()

	file, err := openWorkspaceLock(coordinator.path)
	if err != nil {
		return nil, err
	}
	stat, err := fstat(int(file.Fd()))
	if err != nil || !sameFileIdentity(coordinator.identity, identityFromStat(stat), true) {
		_ = file.Close()
		return nil, ErrSourceChanged
	}
	for {
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock native workspace: %w", err)
		}
		if nonblocking {
			_ = file.Close()
			return nil, ErrWorkspaceBusy
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		_ = file.Close()
		return nil, err
	}
	releaseGate = false
	return &Lease{coordinator: coordinator, file: file, purpose: purpose}, nil
}

// Purpose returns the activity that owns the lease.
func (lease *Lease) Purpose() Purpose {
	if lease == nil || lease.released.Load() {
		return ""
	}
	return lease.purpose
}

// Release unlocks and closes the cross-process lock, then wakes one waiter.
func (lease *Lease) Release() error {
	if lease == nil {
		return nil
	}
	var result error
	lease.once.Do(func() {
		lease.released.Store(true)
		if lease.file != nil {
			if err := unix.Flock(int(lease.file.Fd()), unix.LOCK_UN); err != nil {
				result = fmt.Errorf("unlock native workspace: %w", err)
			}
			if err := lease.file.Close(); err != nil && result == nil {
				result = fmt.Errorf("close native workspace lock: %w", err)
			}
		}
		if lease.coordinator != nil && lease.coordinator.gate != nil {
			<-lease.coordinator.gate
		}
	})
	return result
}

func (coordinator *Coordinator) owns(lease *Lease) bool {
	return coordinator != nil && lease != nil && lease.coordinator == coordinator &&
		!lease.released.Load() && lease.file != nil
}

func openWorkspaceLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open workspace lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("retain workspace lock file")
	}
	closeFailure := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	stat, err := fstat(fd)
	if err != nil {
		return closeFailure(fmt.Errorf("inspect workspace lock: %w", err))
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Uid != uint32(os.Geteuid()) ||
		stat.Nlink != 1 || stat.Mode&0o7777 != 0o600 {
		return closeFailure(errors.New("workspace lock must be a service-owned private single-link regular file"))
	}
	return file, nil
}

func validPurpose(purpose Purpose) bool {
	switch purpose {
	case PurposeRead, PurposePreview, PurposeSave, PurposeInventory,
		PurposeManualRun, PurposeScheduled, PurposeRecovery, PurposeBootstrap:
		return true
	default:
		return false
	}
}
