package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/acmemux/AcmeMux/internal/jobs"
	"github.com/acmemux/AcmeMux/internal/operation"
)

const (
	defaultWakeInterval = time.Minute
	deferredRetry       = time.Second
)

// Operations is the trusted durable-operation surface consumed by the
// scheduler. Startup readiness prevents automatic work from racing operation
// interruption reconciliation.
type Operations interface {
	EnqueueScheduled(context.Context) (jobs.Operation, error)
	Ready() <-chan struct{}
	InterruptedOnStart() bool
}

// Clock makes wall-clock calculation and wakeup deterministic in tests.
type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time                                { return time.Now() }
func (wallClock) After(duration time.Duration) <-chan time.Time { return time.After(duration) }

// Service owns schedule updates and the one in-process due-evaluation loop.
type Service struct {
	store      *Store
	operations Operations
	clock      Clock
	wake       chan struct{}
	ready      chan struct{}
	readyOnce  sync.Once
	mu         sync.Mutex
}

func New(database Database, operations Operations, clock Clock) (*Service, error) {
	if operations == nil {
		return nil, errors.New("scheduled operation service is required")
	}
	if clock == nil {
		clock = wallClock{}
	}
	store, err := NewStore(database)
	if err != nil {
		return nil, err
	}
	return &Service{
		store: store, operations: operations, clock: clock,
		wake: make(chan struct{}, 1), ready: make(chan struct{}),
	}, nil
}

func (service *Service) Get(ctx context.Context) (Schedule, error) {
	if service == nil || service.store == nil || service.clock == nil {
		return Schedule{}, errors.New("automatic scheduler is unavailable")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.store.Get(ctx, service.instant())
}

func (service *Service) Update(ctx context.Context, update Update) (Schedule, error) {
	if service == nil || service.store == nil || service.clock == nil {
		return Schedule{}, errors.New("automatic scheduler is unavailable")
	}
	service.mu.Lock()
	schedule, err := service.store.Save(ctx, update, service.instant())
	service.mu.Unlock()
	if err == nil {
		service.notify()
	}
	return schedule, err
}

// Run waits for operation recovery, repairs any scheduler crash window, and
// then wakes for configuration changes, due instants, contention, and bounded
// wall-clock jump detection.
func (service *Service) Run(ctx context.Context) error {
	if service == nil || service.store == nil || service.operations == nil || service.clock == nil || service.wake == nil {
		return errors.New("automatic scheduler is unavailable")
	}
	ready := service.operations.Ready()
	if ready == nil {
		return errors.New("operation recovery readiness is unavailable")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-ready:
	}
	service.mu.Lock()
	err := service.store.Recover(ctx, service.instant(), service.operations.InterruptedOnStart())
	service.mu.Unlock()
	if err != nil {
		return err
	}
	service.readyOnce.Do(func() { close(service.ready) })
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := service.evaluate(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		delay, err := service.delay(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-service.wake:
		case <-service.clock.After(delay):
		}
	}
}

// Ready closes after operation and scheduler startup recovery are complete.
func (service *Service) Ready() <-chan struct{} {
	if service == nil || service.ready == nil {
		return nil
	}
	return service.ready
}

func (service *Service) evaluate(ctx context.Context) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	claim, err := service.store.ClaimDue(ctx, service.instant())
	if errors.Is(err, ErrNotDue) {
		return nil
	}
	if err != nil {
		return err
	}
	_, enqueueErr := service.operations.EnqueueScheduled(ctx)
	now := service.instant()
	switch {
	case enqueueErr == nil:
		return service.store.CompleteClaim(ctx, claim, now)
	case errors.Is(enqueueErr, operation.ErrActive):
		return service.store.ReleaseClaim(ctx, claim, "operation_active", true, now)
	case errors.Is(enqueueErr, operation.ErrBusy):
		return service.store.ReleaseClaim(ctx, claim, "workspace_busy", true, now)
	case errors.Is(enqueueErr, operation.ErrRecovery):
		return service.store.ReleaseClaim(ctx, claim, "recovery_required", false, now)
	case errors.Is(enqueueErr, operation.ErrWorkspace), errors.Is(enqueueErr, operation.ErrChanged):
		return service.store.ReleaseClaim(ctx, claim, "workspace_invalid", false, now)
	case errors.Is(enqueueErr, operation.ErrConfiguration):
		return service.store.ReleaseClaim(ctx, claim, "configuration_invalid", false, now)
	default:
		return service.store.ReleaseClaim(ctx, claim, "operation_unavailable", false, now)
	}
}

func (service *Service) delay(ctx context.Context) (time.Duration, error) {
	service.mu.Lock()
	schedule, err := service.store.Get(ctx, service.instant())
	service.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if !schedule.Enabled {
		return defaultWakeInterval, nil
	}
	if schedule.State == StateDue || schedule.State == StateDeferred {
		return deferredRetry, nil
	}
	delay := schedule.NextEvaluation.Sub(service.instant())
	if delay <= 0 {
		return deferredRetry, nil
	}
	if delay > defaultWakeInterval {
		return defaultWakeInterval, nil
	}
	return delay, nil
}

func (service *Service) instant() time.Time { return service.clock.Now().UTC().Round(0) }

func (service *Service) notify() {
	select {
	case service.wake <- struct{}{}:
	default:
	}
}
