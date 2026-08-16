package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPollInterval       = 250 * time.Millisecond
	maximumPollInterval       = 5 * time.Second
	defaultPersistenceTimeout = 5 * time.Second
)

// Option configures deterministic worker dependencies. Production uses the
// cryptographic random source, UTC wall clock, and bounded poll fallback.
type Option func(*serviceOptions) error

type serviceOptions struct {
	now                func() time.Time
	random             io.Reader
	pollInterval       time.Duration
	persistenceTimeout time.Duration
}

// WithClock supplies a controllable clock for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(options *serviceOptions) error {
		if now == nil {
			return errors.New("operation clock is required")
		}
		options.now = now
		return nil
	}
}

// WithRandom supplies a bounded ID source, primarily for deterministic tests.
func WithRandom(source io.Reader) Option {
	return func(options *serviceOptions) error {
		if source == nil {
			return errors.New("operation random source is required")
		}
		options.random = source
		return nil
	}
}

// WithPollInterval narrows the durable queue fallback poll interval.
func WithPollInterval(interval time.Duration) Option {
	return func(options *serviceOptions) error {
		if interval <= 0 || interval > maximumPollInterval {
			return errors.New("operation poll interval is invalid")
		}
		options.pollInterval = interval
		return nil
	}
}

// Service combines the latest-only store with one in-process worker. Browser
// request contexts are used only through the enqueue commit; Execute always
// receives the service-owned Run context.
type Service struct {
	store              *Store
	executor           Executor
	now                func() time.Time
	random             io.Reader
	pollInterval       time.Duration
	persistenceTimeout time.Duration
	wake               chan struct{}
	running            atomic.Bool
}

// New creates the durable manual-operation service.
func New(database Database, executor Executor, optionValues ...Option) (*Service, error) {
	if executor == nil {
		return nil, errors.New("operation executor is required")
	}
	store, err := NewStore(database)
	if err != nil {
		return nil, err
	}
	options := serviceOptions{
		now: time.Now, random: rand.Reader, pollInterval: defaultPollInterval,
		persistenceTimeout: defaultPersistenceTimeout,
	}
	for _, option := range optionValues {
		if option == nil {
			return nil, errors.New("nil operation option")
		}
		if err := option(&options); err != nil {
			return nil, err
		}
	}
	return &Service{
		store: store, executor: executor, now: options.now, random: options.random,
		pollInterval: options.pollInterval, persistenceTimeout: options.persistenceTimeout,
		wake: make(chan struct{}, 1),
	}, nil
}

// Enqueue commits one manual request before notifying the worker. Once this
// returns successfully, browser disconnect, session expiry, and service restart
// cannot erase the accepted request. Authorization is revalidated by the HTTP
// boundary immediately before calling Enqueue and is not retained here.
func (service *Service) Enqueue(ctx context.Context, request Request) (Operation, error) {
	if service == nil || service.store == nil || service.random == nil || service.now == nil {
		return Operation{}, errors.New("operation service is not initialized")
	}
	if ctx == nil {
		return Operation{}, errors.New("operation enqueue context is required")
	}
	var raw [16]byte
	if _, err := io.ReadFull(service.random, raw[:]); err != nil {
		return Operation{}, errors.New("generate operation identifier")
	}
	operation, err := service.store.Enqueue(ctx, hex.EncodeToString(raw[:]), request, service.instant())
	if err != nil {
		return Operation{}, err
	}
	service.notify()
	return cloneOperation(operation), nil
}

// Status returns only pollable active work. Restart reconciliation is exposed
// as a synthetic running/refreshing-inventory projection without leaking the
// incomplete terminal fields stored underneath it.
func (service *Service) Status(ctx context.Context) (Operation, error) {
	if service == nil || service.store == nil {
		return Operation{}, errors.New("operation service is not initialized")
	}
	operation, err := service.store.Latest(ctx)
	if err != nil {
		return Operation{}, err
	}
	if operation.Active() {
		return cloneOperation(operation), nil
	}
	if operation.Terminal() && operation.Inventory.State == InventoryPending {
		return Operation{
			ID: operation.ID, Kind: operation.Kind, State: StateRunning,
			Phase: PhaseRefreshingInventory, RequestedAt: operation.RequestedAt,
			StartedAt: operation.StartedAt, UpdatedAt: operation.UpdatedAt,
			Inventory: InventoryResult{State: InventoryPending},
		}, nil
	}
	return Operation{}, ErrNotFound
}

// Latest returns only a fully reconciled terminal result. Active work and a
// terminal row whose inventory reconciliation is still pending are hidden so
// transport cannot expose an incomplete latest result.
func (service *Service) Latest(ctx context.Context) (Operation, error) {
	if service == nil || service.store == nil {
		return Operation{}, errors.New("operation service is not initialized")
	}
	operation, err := service.store.Latest(ctx)
	if err != nil {
		return Operation{}, err
	}
	if !operation.Terminal() || operation.Inventory.State == InventoryPending {
		return Operation{}, ErrNotFound
	}
	return cloneOperation(operation), nil
}

// Run owns the one durable worker until ctx is canceled. It is safe to start
// it before or after the HTTP listener; accepted work is also found by bounded
// polling, so a lost in-memory wake cannot lose a SQLite request.
func (service *Service) Run(ctx context.Context) error {
	if service == nil || service.store == nil || service.executor == nil || service.wake == nil {
		return errors.New("operation service is not initialized")
	}
	if ctx == nil {
		return errors.New("operation worker context is required")
	}
	if !service.running.CompareAndSwap(false, true) {
		return ErrWorkerRunning
	}
	defer service.running.Store(false)

	if err := service.recover(ctx); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	timer := time.NewTimer(service.pollInterval)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		operation, err := service.store.Claim(ctx, service.instant())
		switch {
		case err == nil:
			if err := service.execute(ctx, operation); err != nil {
				return err
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(service.pollInterval)
			continue
		case errors.Is(err, ErrNoQueued):
		case ctx.Err() != nil:
			return nil
		default:
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-service.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(service.pollInterval)
		case <-timer.C:
			timer.Reset(service.pollInterval)
		}
	}
}

func (service *Service) recover(ctx context.Context) error {
	if _, _, err := service.store.InterruptRunning(ctx, service.instant()); err != nil {
		return err
	}
	operation, err := service.store.PendingReconciliation(ctx)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return service.reconcile(ctx, operation)
}

func (service *Service) execute(ctx context.Context, operation Operation) error {
	currentPhase := PhaseRevalidating
	var phaseFailure error
	var phaseMu sync.Mutex
	reportPhase := func(next Phase) error {
		phaseMu.Lock()
		defer phaseMu.Unlock()
		if phaseFailure != nil {
			return phaseFailure
		}
		if !validPhaseTransition(currentPhase, next) {
			phaseFailure = ErrStateChanged
			return phaseFailure
		}
		persistCtx, cancel := service.persistenceContext()
		err := service.store.UpdatePhase(persistCtx, operation.ID, next, service.instant())
		cancel()
		if err != nil {
			phaseFailure = err
			return err
		}
		currentPhase = next
		return nil
	}

	executionContext, cancelExecution := context.WithCancel(ctx)
	result, panicked := service.callExecute(executionContext, operation.ID, operation.Request, reportPhase)
	cancelExecution()
	phaseMu.Lock()
	lastPhase := currentPhase
	transitionErr := phaseFailure
	phaseMu.Unlock()
	if panicked || transitionErr != nil || lastPhase != PhaseRefreshingInventory || validateExecutorResult(result) != nil {
		code := "worker_result_invalid"
		if panicked {
			code = "worker_panicked"
		} else if transitionErr != nil {
			code = "worker_phase_failed"
		}
		persistCtx, cancel := service.persistenceContext()
		uncertain, err := service.store.FinishUncertain(
			persistCtx, operation.ID, StateAmbiguous, code, service.instant(),
		)
		cancel()
		if err != nil {
			return err
		}
		return service.reconcile(ctx, uncertain)
	}

	persistCtx, cancel := service.persistenceContext()
	_, err := service.store.Finish(persistCtx, operation.ID, result, service.instant())
	cancel()
	return err
}

func (service *Service) callExecute(ctx context.Context, id string, request Request, report PhaseReporter) (result Result, panicked bool) {
	defer func() {
		if recover() != nil {
			result = Result{}
			panicked = true
		}
	}()
	return service.executor.Execute(ctx, id, cloneRequest(request), report), false
}

func (service *Service) reconcile(ctx context.Context, operation Operation) error {
	reconciliationContext, cancelReconciliation := context.WithCancel(ctx)
	inventory, panicked := service.callReconcile(reconciliationContext, operation.ID)
	cancelReconciliation()
	if panicked || validateInventory(inventory, false) != nil {
		inventory = InventoryResult{State: InventoryUnavailable, Code: "inventory_reconciliation_failed"}
	}
	persistCtx, cancel := service.persistenceContext()
	_, err := service.store.CompleteReconciliation(persistCtx, operation.ID, inventory, service.instant())
	cancel()
	return err
}

func (service *Service) callReconcile(ctx context.Context, id string) (inventory InventoryResult, panicked bool) {
	defer func() {
		if recover() != nil {
			inventory = InventoryResult{}
			panicked = true
		}
	}()
	return service.executor.Reconcile(ctx, id), false
}

func (service *Service) persistenceContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), service.persistenceTimeout)
}

func (service *Service) instant() time.Time {
	return service.now().UTC().Round(0)
}

func (service *Service) notify() {
	select {
	case service.wake <- struct{}{}:
	default:
	}
}

// Running reports whether this service currently owns its worker loop. It is
// intended for lifecycle coordination, not operation status.
func (service *Service) Running() bool {
	return service != nil && service.running.Load()
}
