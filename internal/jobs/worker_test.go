package jobs

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeExecutor struct {
	execute   func(context.Context, string, Request, PhaseReporter) Result
	reconcile func(context.Context, string) InventoryResult
}

func (fake fakeExecutor) Execute(ctx context.Context, id string, request Request, report PhaseReporter) Result {
	result := fake.execute(ctx, id, request, report)
	if len(result.Items) == 0 {
		state := ItemAmbiguous
		switch result.State {
		case StateSucceeded:
			state = ItemCompleted
		case StateNotAttempted, StateIncompatible:
			state = ItemNotAttempted
		case StateFailed:
			state = ItemFailed
		}
		result.Items = make([]ItemResult, len(request.Items))
		for index, name := range request.Items {
			result.Items[index] = ItemResult{Name: name, State: state, Code: result.Code}
		}
	}
	return result
}

func (fake fakeExecutor) Reconcile(ctx context.Context, id string) InventoryResult {
	if fake.reconcile == nil {
		return InventoryResult{State: InventoryUnavailable, Code: "inventory_unavailable"}
	}
	return fake.reconcile(ctx, id)
}

type steppingClock struct {
	mu   sync.Mutex
	next time.Time
}

func (clock *steppingClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	result := clock.next
	clock.next = clock.next.Add(time.Second)
	return result
}

func TestWorkerUsesServiceLifetimeAfterBrowserDisconnect(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	clock := &steppingClock{next: testEpoch}
	executed := make(chan string, 1)
	count := 1
	executor := fakeExecutor{execute: func(ctx context.Context, id string, request Request, report PhaseReporter) Result {
		if err := ctx.Err(); err != nil {
			t.Errorf("worker received canceled browser context: %v", err)
		}
		if err := report(PhaseExecuting); err != nil {
			t.Errorf("report executing: %v", err)
		}
		if err := report(PhaseRefreshingInventory); err != nil {
			t.Errorf("report refresh: %v", err)
		}
		if request.ReviewedEvidenceSHA256 != testRequest().ReviewedEvidenceSHA256 {
			t.Errorf("reviewed request was not retained: %#v", request)
		}
		executed <- id
		return Result{
			State: StateSucceeded, Code: "completed", MayHaveChanged: true,
			Inventory: InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count},
			Output:    "safe transcript",
		}
	}}
	service, err := New(database, executor,
		WithClock(clock.now), WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x21}, 16))),
		WithPollInterval(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	browserContext, cancelBrowser := context.WithCancel(context.Background())
	queued, err := service.Enqueue(browserContext, testRequest())
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	cancelBrowser()

	workerContext, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan error, 1)
	go func() { workerDone <- service.Run(workerContext) }()
	select {
	case id := <-executed:
		if id != queued.ID {
			t.Fatalf("executed ID = %q, want %q", id, queued.ID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not execute accepted operation")
	}
	waitForState(t, service, StateSucceeded)
	cancelWorker()
	if err := <-workerDone; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	latest, _ := service.Latest(context.Background())
	if latest.Output != "safe transcript" || latest.Inventory.CertificateCount == nil ||
		*latest.Inventory.CertificateCount != 1 {
		t.Fatalf("latest = %#v", latest)
	}
}

func TestWorkerRestartsQueuedButNeverReplaysRunning(t *testing.T) {
	t.Parallel()
	t.Run("queued survives restart", func(t *testing.T) {
		database := openTestDatabase(t)
		clock := &steppingClock{next: testEpoch}
		placeholder := fakeExecutor{execute: func(context.Context, string, Request, PhaseReporter) Result { return Result{} }}
		first, _ := New(database, placeholder,
			WithClock(clock.now), WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x31}, 16))))
		queued, err := first.Enqueue(context.Background(), testRequest())
		if err != nil {
			t.Fatal(err)
		}

		executed := make(chan string, 1)
		count := 0
		second, _ := New(database, fakeExecutor{execute: func(_ context.Context, id string, request Request, report PhaseReporter) Result {
			_ = report(PhaseExecuting)
			_ = report(PhaseRefreshingInventory)
			if request.ReviewedEvidenceSHA256 != testRequest().ReviewedEvidenceSHA256 {
				t.Errorf("restarted request = %#v", request)
			}
			executed <- id
			return Result{
				State: StateSucceeded, Code: "completed",
				Inventory: InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count},
			}
		}}, WithClock(clock.now), WithPollInterval(5*time.Millisecond))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- second.Run(ctx) }()
		select {
		case id := <-executed:
			if id != queued.ID {
				t.Fatalf("executed ID = %q, want %q", id, queued.ID)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("queued operation did not resume")
		}
		waitForState(t, second, StateSucceeded)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("running becomes interrupted and inventory-only", func(t *testing.T) {
		database := openTestDatabase(t)
		store, _ := NewStore(database)
		id := strings.Repeat("e", 32)
		if _, err := store.Enqueue(context.Background(), id, testRequest(), testEpoch); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Claim(context.Background(), testEpoch.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		reconciled := make(chan string, 1)
		count := 3
		executor := fakeExecutor{
			execute: func(context.Context, string, Request, PhaseReporter) Result {
				t.Fatal("running operation was replayed")
				return Result{}
			},
			reconcile: func(_ context.Context, got string) InventoryResult {
				reconciled <- got
				return InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count}
			},
		}
		clock := &steppingClock{next: testEpoch.Add(2 * time.Second)}
		service, _ := New(database, executor, WithClock(clock.now), WithPollInterval(5*time.Millisecond))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- service.Run(ctx) }()
		select {
		case got := <-reconciled:
			if got != id {
				t.Fatalf("reconciled ID = %q, want %q", got, id)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("restart reconciliation did not run")
		}
		waitForState(t, service, StateInterrupted)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		latest, _ := service.Latest(context.Background())
		if latest.Code != "service_restarted" || latest.Inventory.CertificateCount == nil ||
			*latest.Inventory.CertificateCount != 3 {
			t.Fatalf("latest = %#v", latest)
		}
	})
}

func TestWorkerPersistsObservableMonotonicPhases(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	clock := &steppingClock{next: testEpoch}
	executing := make(chan struct{})
	continueRun := make(chan struct{})
	refreshing := make(chan struct{})
	continueRefresh := make(chan struct{})
	count := 0
	executor := fakeExecutor{execute: func(_ context.Context, _ string, _ Request, report PhaseReporter) Result {
		if err := report(PhaseExecuting); err != nil {
			t.Errorf("executing phase: %v", err)
		}
		close(executing)
		<-continueRun
		if err := report(PhaseRefreshingInventory); err != nil {
			t.Errorf("refreshing phase: %v", err)
		}
		close(refreshing)
		<-continueRefresh
		return Result{
			State: StateSucceeded, Code: "completed",
			Inventory: InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count},
		}
	}}
	service, _ := New(database, executor,
		WithClock(clock.now), WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x41}, 16))),
		WithPollInterval(5*time.Millisecond))
	if _, err := service.Enqueue(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	<-executing
	assertLatestPhase(t, service, PhaseExecuting)
	close(continueRun)
	<-refreshing
	assertLatestPhase(t, service, PhaseRefreshingInventory)
	close(continueRefresh)
	waitForState(t, service, StateSucceeded)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStatusKeepsRestartReconciliationPollableAndLatestHidden(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	store, _ := NewStore(database)
	id := strings.Repeat("f", 32)
	if _, err := store.Enqueue(context.Background(), id, testRequest(), testEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(context.Background(), testEpoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reconciling := make(chan struct{})
	finish := make(chan struct{})
	count := 0
	executor := fakeExecutor{
		execute: func(context.Context, string, Request, PhaseReporter) Result {
			t.Fatal("interrupted operation was replayed")
			return Result{}
		},
		reconcile: func(context.Context, string) InventoryResult {
			close(reconciling)
			<-finish
			return InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count}
		},
	}
	clock := &steppingClock{next: testEpoch.Add(2 * time.Second)}
	service, _ := New(database, executor, WithClock(clock.now), WithPollInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-reconciling:
	case <-time.After(5 * time.Second):
		t.Fatal("restart reconciliation did not begin")
	}
	status, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StateRunning || status.Phase != PhaseRefreshingInventory ||
		status.ID != id || status.Code != "" || !status.FinishedAt.IsZero() || status.Output != "" {
		t.Fatalf("synthetic recovery status = %#v", status)
	}
	if _, err := service.Latest(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Latest(during reconciliation) error = %v, want ErrNotFound", err)
	}
	close(finish)
	waitForState(t, service, StateInterrupted)
	if _, err := service.Status(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status(after reconciliation) error = %v, want ErrNotFound", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestWorkerContainsExecutorPanicAndReconcilesWithoutPanicText(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	clock := &steppingClock{next: testEpoch}
	count := 1
	reconciled := make(chan struct{})
	executionCanceled := make(chan struct{})
	service, _ := New(database, fakeExecutor{
		execute: func(ctx context.Context, _ string, _ Request, report PhaseReporter) Result {
			_ = report(PhaseExecuting)
			go func() {
				<-ctx.Done()
				close(executionCanceled)
			}()
			panic("secret panic canary")
		},
		reconcile: func(context.Context, string) InventoryResult {
			close(reconciled)
			return InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count}
		},
	}, WithClock(clock.now), WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x51}, 16))),
		WithPollInterval(5*time.Millisecond))
	if _, err := service.Enqueue(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-reconciled:
	case <-time.After(5 * time.Second):
		t.Fatal("panic did not trigger inventory reconciliation")
	}
	select {
	case <-executionCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("panic did not cancel the executor context")
	}
	waitForState(t, service, StateAmbiguous)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	latest, _ := service.Latest(context.Background())
	if latest.Output != "" || strings.Contains(latest.Code, "secret") || latest.Code != "worker_panicked" ||
		len(latest.Items) != 1 || latest.Items[0].State != ItemAmbiguous || latest.Items[0].Code != "worker_panicked" {
		t.Fatalf("panic details reached latest result: %#v", latest)
	}
}

func TestWorkerServiceShutdownTerminatesActiveWorkWithoutBrowserCancellation(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	clock := &steppingClock{next: testEpoch}
	started := make(chan struct{})
	executor := fakeExecutor{execute: func(ctx context.Context, _ string, _ Request, report PhaseReporter) Result {
		if err := report(PhaseExecuting); err != nil {
			t.Errorf("report executing: %v", err)
		}
		close(started)
		<-ctx.Done()
		if err := report(PhaseRefreshingInventory); err != nil {
			t.Errorf("report refresh after shutdown: %v", err)
		}
		return Result{
			State: StateInterrupted, Code: "service_stopping", MayHaveChanged: true,
			Inventory: InventoryResult{State: InventoryUnavailable, Code: "inventory_refresh_interrupted"},
		}
	}}
	service, _ := New(database, executor,
		WithClock(clock.now), WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x61}, 16))),
		WithPollInterval(5*time.Millisecond))
	if _, err := service.Enqueue(context.Background(), testRequest()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	latest, err := service.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if latest.State != StateInterrupted || latest.Code != "service_stopping" ||
		latest.Inventory.State != InventoryUnavailable || !latest.MayHaveChanged {
		t.Fatalf("shutdown result = %#v", latest)
	}
}

func TestWorkerRejectsSecondRun(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	service, _ := New(database, fakeExecutor{execute: func(context.Context, string, Request, PhaseReporter) Result { return Result{} }},
		WithPollInterval(5*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for !service.Running() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := service.Run(context.Background()); !errors.Is(err, ErrWorkerRunning) {
		t.Fatalf("second Run() error = %v, want ErrWorkerRunning", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func waitForState(t *testing.T, service *Service, want State) Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := service.Latest(context.Background())
		if err == nil && operation.State == want && operation.Inventory.State != InventoryPending {
			return operation
		}
		time.Sleep(time.Millisecond)
	}
	operation, err := service.Latest(context.Background())
	t.Fatalf("latest state = %#v, error = %v, want %s", operation, err, want)
	return Operation{}
}

func assertLatestPhase(t *testing.T, service *Service, want Phase) {
	t.Helper()
	operation, err := service.Status(context.Background())
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if operation.State != StateRunning || operation.Phase != want {
		t.Fatalf("latest state/phase = %s/%s, want running/%s", operation.State, operation.Phase, want)
	}
}
