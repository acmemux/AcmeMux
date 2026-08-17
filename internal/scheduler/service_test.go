package scheduler

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/jobs"
	"github.com/acmemux/AcmeMux/internal/operation"
	"github.com/acmemux/AcmeMux/internal/state"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) set(value time.Time) {
	clock.mu.Lock()
	clock.now = value
	clock.mu.Unlock()
}

func (*fakeClock) After(time.Duration) <-chan time.Time { return time.After(time.Millisecond) }

type fakeOperations struct {
	ready       chan struct{}
	interrupted bool
	mu          sync.Mutex
	errors      []error
	calls       int
}

func (operations *fakeOperations) EnqueueScheduled(context.Context) (jobs.Operation, error) {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	operations.calls++
	if len(operations.errors) > 0 {
		err := operations.errors[0]
		operations.errors = operations.errors[1:]
		return jobs.Operation{}, err
	}
	return jobs.Operation{Kind: jobs.KindScheduled}, nil
}

func (operations *fakeOperations) Ready() <-chan struct{}   { return operations.ready }
func (operations *fakeOperations) InterruptedOnStart() bool { return operations.interrupted }

func (operations *fakeOperations) callCount() int {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	return operations.calls
}

func TestServiceReportsReadyOnlyAfterStartupRecovery(t *testing.T) {
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	operationsReady := make(chan struct{})
	service, err := New(database, &fakeOperations{ready: operationsReady}, &fakeClock{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-service.Ready():
		cancel()
		t.Fatal("scheduler reported ready before operation recovery")
	case <-time.After(20 * time.Millisecond):
	}
	close(operationsReady)
	select {
	case <-service.Ready():
	case <-time.After(time.Second):
		cancel()
		t.Fatal("scheduler did not report ready after startup recovery")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServiceTriggersPersistedDueScheduleAfterRestartAndDefersContention(t *testing.T) {
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	ready := make(chan struct{})
	close(ready)
	firstOps := &fakeOperations{ready: ready}
	first, err := New(database, firstOps, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Update(context.Background(), Update{Enabled: true, TimeZone: "UTC", LocalMinute: 12*60 + 1}); err != nil {
		t.Fatal(err)
	}

	// Build a new service over the same database to represent an ordinary
	// application restart. The first contention result remains due and is
	// retried once the existing operation clears.
	clock.set(time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC))
	restartedOps := &fakeOperations{ready: ready, errors: []error{operation.ErrActive, operation.ErrActive, operation.ErrBusy}}
	restarted, err := New(database, restartedOps, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.Run(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	var schedule Schedule
	for time.Now().Before(deadline) {
		schedule, err = restarted.Get(context.Background())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if schedule.ReasonCode == "triggered" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if restartedOps.callCount() != 4 {
		t.Fatalf("scheduled enqueue calls = %d, want 4", restartedOps.callCount())
	}
	if schedule.ReasonCode != "triggered" || schedule.LastTriggeredAt.IsZero() || schedule.State != StateScheduled {
		t.Fatalf("triggered schedule = %#v", schedule)
	}
}

type blockingOperations struct {
	ready   chan struct{}
	entered chan struct{}
	release chan struct{}
}

func (operations *blockingOperations) EnqueueScheduled(ctx context.Context) (jobs.Operation, error) {
	close(operations.entered)
	select {
	case <-ctx.Done():
		return jobs.Operation{}, ctx.Err()
	case <-operations.release:
		return jobs.Operation{Kind: jobs.KindScheduled}, nil
	}
}

func (operations *blockingOperations) Ready() <-chan struct{} { return operations.ready }
func (*blockingOperations) InterruptedOnStart() bool          { return false }

func TestServiceSerializesScheduleEditWithDurableTriggerAcceptance(t *testing.T) {
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)}
	ready := make(chan struct{})
	close(ready)
	operations := &blockingOperations{ready: ready, entered: make(chan struct{}), release: make(chan struct{})}
	service, err := New(database, operations, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), Update{Enabled: true, TimeZone: "UTC", LocalMinute: 12*60 + 1}); err != nil {
		t.Fatal(err)
	}
	clock.set(time.Date(2026, 8, 16, 12, 2, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	select {
	case <-operations.entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("scheduler did not begin durable trigger acceptance")
	}

	updated := make(chan error, 1)
	go func() {
		_, updateErr := service.Update(context.Background(), Update{Enabled: true, TimeZone: "UTC", LocalMinute: 13*60 + 5})
		updated <- updateErr
	}()
	select {
	case err := <-updated:
		cancel()
		t.Fatalf("schedule edit overlapped trigger acceptance: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(operations.release)
	if err := <-updated; err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	schedule, err := service.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if schedule.LocalTime() != "13:05" || schedule.ReasonCode != "schedule_saved" {
		t.Fatalf("edited schedule = %#v", schedule)
	}
}

func TestServiceAdvancesAfterStartupInterruptionWithoutEnqueue(t *testing.T) {
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	clock := &fakeClock{now: time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)}
	ready := make(chan struct{})
	close(ready)
	operations := &fakeOperations{ready: ready, interrupted: true, errors: []error{errors.New("must not enqueue")}}
	service, err := New(database, operations, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(context.Background(), Update{Enabled: true, TimeZone: "UTC", LocalMinute: 1}); err != nil {
		t.Fatal(err)
	}
	clock.set(time.Date(2026, 8, 17, 0, 2, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if operations.callCount() != 0 {
		t.Fatalf("interrupted startup scheduled %d operations", operations.callCount())
	}
	schedule, err := service.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if schedule.ReasonCode != "operation_interrupted" || !schedule.NextEvaluation.After(clock.Now()) {
		t.Fatalf("post-interruption schedule = %#v", schedule)
	}
}
