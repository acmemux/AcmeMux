package scheduler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

func TestStorePersistsOneScheduleAndCoalescesMissedDates(t *testing.T) {
	t.Parallel()
	database, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	configuredAt := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	schedule, err := store.Save(ctx, Update{Enabled: true, TimeZone: "America/Denver", LocalMinute: 3*60 + 35}, configuredAt)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.State != StateScheduled || schedule.LocalTime() != "03:35" ||
		!schedule.NextEvaluation.Equal(time.Date(2026, 8, 17, 9, 35, 0, 0, time.UTC)) {
		t.Fatalf("saved schedule = %#v", schedule)
	}

	// A multi-day clock jump claims only the one persisted due occurrence and
	// advances directly to the next ordinary date after the current instant.
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	claim, err := store.ClaimDue(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Occurrence.Equal(time.Date(2026, 8, 17, 9, 35, 0, 0, time.UTC)) {
		t.Fatalf("claimed occurrence = %s", claim.Occurrence)
	}
	if err := store.CompleteClaim(ctx, claim, now); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	schedule, err = restarted.Get(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.ReasonCode != "triggered" || schedule.LastTriggerDate != "2026-08-17" ||
		!schedule.NextEvaluation.Equal(time.Date(2026, 8, 21, 9, 35, 0, 0, time.UTC)) {
		t.Fatalf("completed schedule = %#v", schedule)
	}
	var rows int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM automatic_schedule").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("schedule row count = %d, want 1", rows)
	}
}

func TestStoreRecoveryNeverReplaysClaimOrInterruptedOperation(t *testing.T) {
	t.Parallel()
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, _ := NewStore(database)
	ctx := context.Background()
	start := time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC)
	if _, err := store.Save(ctx, Update{Enabled: true, TimeZone: "UTC", LocalMinute: 1}, start); err != nil {
		t.Fatal(err)
	}
	claimAt := start.Add(2 * time.Minute)
	if _, err := store.ClaimDue(ctx, claimAt); err != nil {
		t.Fatal(err)
	}
	restartAt := start.Add(48 * time.Hour)
	if err := store.Recover(ctx, restartAt, true); err != nil {
		t.Fatal(err)
	}
	schedule, err := store.Get(ctx, restartAt)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.Claiming || schedule.ReasonCode != "operation_interrupted" || !schedule.NextEvaluation.After(restartAt) {
		t.Fatalf("recovered schedule = %#v", schedule)
	}
	if _, err := store.ClaimDue(ctx, restartAt); err != ErrNotDue {
		t.Fatalf("immediate post-recovery claim error = %v, want ErrNotDue", err)
	}
}

func TestStoreDoesNotReplayTriggeredLocalDateAfterClockRollbackAndEdit(t *testing.T) {
	t.Parallel()
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, _ := NewStore(database)
	ctx := context.Background()
	initial := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	update := Update{Enabled: true, TimeZone: "UTC", LocalMinute: 12*60 + 1}
	if _, err := store.Save(ctx, update, initial); err != nil {
		t.Fatal(err)
	}
	triggeredAt := initial.Add(2 * time.Minute)
	claim, err := store.ClaimDue(ctx, triggeredAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteClaim(ctx, claim, triggeredAt); err != nil {
		t.Fatal(err)
	}

	// Saving after a backward clock adjustment can calculate the already-used
	// local date again. The persisted date guard must coalesce it, not replay it.
	rolledBack := initial.Add(-time.Hour)
	if _, err := store.Save(ctx, update, rolledBack); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimDue(ctx, triggeredAt); !errors.Is(err, ErrNotDue) {
		t.Fatalf("repeated local-date claim error = %v, want ErrNotDue", err)
	}
	schedule, err := store.Get(ctx, triggeredAt)
	if err != nil {
		t.Fatal(err)
	}
	if schedule.ReasonCode != "clock_rollback_coalesced" ||
		!schedule.NextEvaluation.Equal(time.Date(2026, 8, 17, 12, 1, 0, 0, time.UTC)) {
		t.Fatalf("coalesced rollback schedule = %#v", schedule)
	}
}
