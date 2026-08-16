package jobs

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

var testEpoch = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

func TestStorePersistsOneBoundedLifecycle(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}

	queued, err := store.Enqueue(context.Background(), strings.Repeat("1", 32), testRequest("first", "second"), testEpoch)
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	if queued.State != StateQueued || queued.Phase != PhaseQueued || !queued.StartedAt.IsZero() || !queued.Active() ||
		queued.Request.ReviewedEvidenceSHA256 != strings.Repeat("a", 64) || len(queued.Request.Items) != 2 {
		t.Fatalf("queued operation = %#v", queued)
	}
	if _, err := store.Enqueue(context.Background(), strings.Repeat("2", 32), testRequest(), testEpoch.Add(time.Second)); !errors.Is(err, ErrActive) {
		t.Fatalf("second Enqueue() error = %v, want ErrActive", err)
	}

	running, err := store.Claim(context.Background(), testEpoch.Add(time.Second))
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if running.State != StateRunning || running.Phase != PhaseRevalidating || running.StartedAt.IsZero() {
		t.Fatalf("running operation = %#v", running)
	}
	if err := store.UpdatePhase(context.Background(), running.ID, PhaseExecuting, testEpoch.Add(2*time.Second)); err != nil {
		t.Fatalf("UpdatePhase(executing) error = %v", err)
	}
	if err := store.UpdatePhase(context.Background(), running.ID, PhaseRefreshingInventory, testEpoch.Add(3*time.Second)); err != nil {
		t.Fatalf("UpdatePhase(refreshing) error = %v", err)
	}
	count := 2
	finished, err := store.Finish(context.Background(), running.ID, Result{
		State: StatePartial, Code: "certificate_failed", MayHaveChanged: true,
		Inventory: InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count},
		Output:    "safe redacted output\n", OutputTruncated: true,
		Items: []ItemResult{
			{Name: "first", State: ItemCompleted, Code: "completed"},
			{Name: "second", State: ItemFailed, Code: "upstream_failed"},
		},
	}, testEpoch.Add(4*time.Second))
	if err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if !finished.Terminal() || finished.Active() || finished.Phase != "" ||
		finished.Inventory.CertificateCount == nil || *finished.Inventory.CertificateCount != 2 ||
		len(finished.Items) != 2 || !finished.OutputTruncated {
		t.Fatalf("finished operation = %#v", finished)
	}

	reloaded, err := store.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if reloaded.ID != finished.ID || reloaded.Output != finished.Output || len(reloaded.Items) != 2 {
		t.Fatalf("reloaded operation = %#v", reloaded)
	}

	replacement, err := store.Enqueue(context.Background(), strings.Repeat("2", 32), testRequest(), testEpoch.Add(5*time.Second))
	if err != nil {
		t.Fatalf("replacement Enqueue() error = %v", err)
	}
	if replacement.ID == finished.ID || len(replacement.Items) != 0 || replacement.Output != "" {
		t.Fatalf("replacement operation = %#v", replacement)
	}
}

func TestStoreRejectsInvalidResultsAndPhaseTransitions(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	store, _ := NewStore(database)
	id := strings.Repeat("a", 32)
	if _, err := store.Enqueue(context.Background(), id, testRequest(), testEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(context.Background(), testEpoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdatePhase(context.Background(), id, PhaseRefreshingInventory, testEpoch.Add(2*time.Second)); err != nil {
		t.Fatalf("direct revalidating -> refreshing transition error = %v", err)
	}
	if err := store.UpdatePhase(context.Background(), id, PhaseExecuting, testEpoch.Add(3*time.Second)); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("backward phase error = %v, want ErrStateChanged", err)
	}

	count := 0
	invalid := Result{
		State: StateSucceeded, Code: "completed",
		Inventory: InventoryResult{State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count},
		Output:    "unsafe\x00output",
	}
	if _, err := store.Finish(context.Background(), id, invalid, testEpoch.Add(4*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Finish(invalid output) error = %v, want ErrInvalid", err)
	}

	invalid.Output = strings.Repeat("x", maximumOutputBytes+1)
	if _, err := store.Finish(context.Background(), id, invalid, testEpoch.Add(4*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Finish(oversized output) error = %v, want ErrInvalid", err)
	}

	invalid.Output = ""
	invalid.Items = []ItemResult{
		{Name: "same", State: ItemCompleted, Code: "completed"},
		{Name: "same", State: ItemFailed, Code: "failed"},
	}
	if _, err := store.Finish(context.Background(), id, invalid, testEpoch.Add(4*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Finish(duplicate items) error = %v, want ErrInvalid", err)
	}
	invalid.Items = []ItemResult{{Name: "different", State: ItemCompleted, Code: "completed"}}
	if _, err := store.Finish(context.Background(), id, invalid, testEpoch.Add(4*time.Second)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Finish(changed reviewed scope) error = %v, want ErrInvalid", err)
	}
}

func TestStoreClaimsAtMostOnce(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	store, _ := NewStore(database)
	if _, err := store.Enqueue(context.Background(), strings.Repeat("b", 32), testRequest(), testEpoch); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errorsFound := make(chan error, 8)
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := store.Claim(context.Background(), testEpoch.Add(time.Second))
			errorsFound <- err
		}()
	}
	close(start)
	group.Wait()
	close(errorsFound)
	claimed := 0
	for err := range errorsFound {
		switch {
		case err == nil:
			claimed++
		case errors.Is(err, ErrNoQueued):
		default:
			t.Fatalf("Claim() error = %v", err)
		}
	}
	if claimed != 1 {
		t.Fatalf("successful claims = %d, want 1", claimed)
	}
}

func TestStoreRestartRecoveryNeverRequeuesRunningWork(t *testing.T) {
	t.Parallel()
	database := openTestDatabase(t)
	store, _ := NewStore(database)
	id := strings.Repeat("c", 32)
	if _, err := store.Enqueue(context.Background(), id, testRequest(), testEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(context.Background(), testEpoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	interrupted, changed, err := store.InterruptRunning(context.Background(), testEpoch.Add(2*time.Second))
	if err != nil {
		t.Fatalf("InterruptRunning() error = %v", err)
	}
	if !changed || interrupted.State != StateInterrupted || interrupted.Code != "service_restarted" ||
		interrupted.Inventory.State != InventoryPending || !interrupted.MayHaveChanged {
		t.Fatalf("interrupted operation = %#v", interrupted)
	}
	if len(interrupted.Items) != 1 || interrupted.Items[0].Name != "certificate" ||
		interrupted.Items[0].State != ItemAmbiguous || interrupted.Items[0].Code != "service_restarted" {
		t.Fatalf("interrupted items = %#v", interrupted.Items)
	}
	if _, err := store.Claim(context.Background(), testEpoch.Add(3*time.Second)); !errors.Is(err, ErrNoQueued) {
		t.Fatalf("Claim(after restart) error = %v, want ErrNoQueued", err)
	}
	if _, err := store.Enqueue(context.Background(), strings.Repeat("d", 32), testRequest(), testEpoch.Add(3*time.Second)); !errors.Is(err, ErrActive) {
		t.Fatalf("Enqueue(before reconciliation) error = %v, want ErrActive", err)
	}

	count := 4
	resolved, err := store.CompleteReconciliation(context.Background(), id, InventoryResult{
		State: InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
	}, testEpoch.Add(4*time.Second))
	if err != nil {
		t.Fatalf("CompleteReconciliation() error = %v", err)
	}
	if resolved.State != StateInterrupted || resolved.Inventory.CertificateCount == nil ||
		*resolved.Inventory.CertificateCount != 4 {
		t.Fatalf("resolved operation = %#v", resolved)
	}
}

func openTestDatabase(t *testing.T) *state.DB {
	t.Helper()
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("database.Close() error = %v", err)
		}
	})
	return database
}

func testRequest(items ...string) Request {
	if len(items) == 0 {
		items = []string{"certificate"}
	}
	return Request{ReviewedEvidenceSHA256: strings.Repeat("a", 64), Items: items}
}
