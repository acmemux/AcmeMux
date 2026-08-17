package operation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/broker"
	"github.com/acmemux/AcmeMux/internal/compatibility"
	"github.com/acmemux/AcmeMux/internal/configuration"
	"github.com/acmemux/AcmeMux/internal/inventory"
	"github.com/acmemux/AcmeMux/internal/jobs"
	"github.com/acmemux/AcmeMux/internal/state"
	"github.com/acmemux/AcmeMux/internal/workspace"
)

type fakeConfiguration struct {
	mu       sync.Mutex
	revision string
	intent   configuration.ExecutionIntent
	secret   []byte
	err      error
	errorAt  int
	errorFor error
	calls    int
}

func (fake *fakeConfiguration) PrepareExecution(context.Context, *workspace.Lease) (*configuration.ExecutionPlan, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.calls++
	if fake.errorAt != 0 && fake.calls == fake.errorAt {
		return nil, fake.errorFor
	}
	if fake.err != nil {
		return nil, fake.err
	}
	intent := cloneIntent(fake.intent)
	secrets := [][]byte(nil)
	if len(fake.secret) != 0 {
		secrets = [][]byte{slices.Clone(fake.secret)}
	}
	return &configuration.ExecutionPlan{
		Intent: intent, Revision: fake.revision,
		ReviewedEvidenceSHA256: fakeEvidence(fake.revision), ObservedSecrets: secrets,
	}, nil
}

func fakeEvidence(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (fake *fakeConfiguration) setRevision(value string) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.revision = value
}

func (fake *fakeConfiguration) setError(err error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.err = err
}

func (fake *fakeConfiguration) setErrorAt(call int, err error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.errorAt = call
	fake.errorFor = err
}

type fakeSelections struct{ selection workspace.Selection }

func (fake fakeSelections) Load(context.Context) (workspace.Selection, error) {
	return fake.selection, nil
}

type fakeInspector struct{ err error }

func (fake fakeInspector) Verify(_ context.Context, review workspace.Review) (workspace.Review, error) {
	return review, fake.err
}

type fakePrepared struct{ closes atomic.Int32 }

func (fake *fakePrepared) StartContext(context.Context, func(*exec.Cmd) error, ...string) (*exec.Cmd, error) {
	return nil, errors.New("fake prepared executable must be consumed by a fake")
}
func (fake *fakePrepared) Close() error { fake.closes.Add(1); return nil }

type fakeBroker struct {
	mu      sync.Mutex
	result  broker.Result
	err     error
	started chan struct{}
	release chan struct{}
	runs    int
	request broker.Request
}

func (fake *fakeBroker) Run(ctx context.Context, request broker.Request) (broker.Result, error) {
	fake.mu.Lock()
	fake.runs++
	fake.request = request
	started, release := fake.started, fake.release
	result, err := fake.result, fake.err
	fake.mu.Unlock()
	if started != nil {
		select {
		case <-started:
		default:
			close(started)
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return broker.Result{Outcome: broker.OutcomeInterrupted, Started: true, MayHaveChanged: true}, nil
		}
	}
	_ = request.Prepared.Close()
	return result, err
}

type fakeInventory struct {
	mu      sync.Mutex
	results [][]inventory.Certificate
	err     error
	reads   int
}

func (fake *fakeInventory) Read(_ context.Context, prepared inventory.PreparedExecutable, _ string) ([]inventory.Certificate, error) {
	_ = prepared.Close()
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.reads++
	if fake.err != nil {
		return nil, fake.err
	}
	if len(fake.results) == 0 {
		return []inventory.Certificate{}, nil
	}
	index := min(fake.reads-1, len(fake.results)-1)
	return slices.Clone(fake.results[index]), nil
}

func testIntent(directory string) configuration.ExecutionIntent {
	return configuration.ExecutionIntent{
		WorkingDirectory: directory, ConfigurationPath: filepath.Join(directory, ".lego.yml"),
		StoragePath: filepath.Join(directory, ".lego"), RuntimeIdentity: "v5.3.1",
		RuntimeManifestID: compatibility.ManifestLegoV531,
		Certificates: []configuration.ExecutionCertificate{{
			Name: "gateway", Domains: []string{"gateway.home.example"}, Account: "home",
			CA: "letsencrypt", ChallengeName: "web", ChallengeKind: "http-01", ChallengeMode: "listener",
		}},
	}
}

type operationFixture struct {
	service        *Service
	configuration  *fakeConfiguration
	broker         *fakeBroker
	inventory      *fakeInventory
	coordinator    *workspace.Coordinator
	database       *state.DB
	selection      workspace.Selection
	prepare        RuntimePreparer
	prepareCalls   *atomic.Int32
	prepareErrorAt *atomic.Int32
}

func newOperationFixture(t *testing.T) operationFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := state.Open(filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	coordinator, err := workspace.NewCoordinator(filepath.Join(directory, "workspace.lock"))
	if err != nil {
		t.Fatal(err)
	}
	intent := testIntent(directory)
	selection := workspace.Selection{Review: workspace.Review{
		Adoptable:        true,
		WorkingDirectory: workspace.PathEvidence{Role: workspace.RoleWorkingDirectory, Path: intent.WorkingDirectory, Safe: true, Exists: true},
		Configuration:    workspace.PathEvidence{Role: workspace.RoleConfiguration, Path: intent.ConfigurationPath, Safe: true, Exists: true},
		Storage:          workspace.PathEvidence{Role: workspace.RoleStorage, Path: intent.StoragePath, Safe: true, Exists: true},
	}}
	configurationService := &fakeConfiguration{revision: "reviewed-revision", intent: intent, secret: []byte("TASK08_SECRET")}
	brokerRunner := &fakeBroker{result: broker.Result{
		Outcome: broker.OutcomeSucceeded, Started: true, MayHaveChanged: true,
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), Stdout: "complete\n",
	}}
	inventoryReader := &fakeInventory{results: [][]inventory.Certificate{{}, {{Name: "gateway"}}}}
	var preparedMu sync.Mutex
	prepared := make([]*fakePrepared, 0)
	prepareCalls := &atomic.Int32{}
	prepareErrorAt := &atomic.Int32{}
	prepare := func(context.Context) (PreparedExecutable, error) {
		call := prepareCalls.Add(1)
		if prepareErrorAt.Load() == call {
			return nil, errors.New("runtime changed")
		}
		preparedMu.Lock()
		defer preparedMu.Unlock()
		handle := &fakePrepared{}
		prepared = append(prepared, handle)
		return handle, nil
	}
	service, err := New(Dependencies{
		Database: database, Coordinator: coordinator, Configuration: configurationService,
		WorkspaceSelections: fakeSelections{selection: selection}, WorkspaceInspector: fakeInspector{},
		PrepareRuntime: prepare, Broker: brokerRunner, Inventory: inventoryReader,
		Policy: DefaultPolicy(), Random: bytes.NewReader(bytes.Repeat([]byte{0x51}, 32)),
		JobOptions: []jobs.Option{
			jobs.WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x61}, 64))),
			jobs.WithPollInterval(time.Millisecond),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return operationFixture{
		service: service, configuration: configurationService, broker: brokerRunner,
		inventory: inventoryReader, coordinator: coordinator, database: database, selection: selection,
		prepare:      prepare,
		prepareCalls: prepareCalls, prepareErrorAt: prepareErrorAt,
	}
}

func waitForLatest(t *testing.T, service *Service) jobs.Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := service.Latest(context.Background())
		if err == nil {
			return operation
		}
		if !errors.Is(err, jobs.ErrNotFound) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation did not reach a terminal state")
	return jobs.Operation{}
}

func TestPreviewEnqueueAndRunSurviveBrowserRequestLifetime(t *testing.T) {
	fixture := newOperationFixture(t)
	fixture.broker.mu.Lock()
	fixture.broker.started = make(chan struct{})
	fixture.broker.release = make(chan struct{})
	started := fixture.broker.started
	release := fixture.broker.release
	fixture.broker.mu.Unlock()
	preview, err := fixture.service.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !validReviewToken(preview.ReviewedPreviewToken) || preview.Intent.Certificates[0].Name != "gateway" ||
		preview.Policy.Timeout != 30*time.Minute {
		t.Fatalf("preview = %#v", preview)
	}

	workerContext, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan error, 1)
	go func() { workerDone <- fixture.service.Run(workerContext) }()
	requestContext, cancelRequest := context.WithCancel(context.Background())
	var reauthorized atomic.Int32
	operation, err := fixture.service.Enqueue(requestContext, preview.ReviewedPreviewToken, func(context.Context) error {
		reauthorized.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not start")
	}
	cancelRequest()
	close(release)
	latest := waitForLatest(t, fixture.service)
	stopWorker()
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
	if latest.ID != operation.ID || latest.State != jobs.StateSucceeded || latest.Code != "execution_succeeded" ||
		latest.Inventory.State != jobs.InventoryRefreshed || len(latest.Items) != 1 ||
		latest.Items[0].State != jobs.ItemCompleted || reauthorized.Load() != 1 {
		t.Fatalf("latest = %#v, reauthorized=%d", latest, reauthorized.Load())
	}
}

func TestScheduledOperationUsesTheSameDurableExecutorPath(t *testing.T) {
	fixture := newOperationFixture(t)
	queued, err := fixture.service.EnqueueScheduled(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if queued.Kind != jobs.KindScheduled || queued.State != jobs.StateQueued {
		t.Fatalf("scheduled enqueue = %#v", queued)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.service.Run(ctx) }()
	latest := waitForLatest(t, fixture.service)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if latest.Kind != jobs.KindScheduled || latest.State != jobs.StateSucceeded ||
		latest.Code != "execution_succeeded" || latest.Inventory.State != jobs.InventoryRefreshed {
		t.Fatalf("scheduled result = %#v", latest)
	}
	fixture.broker.mu.Lock()
	runs := fixture.broker.runs
	request := fixture.broker.request
	fixture.broker.mu.Unlock()
	if runs != 1 {
		t.Fatalf("scheduled broker runs = %d, want 1", runs)
	}
	if request.WorkingDirectory != fixture.selection.Review.WorkingDirectory.Path ||
		request.ConfigurationPath != fixture.selection.Review.Configuration.Path || len(request.Environment) != 0 {
		t.Fatalf("scheduled broker request = %#v", request)
	}
}

func TestQueuedOperationFailsClosedWhenReviewedSourceChanges(t *testing.T) {
	fixture := newOperationFixture(t)
	preview, err := fixture.service.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	fixture.configuration.setRevision("changed-revision")
	workerContext, stopWorker := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.service.Run(workerContext) }()
	latest := waitForLatest(t, fixture.service)
	stopWorker()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if latest.State != jobs.StateNotAttempted || latest.Code != "reviewed_source_changed" ||
		latest.Items[0].State != jobs.ItemNotAttempted || latest.Inventory.State != jobs.InventoryRefreshed {
		t.Fatalf("latest = %#v", latest)
	}
}

func TestQueuedOperationRetainsReviewedEvidenceAcrossServiceRestart(t *testing.T) {
	fixture := newOperationFixture(t)
	preview, err := fixture.service.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	queued, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if queued.Request.ReviewedEvidenceSHA256 != fakeEvidence("reviewed-revision") ||
		len(queued.Request.Items) != 1 || queued.Request.Items[0] != "gateway" {
		t.Fatalf("persisted request = %#v", queued.Request)
	}

	restarted, err := New(Dependencies{
		Database: fixture.database, Coordinator: fixture.coordinator, Configuration: fixture.configuration,
		WorkspaceSelections: fakeSelections{selection: fixture.selection}, WorkspaceInspector: fakeInspector{},
		PrepareRuntime: fixture.prepare, Broker: fixture.broker, Inventory: fixture.inventory,
		Policy: DefaultPolicy(), Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 32)),
		JobOptions: []jobs.Option{
			jobs.WithRandom(bytes.NewReader(bytes.Repeat([]byte{0x72}, 32))),
			jobs.WithPollInterval(time.Millisecond),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.Run(ctx) }()
	latest := waitForLatest(t, restarted)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if latest.State != jobs.StateSucceeded || latest.Code != "execution_succeeded" {
		t.Fatalf("restarted result = %#v", latest)
	}
}

func TestAcceptedOperationRecordsWorkspaceContentionWithoutRetry(t *testing.T) {
	fixture := newOperationFixture(t)
	preview, err := fixture.service.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.coordinator.TryAcquire(context.Background(), workspace.PurposeSave)
	if err != nil {
		t.Fatal(err)
	}
	workerContext, stopWorker := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.service.Run(workerContext) }()
	latest := waitForLatest(t, fixture.service)
	_ = lease.Release()
	stopWorker()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	fixture.broker.mu.Lock()
	runs := fixture.broker.runs
	fixture.broker.mu.Unlock()
	if latest.State != jobs.StateNotAttempted || latest.Code != "workspace_busy" || runs != 0 {
		t.Fatalf("latest=%#v broker runs=%d", latest, runs)
	}
}

func TestAcceptedOperationClassifiesFreshCompatibilityFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code string
	}{
		{name: "runtime", err: errors.Join(configuration.ErrChanged, configuration.ErrRuntimeChanged), code: "runtime_incompatible"},
		{name: "configuration", err: configuration.ErrInvalid, code: "configuration_incompatible"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperationFixture(t)
			preview, err := fixture.service.Preview(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			fixture.configuration.setError(test.err)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- fixture.service.Run(ctx) }()
			latest := waitForLatest(t, fixture.service)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if latest.State != jobs.StateIncompatible || latest.Code != test.code ||
				len(latest.Items) != 1 || latest.Items[0].State != jobs.ItemNotAttempted {
				t.Fatalf("incompatible result = %#v", latest)
			}
		})
	}
}

func TestAcceptedOperationPreservesRuntimeIncompatibilityAcrossEveryPreStartWindow(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*operationFixture)
	}{
		{name: "inventory preflight", setup: func(fixture *operationFixture) {
			fixture.prepareErrorAt.Store(1)
		}},
		{name: "source confirmation", setup: func(fixture *operationFixture) {
			fixture.configuration.setErrorAt(4, errors.Join(configuration.ErrChanged, configuration.ErrRuntimeChanged))
		}},
		{name: "final executable preparation", setup: func(fixture *operationFixture) {
			fixture.prepareErrorAt.Store(2)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOperationFixture(t)
			preview, err := fixture.service.Preview(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}
			test.setup(&fixture)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- fixture.service.Run(ctx) }()
			latest := waitForLatest(t, fixture.service)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if latest.State != jobs.StateIncompatible || latest.Code != "runtime_incompatible" ||
				len(latest.Items) != 1 || latest.Items[0].State != jobs.ItemNotAttempted {
				t.Fatalf("runtime incompatibility = %#v", latest)
			}
		})
	}
}

func TestAcceptedOperationReportsPostRunRuntimeDriftWithoutRelabelingNativeEvidence(t *testing.T) {
	fixture := newOperationFixture(t)
	preview, err := fixture.service.Preview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Enqueue(context.Background(), preview.ReviewedPreviewToken, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	fixture.configuration.setErrorAt(5, errors.Join(configuration.ErrChanged, configuration.ErrRuntimeChanged))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.service.Run(ctx) }()
	latest := waitForLatest(t, fixture.service)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if latest.State != jobs.StateAmbiguous || latest.Code != "runtime_changed_after_run" ||
		len(latest.Items) != 1 || latest.Items[0].State != jobs.ItemCompleted {
		t.Fatalf("post-run runtime drift = %#v", latest)
	}
}

func TestExecutorRefreshesInventoryAfterTerminalPhasePersistenceFailure(t *testing.T) {
	fixture := newOperationFixture(t)
	result := fixture.service.executor.Execute(context.Background(), strings.Repeat("a", 32), jobs.Request{
		ReviewedEvidenceSHA256: fakeEvidence("reviewed-revision"), Items: []string{"gateway"},
	}, func(phase jobs.Phase) error {
		if phase == jobs.PhaseRefreshingInventory {
			return errors.New("persist phase")
		}
		return nil
	})
	fixture.inventory.mu.Lock()
	reads := fixture.inventory.reads
	fixture.inventory.mu.Unlock()
	if reads != 2 || result.Inventory.State != jobs.InventoryRefreshed ||
		result.State != jobs.StateAmbiguous || result.Code != "phase_persistence_failed" ||
		len(result.Items) != 1 || result.Items[0].State != jobs.ItemCompleted {
		t.Fatalf("terminal phase failure result = %#v, inventory reads=%d", result, reads)
	}
}

func TestClassifyExecutionPreservesChangedArtifactsAfterStartedBrokerError(t *testing.T) {
	certificates := []configuration.ExecutionCertificate{{Name: "changed"}, {Name: "uncertain"}}
	before := []inventory.Certificate{{Name: "changed"}, {Name: "uncertain"}}
	after := []inventory.Certificate{{Name: "changed", Issuer: "new"}, {Name: "uncertain"}}
	count := len(after)
	result := classifyExecution(broker.Result{
		Outcome: broker.OutcomeAmbiguous, Started: true, MayHaveChanged: true,
	}, &broker.Error{Code: broker.CodePreparedCloseFailed}, certificates, before, after, jobs.InventoryResult{
		State: jobs.InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
	}, "")
	if result.State != jobs.StateAmbiguous || result.Code != "broker_prepared_close_failed" ||
		len(result.Items) != 2 || result.Items[0].State != jobs.ItemCompleted ||
		result.Items[0].Code != "native_artifact_changed" || result.Items[1].State != jobs.ItemAmbiguous {
		t.Fatalf("started broker error result = %#v", result)
	}
}

func TestClassifyExecutionUsesExactUpstreamRenewalMarkerWithoutInventingFailFastOrder(t *testing.T) {
	certificates := []configuration.ExecutionCertificate{
		{Name: "first"}, {Name: "second"}, {Name: "unobserved"},
	}
	before := []inventory.Certificate{{Name: "first"}, {Name: "second"}, {Name: "unobserved"}}
	after := []inventory.Certificate{{Name: "first", Issuer: "changed"}, {Name: "second"}, {Name: "unobserved"}}
	count := len(after)
	result := classifyExecution(broker.Result{
		Outcome: broker.OutcomeFailed, Started: true, MayHaveChanged: true,
		Stdout: "2026-08-16T12:00:00.000000000Z INF Trying renewal. cert-name=second time-remaining=1h\n",
	}, nil, certificates, before, after, jobs.InventoryResult{
		State: jobs.InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
	}, "")
	if result.State != jobs.StatePartial || result.Code != "execution_partial" || len(result.Items) != 3 ||
		result.Items[0].State != jobs.ItemCompleted || result.Items[1].State != jobs.ItemFailed ||
		result.Items[1].Code != "upstream_renewal_failed" || result.Items[2].State != jobs.ItemAmbiguous {
		t.Fatalf("classified renewal failure = %#v", result)
	}

	for _, output := range []string{
		"remote text mentioned cert-name=second without the supported marker\n",
		`2026-08-16T12:00:00.000000000Z ERR Error error="remote detail: Trying renewal. cert-name=second time-remaining=1h"` + "\n",
		"2026-08-16T12:00:00.000000000Z INF Trying renewal. cert-name=second time-remaining=not-a-duration\n",
	} {
		result = classifyExecution(broker.Result{
			Outcome: broker.OutcomeFailed, Started: true, MayHaveChanged: true, Stdout: output,
		}, nil, certificates, before, before, jobs.InventoryResult{
			State: jobs.InventoryRefreshed, Code: "inventory_refreshed", CertificateCount: &count,
		}, "")
		for _, item := range result.Items {
			if item.State != jobs.ItemAmbiguous {
				t.Fatalf("untrusted output invented certificate failure: output=%q items=%#v", output, result.Items)
			}
		}
	}
}
