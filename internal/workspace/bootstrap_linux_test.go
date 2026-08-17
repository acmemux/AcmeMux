//go:build linux

package workspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/acmemux/AcmeMux/internal/state"
)

const bootstrapYAML = "storage: ../storage\n"

type bootstrapFixture struct {
	stateDirectory string
	working        string
	configuration  string
	storage        string
	store          *Store
	journal        *JournalStore
	coordinator    *Coordinator
	inspector      *Inspector
	manager        *TransactionManager
	database       *state.DB
}

func TestBootstrapCreatesConventionalConfigurationAndAdoptsWorkspace(t *testing.T) {
	fixture := newBootstrapFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeBootstrap)
	defer lease.Release()
	candidate := []byte(bootstrapYAML)
	plan := bootstrapPlan(fixture, candidate)
	audit, err := fixture.manager.AuditBootstrap(context.Background(), lease, plan.Request, candidate, plan.Replacements)
	if err != nil {
		t.Fatalf("AuditBootstrap() error = %v", err)
	}
	if audit.ConfigurationSource != ConfigurationConventionalYML || audit.Configuration.Path != fixture.configuration ||
		audit.Configuration.Evidence.Type != PathTypeMissing || audit.Storage.Path != fixture.storage {
		t.Fatalf("bootstrap audit = %#v", audit)
	}
	selection, err := fixture.manager.Bootstrap(context.Background(), lease, plan, allowCommit)
	if err != nil {
		t.Fatalf("Bootstrap() error = %v", err)
	}
	if got := readFile(t, fixture.configuration); !bytes.Equal(got, candidate) {
		t.Fatalf("configuration = %q", got)
	}
	stored, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertStoredSelectionEqual(t, stored, selection)
	if _, err := fixture.journal.Load(context.Background()); !errors.Is(err, ErrNoEditJournal) {
		t.Fatalf("journal error = %v", err)
	}
}

func TestBootstrapPersistsEABSecretOnlyInRestrictedNativeYAML(t *testing.T) {
	fixture := newBootstrapFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeBootstrap)
	defer lease.Release()
	candidate := []byte(`storage: ../storage
accounts:
  home:
    server: googletrust
    eab:
      kid: public-kid
      hmacKey: AQIDBAUGBwgJ-secret-journal-canary
`)
	plan := bootstrapPlan(fixture, candidate)
	if _, err := fixture.manager.Bootstrap(context.Background(), lease, plan, allowCommit); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fixture.configuration)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !bytes.Equal(readFile(t, fixture.configuration), candidate) {
		t.Fatalf("native YAML mode/content = %o/%q", info.Mode().Perm(), readFile(t, fixture.configuration))
	}
	assertBootstrapJournalExcludesCandidate(t, fixture, candidate)
}

func TestBootstrapNeverOverwritesTargetCreatedAfterPreview(t *testing.T) {
	fixture := newBootstrapFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeBootstrap)
	defer lease.Release()
	plan := bootstrapPlan(fixture, []byte(bootstrapYAML))
	if _, err := fixture.manager.AuditBootstrap(context.Background(), lease, plan.Request, plan.CandidateConfiguration, plan.Replacements); err != nil {
		t.Fatal(err)
	}
	const external = "storage: /external\n"
	writeFile(t, fixture.configuration, []byte(external), 0o600)
	if _, err := fixture.manager.Bootstrap(context.Background(), lease, plan, allowCommit); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("Bootstrap() error = %v, want ErrSourceChanged", err)
	}
	if got := string(readFile(t, fixture.configuration)); got != external {
		t.Fatalf("external target was overwritten: %q", got)
	}
	if _, err := fixture.store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("selection error = %v, want ErrNoSelection", err)
	}
}

func TestBootstrapRejectsConventionalAlternateAppearingAfterActivation(t *testing.T) {
	fixture := newBootstrapFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterRename {
			writeFile(t, filepath.Join(fixture.working, ".lego.yaml"), []byte("storage: ../storage\n"), 0o600)
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeRecovery)
	defer lease.Release()
	plan := bootstrapPlan(fixture, []byte(bootstrapYAML))
	if _, err := manager.Bootstrap(context.Background(), lease, plan, allowCommit); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Bootstrap() error = %v, want ErrRecoveryRequired", err)
	}
	if _, err := fixture.store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("selection error = %v, want ErrNoSelection", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil || !recovery.Bootstrap || recovery.State != RecoveryApplied {
		t.Fatalf("recovery = %#v, error = %v", recovery, err)
	}
	if _, err := manager.ResolveRecovery(
		context.Background(), lease, ResolutionAdoptCurrent, allowCommit,
		func(context.Context, *SourceSet) error { return nil },
	); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("ResolveRecovery() error = %v, want ErrRecoveryRequired", err)
	}
	if _, err := fixture.store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("selection after rejected recovery = %v, want ErrNoSelection", err)
	}
}

func TestBootstrapRecoveryDiscardsWhollyUnappliedWithoutSelection(t *testing.T) {
	fixture := newBootstrapFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterStage {
			return errors.New("simulated crash after stage")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeRecovery)
	defer lease.Release()
	plan := bootstrapPlan(fixture, []byte(bootstrapYAML))
	if _, err := manager.Bootstrap(context.Background(), lease, plan, allowCommit); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Bootstrap() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil || !recovery.Bootstrap || recovery.State != RecoveryUnapplied {
		t.Fatalf("recovery = %#v, error = %v", recovery, err)
	}
	result, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil)
	if err != nil {
		t.Fatalf("ResolveRecovery(discard) error = %v", err)
	}
	if result.SelectionPresent {
		t.Fatal("discarded bootstrap unexpectedly returned a workspace selection")
	}
	if _, err := os.Lstat(fixture.configuration); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("configuration target error = %v, want missing", err)
	}
	if _, err := fixture.store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("selection error = %v, want ErrNoSelection", err)
	}
	assertBootstrapClean(t, fixture)
}

func TestBootstrapRecoveryRequiresExplicitAdoptionAfterActivation(t *testing.T) {
	fixture := newBootstrapFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureBeforeFinalize {
			return errors.New("simulated crash before selection finalization")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeRecovery)
	defer lease.Release()
	plan := bootstrapPlan(fixture, []byte(bootstrapYAML))
	if _, err := manager.Bootstrap(context.Background(), lease, plan, allowCommit); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Bootstrap() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil || !recovery.Bootstrap || recovery.State != RecoveryApplied {
		t.Fatalf("recovery = %#v, error = %v", recovery, err)
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionFinalizeApplied, allowCommit, func(context.Context, *SourceSet) error { return nil }); !errors.Is(err, ErrInvalidEdit) {
		t.Fatalf("ResolveRecovery(finalize) error = %v, want ErrInvalidEdit", err)
	}
	validatorCalls := 0
	result, err := manager.ResolveRecovery(context.Background(), lease, ResolutionAdoptCurrent, allowCommit, func(_ context.Context, sources *SourceSet) error {
		validatorCalls++
		if !bytes.Equal(sources.Configuration.Content, []byte(bootstrapYAML)) {
			return errors.New("unexpected active bootstrap content")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ResolveRecovery(adopt_current) error = %v", err)
	}
	if validatorCalls != 1 || !result.SelectionPresent {
		t.Fatalf("validator calls = %d, result = %#v", validatorCalls, result)
	}
	stored, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertStoredSelectionEqual(t, stored, result.Selection)
	assertBootstrapClean(t, fixture)
}

func TestBootstrapFailureBoundariesRemainSecretFreeAndRecoverable(t *testing.T) {
	tests := []struct {
		name    string
		point   FailurePoint
		applied bool
		store   bool
		state   RecoveryState
	}{
		{name: "after journal", point: FailureAfterJournal, state: RecoveryUnapplied},
		{name: "after prepared", point: FailureAfterPrepared, state: RecoveryUnapplied},
		// A raw rename is applied when the retained candidate identity still
		// proves the placement, and ambiguous when rename changed its ctime.
		// Both paths require explicit adopt_current for bootstrap recovery.
		{name: "after rename before placement record", point: FailureAfterRename, applied: true},
		{name: "before finalization", point: FailureBeforeFinalize, applied: true, state: RecoveryApplied},
		{name: "finalization store failure", point: FailureBeforeFinalize, applied: true, store: true, state: RecoveryApplied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBootstrapFixture(t)
			var failingStore *failOnceStoreDatabase
			if test.store {
				failingStore = &failOnceStoreDatabase{database: fixture.database}
				store, err := NewStore(failingStore)
				if err != nil {
					t.Fatal(err)
				}
				fixture.store = store
			}
			manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
				if point != test.point {
					return nil
				}
				if test.store {
					failingStore.failNext = true
					return nil
				}
				return errors.New("simulated bootstrap interruption")
			}))
			lease := acquireLease(t, fixture.coordinator, PurposeRecovery)
			defer lease.Release()
			candidate := []byte(bootstrapYAML + "# AQIDBAUGBwgJ-secret-journal-canary\n")
			plan := bootstrapPlan(fixture, candidate)
			if _, err := manager.Bootstrap(context.Background(), lease, plan, allowCommit); !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("Bootstrap() error = %v, want ErrRecoveryRequired", err)
			}
			if _, err := fixture.store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
				t.Fatalf("selection before recovery error = %v, want ErrNoSelection", err)
			}
			recovery, err := manager.InspectRecovery(context.Background(), lease)
			if err != nil || !recovery.Bootstrap {
				t.Fatalf("recovery = %#v, error = %v", recovery, err)
			}
			validRawRename := test.point == FailureAfterRename &&
				(recovery.State == RecoveryApplied || recovery.State == RecoveryAmbiguous)
			if recovery.State != test.state && !validRawRename {
				t.Fatalf("recovery state = %s, want %s (%#v)", recovery.State, test.state, recovery)
			}
			assertBootstrapJournalExcludesCandidate(t, fixture, candidate)
			journal, err := fixture.journal.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range journal.Files {
				stage := filepath.Join(file.ParentPath, file.StageBasename)
				info, statErr := os.Stat(stage)
				if statErr == nil {
					if info.Mode().Perm() != 0o600 || !bytes.Equal(readFile(t, stage), candidate) {
						t.Fatalf("staged candidate mode/content = %o/%q", info.Mode().Perm(), readFile(t, stage))
					}
				} else if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal(statErr)
				}
			}
			if test.applied {
				info, err := os.Stat(fixture.configuration)
				if err != nil || info.Mode().Perm() != 0o600 || !bytes.Equal(readFile(t, fixture.configuration), candidate) {
					t.Fatalf("active candidate mode/content = %#v/%q, error = %v", info, readFile(t, fixture.configuration), err)
				}
				if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionFinalizeApplied, allowCommit, func(context.Context, *SourceSet) error { return nil }); !errors.Is(err, ErrInvalidEdit) {
					t.Fatalf("FinalizeApplied() error = %v, want ErrInvalidEdit", err)
				}
				result, err := manager.ResolveRecovery(context.Background(), lease, ResolutionAdoptCurrent, allowCommit, func(_ context.Context, sources *SourceSet) error {
					if !bytes.Equal(sources.Configuration.Content, candidate) {
						return errors.New("active bootstrap candidate changed")
					}
					return nil
				})
				if err != nil || !result.SelectionPresent {
					t.Fatalf("AdoptCurrent() result = %#v, error = %v", result, err)
				}
			} else {
				result, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil)
				if err != nil || result.SelectionPresent {
					t.Fatalf("DiscardUnapplied() result = %#v, error = %v", result, err)
				}
				if _, err := os.Lstat(fixture.configuration); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("discarded target error = %v, want missing", err)
				}
			}
			assertBootstrapClean(t, fixture)
		})
	}
}

type failOnceStoreDatabase struct {
	database *state.DB
	failNext bool
}

func (database *failOnceStoreDatabase) BeginTx(ctx context.Context, options *sql.TxOptions) (*sql.Tx, error) {
	if database.failNext {
		database.failNext = false
		return nil, errors.New("simulated selection finalization failure")
	}
	return database.database.BeginTx(ctx, options)
}

func newBootstrapFixture(t *testing.T) *bootstrapFixture {
	t.Helper()
	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	storage := mkdir(t, filepath.Join(root, "storage"), 0o700)
	stateDirectory := mkdir(t, filepath.Join(root, "state"), 0o700)
	database, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournalStore(database)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCoordinator(filepath.Join(stateDirectory, "workspace.lock"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &bootstrapFixture{
		stateDirectory: stateDirectory, working: working, configuration: filepath.Join(working, ".lego.yml"), storage: storage,
		store: store, journal: journal, coordinator: coordinator, inspector: inspector,
		database: database,
	}
	fixture.manager = fixture.managerWith(t)
	return fixture
}

func assertBootstrapJournalExcludesCandidate(t *testing.T, fixture *bootstrapFixture, candidate []byte) {
	t.Helper()
	digest := sha256.Sum256(candidate)
	canary := []byte("AQIDBAUGBwgJ-secret-journal-canary")
	digestText := []byte(hex.EncodeToString(digest[:]))
	entries, err := os.ReadDir(fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(fixture.stateDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, canary) || bytes.Contains(contents, candidate) || bytes.Contains(contents, digestText) {
			t.Fatalf("application state file %s retained candidate content or digest", entry.Name())
		}
	}
}

func (fixture *bootstrapFixture) managerWith(t *testing.T, options ...TransactionOption) *TransactionManager {
	t.Helper()
	manager, err := NewTransactionManager(fixture.inspector, fixture.store, fixture.journal, fixture.coordinator, options...)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func bootstrapPlan(fixture *bootstrapFixture, candidate []byte) BootstrapPlan {
	return BootstrapPlan{
		Request:                BootstrapRequest{WorkingDirectory: fixture.working},
		CandidateConfiguration: candidate,
		Replacements:           []Replacement{{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate}},
	}
}

func assertBootstrapClean(t *testing.T, fixture *bootstrapFixture) {
	t.Helper()
	if _, err := fixture.journal.Load(context.Background()); !errors.Is(err, ErrNoEditJournal) {
		t.Fatalf("journal error = %v, want ErrNoEditJournal", err)
	}
	entries, err := os.ReadDir(fixture.working)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry.Name()) >= len(".acmemux-edit-") && entry.Name()[:len(".acmemux-edit-")] == ".acmemux-edit-" {
			t.Fatalf("bootstrap stage remains: %s", entry.Name())
		}
	}
}
