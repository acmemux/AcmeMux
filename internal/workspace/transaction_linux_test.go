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
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

const (
	transactionOldDotenv = "TOKEN=old-provider-secret\n"
	transactionYAML      = `storage: ../storage
challenges:
  dns:
    dns:
      provider: cloudflare
      envFile: ../secrets/provider.env
`
)

type transactionFixture struct {
	root           string
	stateDirectory string
	working        string
	configuration  string
	dotenv         string
	database       *state.DB
	inspector      *Inspector
	store          *Store
	journal        *JournalStore
	coordinator    *Coordinator
	manager        *TransactionManager
}

func TestTransactionCommitReplacesDotenvBeforeConfigurationAndFinalizesSelection(t *testing.T) {
	fixture := newTransactionFixture(t)
	var observedCanonicalOrder bool
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, ordinal int) error {
		if point != FailureAfterAppliedRecord || ordinal != 0 {
			return nil
		}
		observedCanonicalOrder = bytes.Equal(readFile(t, fixture.dotenv), []byte("TOKEN=new-provider-secret\n")) &&
			bytes.Equal(readFile(t, fixture.configuration), []byte(transactionYAML))
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()

	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	candidate := append(append([]byte(nil), sources.Configuration.Content...), []byte("# reviewed edit\n")...)
	replacements := []Replacement{
		{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate},
		{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=new-provider-secret\n")},
	}
	audit, err := manager.AuditCandidate(context.Background(), lease, sources, candidate, replacements)
	if err != nil {
		t.Fatalf("AuditCandidate() error = %v", err)
	}
	if len(audit.Dotenv) != 1 || !audit.Dotenv[0].Exists || audit.Dotenv[0].WillCreate {
		t.Fatalf("dotenv audit = %#v", audit.Dotenv)
	}
	guardCalls := 0
	selection, err := manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: candidate, Replacements: replacements,
	}, func(context.Context) error {
		guardCalls++
		return nil
	})
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if guardCalls != 1 || !observedCanonicalOrder {
		t.Fatalf("guard calls = %d, observed dotenv-first ordering = %v", guardCalls, observedCanonicalOrder)
	}
	if got := readFile(t, fixture.configuration); !bytes.Equal(got, candidate) {
		t.Fatalf("configuration = %q, want %q", got, candidate)
	}
	if got := readFile(t, fixture.dotenv); string(got) != "TOKEN=new-provider-secret\n" {
		t.Fatalf("dotenv = %q", got)
	}
	if _, err := fixture.journal.Load(context.Background()); !errors.Is(err, ErrNoEditJournal) {
		t.Fatalf("Load(journal) error = %v, want ErrNoEditJournal", err)
	}
	loaded, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(selection) error = %v", err)
	}
	assertStoredSelectionEqual(t, loaded, selection)

	sources.Close()
	if sources.Configuration.Content != nil || sources.Configuration.Fingerprint != (SourceFingerprint{}) ||
		len(sources.Dotenv) != 1 || sources.Dotenv[0].Content != nil || sources.Dotenv[0].Fingerprint != (SourceFingerprint{}) {
		t.Fatalf("Close() retained source content or fingerprint: %#v", sources)
	}
}

func TestTransactionCommitValidatesOneReplacementAcrossSharedDotenvReferences(t *testing.T) {
	fixture := newTransactionFixture(t)
	sharedYAML := []byte(`storage: ../storage
challenges:
  first:
    dns:
      provider: cloudflare
      envFile: ../secrets/provider.env
  second:
    dns:
      provider: cloudflare
      envFile: ../secrets/provider.env
`)
	if err := os.WriteFile(fixture.configuration, sharedYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	review, err := fixture.inspector.Inspect(context.Background(), Request{WorkingDirectory: fixture.working})
	if err != nil || !review.Adoptable || len(review.DotenvFiles) != 2 {
		t.Fatalf("shared review = %#v, %v", review, err)
	}
	if err := fixture.store.Save(context.Background(), Selection{
		Review: review, ReviewedAt: review.ObservedAt.Add(time.Nanosecond),
	}); err != nil {
		t.Fatal(err)
	}
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	if len(sources.Dotenv) != 2 || sources.Dotenv[0].Path != sources.Dotenv[1].Path {
		t.Fatalf("shared source evidence = %#v", sources.Dotenv)
	}
	_, err = fixture.manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{
			Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=shared-replacement\n"),
		}},
	}, allowCommit)
	if err != nil {
		t.Fatalf("Commit(shared dotenv) error = %v", err)
	}
	if got := string(readFile(t, fixture.dotenv)); got != "TOKEN=shared-replacement\n" {
		t.Fatalf("shared dotenv = %q", got)
	}
	assertNoJournalOrStages(t, fixture)
}

func TestTransactionCommitCreatesMissingCandidateDotenvWithoutOverwrite(t *testing.T) {
	fixture := newTransactionFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	created := filepath.Join(filepath.Dir(fixture.dotenv), "created.env")
	candidate := bytes.Replace(sources.Configuration.Content,
		[]byte("../secrets/provider.env"), []byte("../secrets/created.env"), 1)
	replacements := []Replacement{
		{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate},
		{Role: RoleDotenv, Path: created, Content: []byte("TOKEN=created-secret\n")},
	}
	audit, err := fixture.manager.AuditCandidate(context.Background(), lease, sources, candidate, replacements)
	if err != nil {
		t.Fatalf("AuditCandidate() error = %v", err)
	}
	if len(audit.Dotenv) != 1 || audit.Dotenv[0].Exists || !audit.Dotenv[0].WillCreate || audit.Dotenv[0].Path != created {
		t.Fatalf("created dotenv audit = %#v", audit.Dotenv)
	}
	if _, err := fixture.manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: candidate, Replacements: replacements,
	}, allowCommit); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	info, err := os.Lstat(created)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("created dotenv mode = %v", info.Mode())
	}
	if got := readFile(t, created); string(got) != "TOKEN=created-secret\n" {
		t.Fatalf("created dotenv = %q", got)
	}
	if got := readFile(t, fixture.dotenv); string(got) != transactionOldDotenv {
		t.Fatalf("unreferenced dotenv was changed: %q", got)
	}
}

func TestAuditCandidateRejectsExistingDotenvOutsideReviewedSourceSet(t *testing.T) {
	fixture := newTransactionFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposePreview)
	defer lease.Release()
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	unreviewed := writeFile(t, filepath.Join(filepath.Dir(fixture.dotenv), "unreviewed.env"), []byte("TOKEN=unreviewed\n"), 0o600)
	candidate := bytes.Replace(sources.Configuration.Content,
		[]byte("../secrets/provider.env"), []byte("../secrets/unreviewed.env"), 1)
	replacements := []Replacement{{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate}}
	if _, err := fixture.manager.AuditCandidate(context.Background(), lease, sources, candidate, replacements); !errors.Is(err, ErrInvalidEdit) {
		t.Fatalf("AuditCandidate(existing unreviewed %s) error = %v, want ErrInvalidEdit", unreviewed, err)
	}
}

func TestTransactionDetectsChangeBetweenRecheckAndExchangeWithoutOverwritingIt(t *testing.T) {
	fixture := newTransactionFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	external := []byte("TOKEN=external-writer\n")
	_, err = fixture.manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{
			Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=managed-candidate\n"),
		}},
	}, func(context.Context) error {
		if err := os.WriteFile(fixture.dotenv, external, 0o600); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("Commit() error = %v, want ErrSourceChanged", err)
	}
	if got := readFile(t, fixture.dotenv); !bytes.Equal(got, external) {
		t.Fatalf("external content was overwritten: %q", got)
	}
	if _, err := fixture.journal.Load(context.Background()); !errors.Is(err, ErrNoEditJournal) {
		t.Fatalf("Load(journal) error = %v, want ErrNoEditJournal", err)
	}
}

func TestTransactionRetainsDisplacedExternalWriteBeforeCleanup(t *testing.T) {
	fixture := newTransactionFixture(t)
	original, err := os.OpenFile(fixture.dotenv, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	external := []byte("TOKEN=external-through-open-fd\n")
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point != FailureBeforeOldUnlink {
			return nil
		}
		if err := original.Truncate(0); err != nil {
			return err
		}
		if _, err := original.WriteAt(external, 0); err != nil {
			return err
		}
		return original.Sync()
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=managed\n")}},
	}, allowCommit)
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("Commit() error = %v, want ErrSourceChanged", err)
	}
	journal, err := fixture.journal.Load(context.Background())
	if err != nil || len(journal.Files) != 1 {
		t.Fatalf("Load(journal) = %#v, %v", journal, err)
	}
	displacedPath := filepath.Join(journal.Files[0].ParentPath, journal.Files[0].StageBasename)
	if got := readFile(t, displacedPath); !bytes.Equal(got, external) {
		t.Fatalf("external displaced write was lost: %q", got)
	}
}

func TestCleanupCrashBoundariesRemainRecoverableWithoutTouchingForeignFiles(t *testing.T) {
	for _, test := range []struct {
		point         FailurePoint
		wantRecovery  RecoveryState
		externalAdopt bool
	}{
		{point: FailureAfterCleanupRename, wantRecovery: RecoveryAmbiguous, externalAdopt: true},
		{point: FailureAfterCleanupScrub, wantRecovery: RecoveryAmbiguous, externalAdopt: true},
		{point: FailureAfterCleanupUnlink, wantRecovery: RecoveryApplied},
	} {
		t.Run(string(test.point), func(t *testing.T) {
			fixture := newTransactionFixture(t)
			foreignPath := filepath.Join(filepath.Dir(fixture.dotenv), "foreign.keep")
			const foreign = "foreign-content-must-survive"
			writeFile(t, foreignPath, []byte(foreign), 0o600)
			triggered := false
			manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
				if point == test.point && !triggered {
					triggered = true
					return errors.New("simulated cleanup interruption")
				}
				return nil
			}))
			lease := acquireLease(t, fixture.coordinator, PurposeSave)
			defer lease.Release()
			sources, err := manager.Snapshot(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			defer sources.Close()
			const active = "TOKEN=active-cleanup-candidate\n"
			_, err = manager.Commit(context.Background(), lease, CommitPlan{
				Sources: sources, CandidateConfiguration: sources.Configuration.Content,
				Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(active)}},
			}, allowCommit)
			if !errors.Is(err, ErrRecoveryRequired) || !triggered {
				t.Fatalf("Commit() error = %v, want injected recovery", err)
			}
			if got := string(readFile(t, fixture.dotenv)); got != active {
				t.Fatalf("active candidate was replayed or rolled back: %q", got)
			}
			if got := string(readFile(t, foreignPath)); got != foreign {
				t.Fatalf("foreign file changed: %q", got)
			}
			recovery, err := manager.InspectRecovery(context.Background(), lease)
			if err != nil || recovery.State != test.wantRecovery {
				t.Fatalf("InspectRecovery() = %#v, %v", recovery, err)
			}
			resolution := ResolutionFinalizeApplied
			if test.externalAdopt {
				journal, loadErr := fixture.journal.Load(context.Background())
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				cleanupPath := filepath.Join(
					journal.Files[0].ParentPath,
					cleanupBasename(journal.Files[0].StageBasename),
				)
				if removeErr := os.Remove(cleanupPath); removeErr != nil {
					t.Fatal(removeErr)
				}
				resolution = ResolutionAdoptCurrent
			}
			if _, err := manager.ResolveRecovery(
				context.Background(), lease, resolution, allowCommit,
				func(context.Context, *SourceSet) error { return nil },
			); err != nil {
				t.Fatalf("ResolveRecovery(%s) error = %v", resolution, err)
			}
			if got := string(readFile(t, foreignPath)); got != foreign {
				t.Fatalf("foreign file changed during resolution: %q", got)
			}
			assertNoJournalOrStages(t, fixture)
		})
	}
}

func TestTransactionRejectsUnmodifiedSourceChangeDuringCommitGuard(t *testing.T) {
	fixture := newTransactionFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	candidate := append(append([]byte(nil), sources.Configuration.Content...), []byte("# configuration-only edit\n")...)
	external := []byte("TOKEN=external-during-guard\n")
	_, err = fixture.manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: candidate,
		Replacements: []Replacement{{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate}},
	}, func(context.Context) error {
		return os.WriteFile(fixture.dotenv, external, 0o600)
	})
	if !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("Commit() error = %v, want ErrSourceChanged", err)
	}
	if got := readFile(t, fixture.dotenv); !bytes.Equal(got, external) {
		t.Fatalf("external dotenv change was lost: %q", got)
	}
	assertNoJournalOrStages(t, fixture)
}

func TestRecoveryDiscardsWhollyUnappliedCandidatesWithoutReplay(t *testing.T) {
	fixture := newTransactionFixture(t)
	sentinel := errors.New("stop after prepare")
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterPrepared {
			return sentinel
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()

	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=discard-me\n")}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.State != RecoveryUnapplied || len(recovery.Files) != 1 || recovery.Files[0].State != RecoveryFileUnapplied {
		t.Fatalf("recovery = %#v", recovery)
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil); err != nil {
		t.Fatalf("ResolveRecovery(discard) error = %v", err)
	}
	if got := readFile(t, fixture.dotenv); string(got) != transactionOldDotenv {
		t.Fatalf("unapplied candidate was replayed: %q", got)
	}
	assertNoJournalOrStages(t, fixture)
}

func TestRecoveryFinalizesWhollyAppliedCandidateAfterCrashBoundary(t *testing.T) {
	fixture := newTransactionFixture(t)
	sentinel := errors.New("crash after rename")
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterReplace {
			return sentinel
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	const changed = "TOKEN=applied-before-crash\n"

	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(changed)}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.State != RecoveryApplied || recovery.Files[0].State != RecoveryFileApplied {
		t.Fatalf("recovery = %#v", recovery)
	}
	validatorCalls := 0
	selection, err := manager.ResolveRecovery(context.Background(), lease, ResolutionFinalizeApplied, allowCommit,
		func(_ context.Context, current *SourceSet) error {
			validatorCalls++
			if len(current.Dotenv) != 1 || string(current.Dotenv[0].Content) != changed {
				return errors.New("unexpected recovery content")
			}
			return nil
		})
	if err != nil {
		t.Fatalf("ResolveRecovery(finalize) error = %v", err)
	}
	if validatorCalls != 1 || string(readFile(t, fixture.dotenv)) != changed {
		t.Fatalf("validator calls = %d, dotenv = %q", validatorCalls, readFile(t, fixture.dotenv))
	}
	loaded, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !selection.SelectionPresent {
		t.Fatal("adopted recovery did not report a selected workspace")
	}
	assertStoredSelectionEqual(t, loaded, selection.Selection)
	assertNoJournalOrStages(t, fixture)
}

func TestMigration007PreservesLiveV006AppliedRecovery(t *testing.T) {
	fixture := newTransactionFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureBeforeFinalize {
			return errors.New("simulated v006 interruption")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	const changed = "TOKEN=v006-live-recovery\n"
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(changed)}},
	}, allowCommit)
	sources.Close()
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.Close(); err != nil {
		t.Fatal(err)
	}

	legacy, err := sql.Open("sqlite", fixture.database.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"ALTER TABLE workspace_edit_journal DROP COLUMN configuration_source",
		"ALTER TABLE workspace_edit_journal DROP COLUMN bootstrap",
		"DELETE FROM schema_migrations WHERE version = '007_workspace_bootstrap.sql'",
	} {
		if _, err := legacy.Exec(statement); err != nil {
			legacy.Close()
			t.Fatalf("prepare v006 fixture: %v", err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := state.Open(fixture.stateDirectory)
	if err != nil {
		t.Fatalf("Open(v006 upgrade) error = %v", err)
	}
	t.Cleanup(func() { _ = upgraded.Close() })
	fixture.database = upgraded
	fixture.store, err = NewStore(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	fixture.journal, err = NewJournalStore(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	manager = fixture.managerWith(t)
	journal, err := fixture.journal.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if journal.Bootstrap || journal.ConfigurationSource != "" {
		t.Fatalf("migrated v006 journal = %#v", journal)
	}

	lease = acquireLease(t, fixture.coordinator, PurposeRecovery)
	defer lease.Release()
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil || recovery.State != RecoveryApplied || recovery.Bootstrap {
		t.Fatalf("InspectRecovery() = %#v, %v", recovery, err)
	}
	validatorCalls := 0
	result, err := manager.ResolveRecovery(
		context.Background(), lease, ResolutionFinalizeApplied, allowCommit,
		func(_ context.Context, current *SourceSet) error {
			validatorCalls++
			if len(current.Dotenv) != 1 || string(current.Dotenv[0].Content) != changed {
				return errors.New("migrated recovery content changed")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ResolveRecovery() error = %v", err)
	}
	if validatorCalls != 1 || !result.SelectionPresent ||
		result.Selection.Review.ConfigurationSource != ConfigurationConventionalYML {
		t.Fatalf("migrated recovery result = %#v, validator calls = %d", result, validatorCalls)
	}
	assertNoJournalOrStages(t, fixture)
}

func TestRecoveryAdoptsExternallyRepairedCurrentFilesAfterRawRenameCrash(t *testing.T) {
	fixture := newTransactionFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterRename {
			return errors.New("simulated power loss after rename")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeRecovery)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	const changed = "TOKEN=active-after-raw-rename\n"
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(changed)}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.State != RecoveryAmbiguous || recovery.Files[0].State != RecoveryFileAmbiguous {
		t.Fatalf("raw-rename recovery = %#v", recovery)
	}
	journal, err := fixture.journal.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(journal.Files[0].ParentPath, journal.Files[0].StageBasename)
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	const repaired = "TOKEN=externally-repaired\n"
	if err := os.Remove(fixture.dotenv); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.dotenv, []byte(repaired), 0o600); err != nil {
		t.Fatal(err)
	}
	selection, err := manager.ResolveRecovery(
		context.Background(), lease, ResolutionAdoptCurrent, allowCommit,
		func(_ context.Context, current *SourceSet) error {
			if len(current.Dotenv) != 1 || string(current.Dotenv[0].Content) != repaired {
				return errors.New("active recovery content is unexpected")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("ResolveRecovery(adopt current) error = %v", err)
	}
	if got := string(readFile(t, fixture.dotenv)); got != repaired {
		t.Fatalf("active dotenv = %q", got)
	}
	loaded, err := fixture.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !selection.SelectionPresent {
		t.Fatal("adopted recovery did not report a selected workspace")
	}
	assertStoredSelectionEqual(t, loaded, selection.Selection)
	assertNoJournalOrStages(t, fixture)
}

func TestRecoveryClassifiesPartialEditAndAdoptsOnlyFreshCurrentWorkspace(t *testing.T) {
	fixture := newTransactionFixture(t)
	sentinel := errors.New("crash after first applied record")
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, ordinal int) error {
		if point == FailureAfterAppliedRecord && ordinal == 0 {
			return sentinel
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	candidate := append(append([]byte(nil), sources.Configuration.Content...), []byte("# not replayed\n")...)
	const changedDotenv = "TOKEN=first-file-applied\n"
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: candidate,
		Replacements: []Replacement{
			{Role: RoleConfiguration, Path: fixture.configuration, Content: candidate},
			{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(changedDotenv)},
		},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.State != RecoveryPartial || len(recovery.Files) != 2 ||
		recovery.Files[0].Role != RoleDotenv || recovery.Files[0].State != RecoveryFileApplied ||
		recovery.Files[1].Role != RoleConfiguration || recovery.Files[1].State != RecoveryFileUnapplied {
		t.Fatalf("partial recovery = %#v", recovery)
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionFinalizeApplied, allowCommit,
		func(context.Context, *SourceSet) error { return nil }); !errors.Is(err, ErrInvalidEdit) {
		t.Fatalf("ResolveRecovery(finalize partial) error = %v, want ErrInvalidEdit", err)
	}
	_, err = manager.ResolveRecovery(context.Background(), lease, ResolutionAdoptCurrent, allowCommit,
		func(_ context.Context, current *SourceSet) error {
			if string(current.Configuration.Content) != transactionYAML || len(current.Dotenv) != 1 ||
				string(current.Dotenv[0].Content) != changedDotenv {
				return errors.New("partial active set was not freshly read")
			}
			return nil
		})
	if err != nil {
		t.Fatalf("ResolveRecovery(adopt) error = %v", err)
	}
	if string(readFile(t, fixture.configuration)) != transactionYAML || string(readFile(t, fixture.dotenv)) != changedDotenv {
		t.Fatal("adopt-current replayed the unapplied configuration candidate")
	}
	assertNoJournalOrStages(t, fixture)
}

func TestFinalizeAppliedRejectsUnreviewedPathSwapAndExplicitAdoptAcceptsFreshCurrent(t *testing.T) {
	fixture := newTransactionFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point == FailureAfterAppliedRecord {
			return errors.New("retain applied recovery")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=applied\n")}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	storage := filepath.Join(fixture.root, "storage")
	if err := os.Rename(storage, storage+".prior"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(storage, 0o700); err != nil {
		t.Fatal(err)
	}
	validator := func(context.Context, *SourceSet) error { return nil }
	if _, err := manager.ResolveRecovery(
		context.Background(), lease, ResolutionFinalizeApplied, allowCommit, validator,
	); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("ResolveRecovery(finalize swapped path) error = %v, want ErrSourceChanged", err)
	}
	if _, err := fixture.journal.Load(context.Background()); err != nil {
		t.Fatalf("finalize failure cleared journal: %v", err)
	}
	if _, err := manager.ResolveRecovery(
		context.Background(), lease, ResolutionAdoptCurrent, allowCommit, validator,
	); err != nil {
		t.Fatalf("ResolveRecovery(adopt current) error = %v", err)
	}
	assertNoJournalOrStages(t, fixture)
}

func TestJournalNeverPersistsCandidateContentOrContentHash(t *testing.T) {
	fixture := newTransactionFixture(t)
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, ordinal int) error {
		if point == FailureAfterStage && ordinal == 0 {
			return errors.New("retain journal for inspection")
		}
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	const canary = "native-edit-secret-canary-c3b4c932"
	candidateContent := []byte("TOKEN=" + canary + "\n")
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: candidateContent}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	digest := sha256.Sum256(candidateContent)
	needles := [][]byte{candidateContent, digest[:], []byte(hex.EncodeToString(digest[:]))}
	for _, path := range directoryFiles(t, fixture.stateDirectory) {
		contents := readFile(t, path)
		for _, needle := range needles {
			if bytes.Contains(contents, needle) {
				t.Fatalf("application state %s retained candidate content or hash", filepath.Base(path))
			}
		}
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil); err != nil {
		t.Fatalf("cleanup recovery: %v", err)
	}
}

func TestEveryDurableFailureBoundaryHasDeterministicRecovery(t *testing.T) {
	tests := []struct {
		name       string
		point      FailurePoint
		wantState  RecoveryState
		wantFile   RecoveryFileState
		resolution RecoveryResolution
	}{
		{name: "journal only", point: FailureAfterJournal, wantState: RecoveryUnapplied, wantFile: RecoveryFileUnstaged, resolution: ResolutionDiscardUnapplied},
		{name: "candidate staged", point: FailureAfterStage, wantState: RecoveryUnapplied, wantFile: RecoveryFileUnapplied, resolution: ResolutionDiscardUnapplied},
		{name: "all prepared", point: FailureAfterPrepared, wantState: RecoveryUnapplied, wantFile: RecoveryFileUnapplied, resolution: ResolutionDiscardUnapplied},
		{name: "before first replace", point: FailureBeforeReplace, wantState: RecoveryUnapplied, wantFile: RecoveryFileUnapplied, resolution: ResolutionDiscardUnapplied},
		{name: "after rename", point: FailureAfterReplace, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "before active directory sync", point: FailureBeforeActiveSync, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "after directory sync", point: FailureAfterDirectorySync, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "after applied record", point: FailureAfterAppliedRecord, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "before displaced unlink", point: FailureBeforeOldUnlink, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "before displaced directory sync", point: FailureBeforeOldDirSync, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
		{name: "before finalization", point: FailureBeforeFinalize, wantState: RecoveryApplied, wantFile: RecoveryFileApplied, resolution: ResolutionFinalizeApplied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTransactionFixture(t)
			triggered := false
			manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
				if point == test.point && !triggered {
					triggered = true
					return errors.New("simulated interruption")
				}
				return nil
			}))
			lease := acquireLease(t, fixture.coordinator, PurposeSave)
			defer lease.Release()
			sources, err := manager.Snapshot(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			defer sources.Close()
			const changed = "TOKEN=durable-boundary-candidate\n"
			_, err = manager.Commit(context.Background(), lease, CommitPlan{
				Sources: sources, CandidateConfiguration: sources.Configuration.Content,
				Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte(changed)}},
			}, allowCommit)
			if !triggered || !errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("Commit() triggered = %v, error = %v", triggered, err)
			}
			recovery, err := manager.InspectRecovery(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			if recovery.State != test.wantState || len(recovery.Files) != 1 || recovery.Files[0].State != test.wantFile {
				t.Fatalf("recovery = %#v, want state %s file %s", recovery, test.wantState, test.wantFile)
			}
			var validator RecoveryValidator
			if test.resolution == ResolutionFinalizeApplied {
				validator = func(_ context.Context, current *SourceSet) error {
					if len(current.Dotenv) != 1 || string(current.Dotenv[0].Content) != changed {
						return errors.New("applied boundary did not retain candidate")
					}
					return nil
				}
			}
			if _, err := manager.ResolveRecovery(context.Background(), lease, test.resolution, allowCommit, validator); err != nil {
				t.Fatalf("ResolveRecovery(%s) error = %v", test.resolution, err)
			}
			want := transactionOldDotenv
			if test.resolution == ResolutionFinalizeApplied {
				want = changed
			}
			if got := string(readFile(t, fixture.dotenv)); got != want {
				t.Fatalf("active dotenv = %q, want %q", got, want)
			}
			assertNoJournalOrStages(t, fixture)
		})
	}
}

func TestStagingWriteAndSyncFailuresLeaveActiveFilesUnchanged(t *testing.T) {
	for _, point := range []FailurePoint{
		FailureBeforeStageWrite,
		FailureBeforeStageSync,
		FailureBeforeStageDirSync,
	} {
		t.Run(string(point), func(t *testing.T) {
			fixture := newTransactionFixture(t)
			sentinel := errors.New("simulated staging filesystem failure")
			manager := fixture.managerWith(t, WithFailureInjector(func(current FailurePoint, _ int) error {
				if current == point {
					return sentinel
				}
				return nil
			}))
			lease := acquireLease(t, fixture.coordinator, PurposeSave)
			defer lease.Release()
			sources, err := manager.Snapshot(context.Background(), lease)
			if err != nil {
				t.Fatal(err)
			}
			defer sources.Close()
			_, err = manager.Commit(context.Background(), lease, CommitPlan{
				Sources: sources, CandidateConfiguration: sources.Configuration.Content,
				Replacements: []Replacement{{
					Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=never-active\n"),
				}},
			}, allowCommit)
			if !errors.Is(err, sentinel) || errors.Is(err, ErrRecoveryRequired) {
				t.Fatalf("Commit() error = %v, want simulated pre-activation failure", err)
			}
			if got := string(readFile(t, fixture.dotenv)); got != transactionOldDotenv {
				t.Fatalf("active dotenv = %q", got)
			}
			assertNoJournalOrStages(t, fixture)
		})
	}
}

func TestStageCleanupPreservesSubstitutedFileAndScrubsRetainedCandidate(t *testing.T) {
	fixture := newTransactionFixture(t)
	sentinel := errors.New("simulated stage substitution")
	const foreign = "foreign-file-at-managed-basename"
	var stagePath, movedPath string
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point != FailureBeforeStageSync {
			return nil
		}
		journal, err := fixture.journal.Load(context.Background())
		if err != nil {
			return err
		}
		stagePath = filepath.Join(journal.Files[0].ParentPath, journal.Files[0].StageBasename)
		movedPath = stagePath + ".external-move"
		if err := os.Rename(stagePath, movedPath); err != nil {
			return err
		}
		if err := os.WriteFile(stagePath, []byte(foreign), 0o600); err != nil {
			return err
		}
		return sentinel
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{
			Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=staged-secret-canary\n"),
		}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, sentinel) {
		t.Fatalf("Commit() error = %v, want recovery + injected failure", err)
	}
	if got := string(readFile(t, stagePath)); got != foreign {
		t.Fatalf("substituted stage was changed or deleted: %q", got)
	}
	if got := readFile(t, movedPath); len(got) != 0 {
		t.Fatalf("retained candidate was not scrubbed: %q", got)
	}
	if _, err := fixture.journal.Load(context.Background()); err != nil {
		t.Fatalf("recovery journal was cleared after uncertain cleanup: %v", err)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil || recovery.State != RecoveryAmbiguous {
		t.Fatalf("InspectRecovery() = %#v, %v", recovery, err)
	}
	if err := os.Remove(stagePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(movedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil); err != nil {
		t.Fatalf("ResolveRecovery() after external cleanup = %v", err)
	}
}

func TestStageNameCollisionIsNeverDeletedAsManagedCandidate(t *testing.T) {
	fixture := newTransactionFixture(t)
	const foreign = "foreign-stage-collision"
	var collisionPath string
	manager := fixture.managerWith(t, WithFailureInjector(func(point FailurePoint, _ int) error {
		if point != FailureAfterJournal {
			return nil
		}
		journal, err := fixture.journal.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		collisionPath = filepath.Join(journal.Files[0].ParentPath, journal.Files[0].StageBasename)
		writeFile(t, collisionPath, []byte(foreign), 0o600)
		return nil
	}))
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	defer lease.Release()
	sources, err := manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	_, err = manager.Commit(context.Background(), lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=candidate\n")}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("Commit() error = %v, want ErrRecoveryRequired", err)
	}
	if got := string(readFile(t, collisionPath)); got != foreign {
		t.Fatalf("foreign stage was changed or deleted: %q", got)
	}
	recovery, err := manager.InspectRecovery(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	if recovery.State != RecoveryAmbiguous {
		t.Fatalf("collision recovery = %#v", recovery)
	}
	if err := os.Remove(collisionPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ResolveRecovery(context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil); err != nil {
		t.Fatalf("ResolveRecovery() after external collision resolution = %v", err)
	}
}

func TestCoordinatorSerializesProcessesAndHonorsWaitingContext(t *testing.T) {
	root := secureTempDir(t)
	lockPath := filepath.Join(root, "workspace.lock")
	firstCoordinator, err := NewCoordinator(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	secondCoordinator, err := NewCoordinator(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	first := acquireLease(t, firstCoordinator, PurposeInventory)
	if _, err := firstCoordinator.TryAcquire(context.Background(), PurposeRead); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("same-process TryAcquire() error = %v, want ErrWorkspaceBusy", err)
	}
	if _, err := secondCoordinator.TryAcquire(context.Background(), PurposeRead); !errors.Is(err, ErrWorkspaceBusy) {
		t.Fatalf("cross-coordinator TryAcquire() error = %v, want ErrWorkspaceBusy", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := secondCoordinator.Acquire(ctx, PurposeScheduled); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire(canceled) error = %v, want DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Acquire ignored context for %v", elapsed)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := secondCoordinator.TryAcquire(context.Background(), PurposeManualRun)
	if err != nil {
		t.Fatalf("TryAcquire(after release) error = %v", err)
	}
	if second.Purpose() != PurposeManualRun {
		t.Fatalf("lease purpose = %q", second.Purpose())
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if second.Purpose() != "" {
		t.Fatalf("released lease purpose = %q", second.Purpose())
	}
	info, err := os.Lstat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("lock mode = %v", info.Mode())
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	writeFile(t, lockPath, nil, 0o600)
	if _, err := firstCoordinator.TryAcquire(context.Background(), PurposeRead); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("TryAcquire(replaced lock) error = %v, want ErrSourceChanged", err)
	}
}

func TestTransactionManagerBoundsSnapshotAndCandidateAudit(t *testing.T) {
	fixture := newTransactionFixture(t)
	lease := acquireLease(t, fixture.coordinator, PurposePreview)
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	manager := fixture.managerWith(t, WithTransactionTimeout(time.Nanosecond))
	if _, err := manager.Snapshot(context.Background(), lease); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Snapshot(timeout) error = %v, want DeadlineExceeded", err)
	}
	if _, err := manager.AuditCandidate(
		context.Background(), lease, sources, sources.Configuration.Content, []Replacement{{
			Role: RoleDotenv, Path: sources.Dotenv[0].Path, Content: sources.Dotenv[0].Content,
		}},
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AuditCandidate(timeout) error = %v, want DeadlineExceeded", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	next, err := fixture.coordinator.TryAcquire(context.Background(), PurposeRead)
	if err != nil {
		t.Fatalf("TryAcquire() after bounded operation = %v", err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestTransactionCancellationAfterJournalRetainsRecoverableEvidence(t *testing.T) {
	fixture := newTransactionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := fixture.managerWith(t,
		WithFailureInjector(func(point FailurePoint, _ int) error {
			if point == FailureAfterJournal {
				cancel()
			}
			return nil
		}),
	)
	lease := acquireLease(t, fixture.coordinator, PurposeSave)
	sources, err := fixture.manager.Snapshot(context.Background(), lease)
	if err != nil {
		t.Fatal(err)
	}
	defer sources.Close()
	_, err = manager.Commit(ctx, lease, CommitPlan{
		Sources: sources, CandidateConfiguration: sources.Configuration.Content,
		Replacements: []Replacement{{Role: RoleDotenv, Path: fixture.dotenv, Content: []byte("TOKEN=timed-out\n")}},
	}, allowCommit)
	if !errors.Is(err, ErrRecoveryRequired) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Commit(canceled after journal) error = %v", err)
	}
	recovery, err := fixture.manager.InspectRecovery(context.Background(), lease)
	if err != nil || recovery.State != RecoveryUnapplied {
		t.Fatalf("InspectRecovery() = %#v, %v", recovery, err)
	}
	if _, err := fixture.manager.ResolveRecovery(
		context.Background(), lease, ResolutionDiscardUnapplied, allowCommit, nil,
	); err != nil {
		t.Fatalf("ResolveRecovery() error = %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	next, err := fixture.coordinator.TryAcquire(context.Background(), PurposeRead)
	if err != nil {
		t.Fatalf("TryAcquire() after timeout recovery = %v", err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func newTransactionFixture(t *testing.T) *transactionFixture {
	t.Helper()
	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	mkdir(t, filepath.Join(root, "storage"), 0o700)
	secrets := mkdir(t, filepath.Join(root, "secrets"), 0o700)
	stateDirectory := mkdir(t, filepath.Join(root, "state"), 0o700)
	configuration := writeFile(t, filepath.Join(working, ".lego.yml"), []byte(transactionYAML), 0o600)
	dotenv := writeFile(t, filepath.Join(secrets, "provider.env"), []byte(transactionOldDotenv), 0o600)
	database, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("Inspect() review = %#v, error = %v", review, err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Review: review, ReviewedAt: review.ObservedAt.Add(time.Nanosecond)}
	if err := store.Save(context.Background(), selection); err != nil {
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
	fixture := &transactionFixture{
		root: root, stateDirectory: stateDirectory, working: working,
		configuration: configuration, dotenv: dotenv, database: database,
		inspector: inspector, store: store, journal: journal, coordinator: coordinator,
	}
	fixture.manager = fixture.managerWith(t)
	return fixture
}

func (fixture *transactionFixture) managerWith(t *testing.T, options ...TransactionOption) *TransactionManager {
	t.Helper()
	manager, err := NewTransactionManager(fixture.inspector, fixture.store, fixture.journal, fixture.coordinator, options...)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func acquireLease(t *testing.T, coordinator *Coordinator, purpose Purpose) *Lease {
	t.Helper()
	lease, err := coordinator.Acquire(context.Background(), purpose)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func allowCommit(context.Context) error { return nil }

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func assertNoJournalOrStages(t *testing.T, fixture *transactionFixture) {
	t.Helper()
	if _, err := fixture.journal.Load(context.Background()); !errors.Is(err, ErrNoEditJournal) {
		t.Fatalf("Load(journal) error = %v, want ErrNoEditJournal", err)
	}
	for _, directory := range []string{filepath.Dir(fixture.configuration), filepath.Dir(fixture.dotenv)} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if len(entry.Name()) >= len(".acmemux-edit-") && entry.Name()[:len(".acmemux-edit-")] == ".acmemux-edit-" {
				t.Fatalf("staging file remains: %s", filepath.Join(directory, entry.Name()))
			}
		}
	}
}
