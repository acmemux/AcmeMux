//go:build linux

package workspace

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/acmemux/AcmeMux/internal/state"
)

func TestStoreRoundTripsReplacesAndClearsSingleton(t *testing.T) {
	t.Parallel()

	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	store, err := NewStore(database)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("Load() error = %v, want ErrNoSelection", err)
	}

	first := workspaceSelectionFixture(t, false)
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(first) error = %v", err)
	}
	assertStoredSelectionEqual(t, loaded, first)

	second := workspaceSelectionFixture(t, true)
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	loaded, err = store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(second) error = %v", err)
	}
	assertStoredSelectionEqual(t, loaded, second)
	for _, table := range []string{
		"workspace_selection", "workspace_path_observation",
		"workspace_component_observation", "workspace_review_diagnostic",
	} {
		var count int
		if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if table == "workspace_selection" && count != 1 {
			t.Fatalf("%s count = %d, want 1", table, count)
		}
	}

	if err := store.Clear(context.Background()); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if err := store.Clear(context.Background()); err != nil {
		t.Fatalf("second Clear() error = %v", err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("Load() after Clear error = %v, want ErrNoSelection", err)
	}
	for _, table := range []string{
		"workspace_path_observation", "workspace_component_observation", "workspace_review_diagnostic",
	} {
		var count int
		if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
			t.Fatalf("count cleared %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("cleared %s count = %d, want 0", table, count)
		}
	}
}

func TestStoreSurvivesDatabaseReopenAndRetainsNanoseconds(t *testing.T) {
	t.Parallel()

	stateDirectory := t.TempDir()
	database, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := workspaceSelectionFixture(t, true)
	selection.Review.ObservedAt = time.Date(2026, time.August, 15, 18, 19, 20, 123456789, time.UTC)
	selection.ReviewedAt = time.Date(2026, time.August, 15, 18, 19, 21, 987654321, time.UTC)
	selection.Review.ReviewedEvidenceSHA256 = ReviewFingerprint(selection.Review)
	if err := store.Save(context.Background(), selection); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = state.Open(stateDirectory)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer database.Close()
	store, err = NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() after reopen error = %v", err)
	}
	assertStoredSelectionEqual(t, loaded, selection)
	if loaded.Review.ObservedAt.Nanosecond() != 123456789 || loaded.ReviewedAt.Nanosecond() != 987654321 {
		t.Fatalf("nanoseconds lost: observed=%v reviewed=%v", loaded.Review.ObservedAt, loaded.ReviewedAt)
	}
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspector.Verify(context.Background(), loaded.Review); err != nil {
		t.Fatalf("Verify(loaded review) error = %v", err)
	}
}

func TestStoreAtomicallyUpgradesLegacyReviewFingerprintAndRejectsTampering(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper bool
	}{
		{name: "upgrade"},
		{name: "tampered legacy evidence", tamper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDirectory := t.TempDir()
			database, err := state.Open(stateDirectory)
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewStore(database)
			if err != nil {
				t.Fatal(err)
			}
			selection := workspaceSelectionFixture(t, false)
			if err := store.Save(context.Background(), selection); err != nil {
				t.Fatal(err)
			}
			legacy := legacyReviewFingerprintV1(selection.Review)
			if _, err := database.ExecContext(context.Background(),
				"UPDATE workspace_selection SET reviewed_evidence_sha256 = ?", legacy,
			); err != nil {
				t.Fatal(err)
			}
			if test.tamper {
				if _, err := database.ExecContext(context.Background(),
					"UPDATE workspace_path_observation SET inode_decimal = '999999' WHERE path_ordinal = 2",
				); err != nil {
					t.Fatal(err)
				}
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}

			database, err = state.Open(stateDirectory)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			store, err = NewStore(database)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := store.Load(context.Background())
			if test.tamper {
				if !errors.Is(err, ErrInvalidSelection) {
					t.Fatalf("Load(tampered legacy) error = %v, want ErrInvalidSelection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(legacy) error = %v", err)
			}
			if loaded.Review.ReviewedEvidenceSHA256 != ReviewFingerprint(loaded.Review) ||
				loaded.Review.ReviewedEvidenceSHA256 == legacy {
				t.Fatalf("legacy fingerprint was not upgraded: %#v", loaded.Review)
			}
			var persisted string
			if err := database.QueryRowContext(context.Background(),
				"SELECT reviewed_evidence_sha256 FROM workspace_selection WHERE singleton_id = 1",
			).Scan(&persisted); err != nil {
				t.Fatal(err)
			}
			if persisted != loaded.Review.ReviewedEvidenceSHA256 {
				t.Fatalf("persisted fingerprint = %q, want %q", persisted, loaded.Review.ReviewedEvidenceSHA256)
			}
		})
	}
}

func TestStoreRejectsInvalidSelectionWithoutReplacingCurrent(t *testing.T) {
	t.Parallel()

	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	valid := workspaceSelectionFixture(t, false)
	if err := store.Save(context.Background(), valid); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*Selection){
		"not adoptable": func(selection *Selection) {
			selection.Review.Adoptable = false
		},
		"relative working path": func(selection *Selection) {
			selection.Review.WorkingDirectory.Path = "relative"
		},
		"role order": func(selection *Selection) {
			selection.Review.Storage.Role = RoleWebroot
		},
		"reference resolution": func(selection *Selection) {
			selection.Review.Storage.Reference = "different"
		},
		"confidential permissions": func(selection *Selection) {
			selection.Review.Configuration.Mode |= 0o004
			selection.Review.Configuration.Components[len(selection.Review.Configuration.Components)-1].Mode |= 0o004
		},
		"missing final link": func(selection *Selection) {
			selection.Review.Configuration.NLink = 0
		},
		"component path": func(selection *Selection) {
			selection.Review.Storage.Components[1].Path = "/wrong"
		},
		"blocking diagnostic": func(selection *Selection) {
			selection.Review.Diagnostics = []Diagnostic{{
				Code: CodePathMissing, Severity: SeverityBlocking, Role: RoleStorage,
				Path: selection.Review.Storage.Path, Detail: "missing",
			}}
		},
		"non UTC observation": func(selection *Selection) {
			selection.Review.ObservedAt = selection.Review.ObservedAt.In(time.FixedZone("offset", 3600))
		},
		"review before observation": func(selection *Selection) {
			selection.ReviewedAt = selection.Review.ObservedAt.Add(-time.Nanosecond)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneSelection(valid)
			mutate(&candidate)
			candidate.Review.ReviewedEvidenceSHA256 = ReviewFingerprint(candidate.Review)
			if err := store.Save(context.Background(), candidate); !errors.Is(err, ErrInvalidSelection) {
				t.Fatalf("Save(invalid) error = %v, want ErrInvalidSelection", err)
			}
			loaded, err := store.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertStoredSelectionEqual(t, loaded, valid)
		})
	}

	badDigest := cloneSelection(valid)
	badDigest.Review.ReviewedEvidenceSHA256 = strings.Repeat("a", 64)
	if err := store.Save(context.Background(), badDigest); !errors.Is(err, ErrInvalidSelection) {
		t.Fatalf("Save(bad digest) error = %v, want ErrInvalidSelection", err)
	}
}

func TestStoreRejectsCorruptedPersistedEvidenceAfterReopen(t *testing.T) {
	t.Parallel()

	for name, statement := range map[string]string{
		"noncanonical device":  "UPDATE workspace_path_observation SET device_decimal = '01' WHERE path_ordinal = 0",
		"wrong role":           "UPDATE workspace_path_observation SET role = 'storage' WHERE path_ordinal = 0",
		"wrong component":      "UPDATE workspace_component_observation SET canonical_path = '/wrong' WHERE path_ordinal = 0 AND component_ordinal = 0",
		"wrong component mode": "UPDATE workspace_component_observation SET mode = 33152 WHERE path_ordinal = 0 AND component_ordinal = 0",
		"wrong fingerprint":    "UPDATE workspace_selection SET reviewed_evidence_sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
		"noncanonical time":    "UPDATE workspace_selection SET observed_at_utc = '2026-08-15T12:00:00.000Z'",
		"missing component":    "DELETE FROM workspace_component_observation WHERE path_ordinal = 0 AND component_ordinal = 0",
	} {
		t.Run(name, func(t *testing.T) {
			stateDirectory := t.TempDir()
			database, err := state.Open(stateDirectory)
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewStore(database)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(context.Background(), workspaceSelectionFixture(t, false)); err != nil {
				t.Fatal(err)
			}
			if _, err := database.ExecContext(context.Background(), statement); err != nil {
				t.Fatalf("corrupt persisted evidence: %v", err)
			}
			if err := database.Close(); err != nil {
				t.Fatal(err)
			}
			database, err = state.Open(stateDirectory)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			store, err = NewStore(database)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(context.Background()); !errors.Is(err, ErrInvalidSelection) {
				t.Fatalf("Load(corrupt) error = %v, want ErrInvalidSelection", err)
			}
		})
	}
}

func TestStoreReplacementRollsBackWhenAChildInsertFails(t *testing.T) {
	t.Parallel()

	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	first := workspaceSelectionFixture(t, false)
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(context.Background(), `
CREATE TRIGGER fail_workspace_component
BEFORE INSERT ON workspace_component_observation
WHEN NEW.component_ordinal = 1
BEGIN
    SELECT RAISE(ABORT, 'fixture failure');
END`); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(context.Background(), workspaceSelectionFixture(t, true)); err == nil {
		t.Fatal("Save() error = nil, want child insert failure")
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertStoredSelectionEqual(t, loaded, first)
}

func TestStoreDoesNotWriteNativeSecretsToDatabaseOrWAL(t *testing.T) {
	t.Parallel()

	stateDirectory := t.TempDir()
	database, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	const yamlCanary = "eab-hmac-secret-canary-7a42"
	const dotenvCanary = "provider-token-secret-canary-4c19"
	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	mkdir(t, filepath.Join(root, "storage"), 0o700)
	mkdir(t, filepath.Join(root, "secrets"), 0o700)
	writeFile(t, filepath.Join(root, "secrets", "provider.env"), []byte("TOKEN="+dotenvCanary+"\n"), 0o600)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte(`
storage: ../storage
accounts:
  home:
    eab:
      hmacKey: `+yamlCanary+`
challenges:
  dns:
    dns:
      envFile: ../secrets/provider.env
`), 0o600)
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("Inspect() review = %#v, error = %v", review, err)
	}
	if err := store.Save(context.Background(), Selection{Review: review, ReviewedAt: review.ObservedAt.Add(time.Nanosecond)}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range directoryFiles(t, stateDirectory) {
		contents, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		for _, canary := range []string{yamlCanary, dotenvCanary} {
			if bytes.Contains(contents, []byte(canary)) {
				t.Fatalf("application state %s contains native secret canary", filepath.Base(entry))
			}
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	for _, entry := range directoryFiles(t, stateDirectory) {
		contents, err := os.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte(yamlCanary)) || bytes.Contains(contents, []byte(dotenvCanary)) {
			t.Fatalf("closed application state %s contains native secret canary", filepath.Base(entry))
		}
	}
}

func TestStoreRejectsInvalidDependenciesContextsAndClosedState(t *testing.T) {
	t.Parallel()

	if _, err := NewStore(nil); err == nil {
		t.Fatal("NewStore(nil) error = nil")
	}
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatal(err)
	}
	selection := workspaceSelectionFixture(t, false)
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("Load(closed) error = nil")
	}
	if err := store.Save(context.Background(), selection); err == nil {
		t.Fatal("Save(closed) error = nil")
	}
	if err := store.Clear(context.Background()); err == nil {
		t.Fatal("Clear(closed) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if _, err := store.Load(nil); err == nil {
		t.Fatal("Load(nil) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if err := store.Save(nil, selection); err == nil {
		t.Fatal("Save(nil) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if err := store.Clear(nil); err == nil {
		t.Fatal("Clear(nil) error = nil")
	}
}

func workspaceSelectionFixture(t *testing.T, precedence bool) Selection {
	t.Helper()
	root := secureTempDir(t)
	working := mkdir(t, filepath.Join(root, "working"), 0o700)
	mkdir(t, filepath.Join(root, "storage"), 0o700)
	mkdir(t, filepath.Join(root, "secrets"), 0o700)
	mkdir(t, filepath.Join(root, "webroot"), 0o700)
	writeFile(t, filepath.Join(root, "secrets", "provider.env"), []byte("TOKEN=not-persisted\n"), 0o600)
	writeFile(t, filepath.Join(working, ".lego.yml"), []byte(`
storage: ../storage
challenges:
  dns:
    dns:
      envFile: ../secrets/provider.env
  http:
    http:
      webroot: ../webroot
`), 0o600)
	if precedence {
		writeFile(t, filepath.Join(working, ".lego.yaml"), []byte("storage: ../storage\n"), 0o600)
	}
	inspector, err := NewInspector(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	review, err := inspector.Inspect(context.Background(), Request{WorkingDirectory: working})
	if err != nil || !review.Adoptable {
		t.Fatalf("Inspect() review = %#v, error = %v", review, err)
	}
	return Selection{Review: review, ReviewedAt: review.ObservedAt.Add(987654321 * time.Nanosecond)}
}

func cloneSelection(selection Selection) Selection {
	selection.Review.WorkingDirectory = clonePathEvidence(selection.Review.WorkingDirectory)
	selection.Review.Configuration = clonePathEvidence(selection.Review.Configuration)
	selection.Review.Storage = clonePathEvidence(selection.Review.Storage)
	selection.Review.DotenvFiles = append([]PathEvidence(nil), selection.Review.DotenvFiles...)
	for index := range selection.Review.DotenvFiles {
		selection.Review.DotenvFiles[index] = clonePathEvidence(selection.Review.DotenvFiles[index])
	}
	selection.Review.Webroots = append([]PathEvidence(nil), selection.Review.Webroots...)
	for index := range selection.Review.Webroots {
		selection.Review.Webroots[index] = clonePathEvidence(selection.Review.Webroots[index])
	}
	selection.Review.Diagnostics = append([]Diagnostic(nil), selection.Review.Diagnostics...)
	return selection
}

func clonePathEvidence(evidence PathEvidence) PathEvidence {
	evidence.Components = append([]ComponentEvidence(nil), evidence.Components...)
	return evidence
}

func assertStoredSelectionEqual(t *testing.T, got, want Selection) {
	t.Helper()
	want = cloneSelection(want)
	for _, evidence := range []*PathEvidence{
		&want.Review.WorkingDirectory, &want.Review.Configuration, &want.Review.Storage,
	} {
		for index := range evidence.Components {
			evidence.Components[index].NLink = 0
		}
	}
	for index := range want.Review.DotenvFiles {
		for component := range want.Review.DotenvFiles[index].Components {
			want.Review.DotenvFiles[index].Components[component].NLink = 0
		}
	}
	for index := range want.Review.Webroots {
		for component := range want.Review.Webroots[index].Components {
			want.Review.Webroots[index].Components[component].NLink = 0
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded selection = %#v, want %#v", got, want)
	}
}

func directoryFiles(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	return paths
}
