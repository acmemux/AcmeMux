package runtime

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sgurden-certleap/AcmeMux/internal/state"
)

func TestSelectionStoreRoundTripsAndAtomicallyReplacesSingleton(t *testing.T) {
	t.Parallel()

	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	store, err := NewSelectionStore(database)
	if err != nil {
		t.Fatalf("NewSelectionStore() error = %v", err)
	}

	if _, err := store.Load(context.Background()); !errors.Is(err, ErrNoSelection) {
		t.Fatalf("Load() error = %v, want ErrNoSelection", err)
	}

	first := selectionFixture()
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(first) error = %v", err)
	}
	if loaded != first {
		t.Fatalf("Load(first) = %#v, want %#v", loaded, first)
	}

	second := first
	second.Observation.File.CanonicalPath = "/opt/acmemux/bin/lego-v5.3.1"
	second.Observation.File.Device = 17
	second.Observation.File.Inode = 23
	second.Observation.File.Capabilities = ""
	second.Observation.File.SHA256 = strings.Repeat("b", 64)
	second.Observation.Version = VersionIdentity{Kind: VersionRelease, Value: "v5.3.1"}
	second.Observation.VersionOutput = "lego version 5.3.1 linux/amd64"
	second.Observation.Build.MainVersion = "v5.3.1"
	second.Observation.Build.VCSRevision = "589c84af4f26629fbdaa7fbca712f806632ccb7e"
	second.Observation.ObservedAt = first.Observation.ObservedAt.Add(time.Second)
	second.ManifestID = "lego-v5.3.1-linux-amd64"
	second.ReviewedAt = first.ReviewedAt.Add(2 * time.Second)
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	loaded, err = store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(second) error = %v", err)
	}
	if loaded != second {
		t.Fatalf("Load(second) = %#v, want %#v", loaded, second)
	}
	var count int
	if err := database.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM runtime_selection").Scan(&count); err != nil {
		t.Fatalf("count runtime selections: %v", err)
	}
	if count != 1 {
		t.Fatalf("runtime selection count = %d, want 1", count)
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
}

func TestSelectionStoreRejectsInvalidSelectionWithoutReplacingCurrent(t *testing.T) {
	t.Parallel()

	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	defer database.Close()
	store, err := NewSelectionStore(database)
	if err != nil {
		t.Fatalf("NewSelectionStore() error = %v", err)
	}
	valid := selectionFixture()
	if err := store.Save(context.Background(), valid); err != nil {
		t.Fatalf("Save(valid) error = %v", err)
	}

	tests := map[string]func(*Selection){
		"relative path": func(selection *Selection) {
			selection.Observation.File.CanonicalPath = "usr/local/bin/lego"
		},
		"writable executable": func(selection *Selection) {
			selection.Observation.File.Mode = 0o100775
		},
		"unsafe capabilities": func(selection *Selection) {
			selection.Observation.File.Capabilities = "cap_sys_admin=ep"
		},
		"empty executable": func(selection *Selection) {
			selection.Observation.File.Size = 0
		},
		"uppercase digest": func(selection *Selection) {
			selection.Observation.File.SHA256 = strings.Repeat("A", 64)
		},
		"non-UTC evidence": func(selection *Selection) {
			selection.Observation.File.ModifiedAt = selection.Observation.File.ModifiedAt.In(time.FixedZone("offset", 3600))
		},
		"unknown version kind": func(selection *Selection) {
			selection.Observation.Version.Kind = VersionKind("range")
		},
		"unsupported platform": func(selection *Selection) {
			selection.Observation.Platform.Arch = "386"
			selection.Observation.VersionOutput = "lego version 2a58c3522708e4c7393a67be691bd0c3a16d8441 linux/386"
			selection.Observation.Build.GOARCH = "386"
		},
		"inconsistent version output": func(selection *Selection) {
			selection.Observation.VersionOutput = "lego version v5.3.1 linux/amd64"
		},
		"unavailable build with residue": func(selection *Selection) {
			selection.Observation.Build.Available = false
		},
		"missing build evidence": func(selection *Selection) {
			selection.Observation.Build = BuildEvidence{}
		},
		"incomplete provenance": func(selection *Selection) {
			selection.Observation.Build.ProvenanceComplete = false
		},
		"unexpected command path": func(selection *Selection) {
			selection.Observation.Build.CommandPath = "example.com/wrapped/lego"
		},
		"missing Go version": func(selection *Selection) {
			selection.Observation.Build.GoVersion = ""
		},
		"missing main module": func(selection *Selection) {
			selection.Observation.Build.MainPath = ""
		},
		"malformed dependency graph digest": func(selection *Selection) {
			selection.Observation.Build.DependencyGraphSHA256 = strings.Repeat("C", 64)
		},
		"incomplete modified evidence": func(selection *Selection) {
			selection.Observation.Build.VCSModifiedValid = false
		},
		"modified build": func(selection *Selection) {
			selection.Observation.Build.VCSModified = true
		},
		"empty manifest": func(selection *Selection) {
			selection.ManifestID = ""
		},
		"noncanonical manifest": func(selection *Selection) {
			selection.ManifestID = "../manifest"
		},
		"non-UTC review": func(selection *Selection) {
			selection.ReviewedAt = selection.ReviewedAt.In(time.FixedZone("offset", -3600))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := store.Save(context.Background(), candidate); !errors.Is(err, ErrInvalidSelection) {
				t.Fatalf("Save(invalid) error = %v, want ErrInvalidSelection", err)
			}
			loaded, err := store.Load(context.Background())
			if err != nil {
				t.Fatalf("Load() after invalid replacement error = %v", err)
			}
			if loaded != valid {
				t.Fatalf("invalid Save replaced selection: got %#v, want %#v", loaded, valid)
			}
		})
	}
}

func TestSelectionStoreRejectsCorruptedPersistedMetadata(t *testing.T) {
	t.Parallel()

	for name, statement := range map[string]string{
		"device":                "UPDATE runtime_selection SET device_decimal = '01' WHERE singleton_id = 1",
		"provenance complete":   "UPDATE runtime_selection SET build_provenance_complete = 0 WHERE singleton_id = 1",
		"command path":          "UPDATE runtime_selection SET build_command_path = '' WHERE singleton_id = 1",
		"dependency graph hash": "UPDATE runtime_selection SET build_dependency_graph_sha256 = '' WHERE singleton_id = 1",
		"manifest ID":           "UPDATE runtime_selection SET compatibility_manifest_id = '../manifest' WHERE singleton_id = 1",
	} {
		t.Run(name, func(t *testing.T) {
			database, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatalf("state.Open() error = %v", err)
			}
			defer database.Close()
			store, err := NewSelectionStore(database)
			if err != nil {
				t.Fatalf("NewSelectionStore() error = %v", err)
			}
			if err := store.Save(context.Background(), selectionFixture()); err != nil {
				t.Fatalf("Save() error = %v", err)
			}
			if _, err := database.ExecContext(context.Background(), statement); err != nil {
				t.Fatalf("corrupt persisted selection: %v", err)
			}

			if _, err := store.Load(context.Background()); !errors.Is(err, ErrInvalidSelection) {
				t.Fatalf("Load(corrupt) error = %v, want ErrInvalidSelection", err)
			}
		})
	}
}

func TestSelectionStoreFailsCleanlyWithInvalidDependenciesAndClosedState(t *testing.T) {
	t.Parallel()

	if _, err := NewSelectionStore(nil); err == nil {
		t.Fatal("NewSelectionStore(nil) error = nil")
	}
	database, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open() error = %v", err)
	}
	store, err := NewSelectionStore(database)
	if err != nil {
		t.Fatalf("NewSelectionStore() error = %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := store.Load(context.Background()); err == nil {
		t.Fatal("Load(closed database) error = nil")
	}
	if err := store.Save(context.Background(), selectionFixture()); err == nil {
		t.Fatal("Save(closed database) error = nil")
	}
	if err := store.Clear(context.Background()); err == nil {
		t.Fatal("Clear(closed database) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if _, err := store.Load(nil); err == nil {
		t.Fatal("Load(nil context) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if err := store.Save(nil, selectionFixture()); err == nil {
		t.Fatal("Save(nil context) error = nil")
	}
	//lint:ignore SA1012 this test verifies that the store rejects a nil context
	if err := store.Clear(nil); err == nil {
		t.Fatal("Clear(nil context) error = nil")
	}
}

func selectionFixture() Selection {
	revision := "2a58c3522708e4c7393a67be691bd0c3a16d8441"
	observedAt := time.Date(2026, time.August, 15, 12, 34, 56, 789123456, time.UTC)
	return Selection{
		Observation: Observation{
			File: FileIdentity{
				CanonicalPath: "/usr/local/bin/lego",
				Device:        math.MaxUint64,
				Inode:         math.MaxUint64 - 1,
				Mode:          0o100755,
				Capabilities:  "cap_net_bind_service=ep",
				UID:           math.MaxUint32,
				GID:           math.MaxUint32 - 1,
				Size:          42_987_654,
				ModifiedAt:    time.Date(2026, time.August, 14, 1, 2, 3, 4, time.UTC),
				ChangedAt:     time.Date(2026, time.August, 14, 1, 2, 5, 6, time.UTC),
				SHA256:        strings.Repeat("a", 64),
			},
			Version:  VersionIdentity{Kind: VersionRevision, Value: revision},
			Platform: Platform{OS: "linux", Arch: "amd64"},
			Build: BuildEvidence{
				Available:             true,
				ProvenanceComplete:    true,
				GoVersion:             "go1.26.6",
				CommandPath:           "github.com/go-acme/lego/v5",
				MainPath:              "github.com/go-acme/lego/v5",
				MainVersion:           "v5.3.2-0.20260803101616-2a58c3522708",
				DependencyGraphSHA256: strings.Repeat("c", 64),
				GOOS:                  "linux",
				GOARCH:                "amd64",
				VCSRevision:           revision,
				VCSModifiedKnown:      true,
				VCSModifiedValid:      true,
				VCSModified:           false,
			},
			VersionOutput: "lego version " + revision + " linux/amd64",
			ObservedAt:    observedAt,
		},
		ManifestID: "lego-2a58c3522708-linux-amd64",
		ReviewedAt: observedAt.Add(25 * time.Millisecond),
	}
}
