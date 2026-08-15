package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesRestrictiveMigratedState(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "state")
	database, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	if err := database.PingContext(context.Background()); err != nil {
		t.Fatalf("PingContext() error = %v", err)
	}
	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("Stat(state directory) error = %v", err)
	}
	if permissions := directoryInfo.Mode().Perm(); permissions != 0o700 {
		t.Fatalf("state directory permissions = %o, want 700", permissions)
	}
	databaseInfo, err := os.Stat(database.Path())
	if err != nil {
		t.Fatalf("Stat(database) error = %v", err)
	}
	if permissions := databaseInfo.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("database permissions = %o, want 600", permissions)
	}

	var migrationsApplied int
	if err := database.connection.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrationsApplied); err != nil {
		t.Fatalf("query migration ledger: %v", err)
	}
	if migrationsApplied != 1 {
		t.Fatalf("migration count = %d, want 1", migrationsApplied)
	}
	for _, prohibited := range []string{"credential", "certificate", "private_key", "native_config", "account_material"} {
		var count int
		if err := database.connection.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE lower(name) LIKE ?", "%"+prohibited+"%").Scan(&count); err != nil {
			t.Fatalf("inspect schema for %s: %v", prohibited, err)
		}
		if count != 0 {
			t.Fatalf("schema unexpectedly contains %q", prohibited)
		}
	}
}

func TestOpenRejectsSymlinkDatabase(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(directory, databaseFilename)); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := Open(directory); err == nil {
		t.Fatal("Open() error = nil, want symlink rejection")
	}
}
