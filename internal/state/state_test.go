package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if migrationsApplied != 2 {
		t.Fatalf("migration count = %d, want 2", migrationsApplied)
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

func TestOpenConfiguresConcurrentDurableSQLite(t *testing.T) {
	t.Parallel()

	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	for _, test := range []struct {
		pragma string
		want   string
	}{
		{pragma: "foreign_keys", want: "1"},
		{pragma: "busy_timeout", want: "5000"},
		{pragma: "journal_mode", want: "wal"},
		{pragma: "synchronous", want: "2"},
	} {
		var got string
		if err := database.connection.QueryRow("PRAGMA " + test.pragma).Scan(&got); err != nil {
			t.Fatalf("query PRAGMA %s: %v", test.pragma, err)
		}
		if got != test.want {
			t.Fatalf("PRAGMA %s = %q, want %q", test.pragma, got, test.want)
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

func TestOpenRejectsUnknownAppliedMigration(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	database, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := database.connection.Exec(
		"INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)",
		"999_future.sql",
	); err != nil {
		t.Fatalf("insert future migration fixture: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = Open(directory)
	if err == nil || !strings.Contains(err.Error(), "unknown migration") {
		t.Fatalf("Open() error = %v, want unknown migration rejection", err)
	}
}

func TestOpenSerializesConcurrentMigration(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	start := make(chan struct{})
	results := make(chan error, 4)
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			database, err := Open(directory)
			if err == nil {
				err = database.Close()
			}
			results <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Open() error = %v", err)
		}
	}
}
