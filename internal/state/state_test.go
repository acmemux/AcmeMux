package state

import (
	"context"
	"database/sql"
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
	if migrationsApplied != 7 {
		t.Fatalf("migration count = %d, want 7", migrationsApplied)
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

func TestNativeEditMigrationCreatesSecretFreeRecoverySchema(t *testing.T) {
	t.Parallel()

	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	for _, table := range []string{"workspace_edit_journal", "workspace_edit_journal_file"} {
		var definition string
		if err := database.connection.QueryRow(
			"SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", table,
		).Scan(&definition); err != nil {
			t.Fatalf("inspect %s schema: %v", table, err)
		}
		columns, err := database.connection.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatalf("inspect %s columns: %v", table, err)
		}
		for columns.Next() {
			var (
				columnID     int
				name         string
				columnType   string
				notNull      int
				defaultValue sql.NullString
				primaryKey   int
			)
			if err := columns.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				columns.Close()
				t.Fatalf("read %s columns: %v", table, err)
			}
			for _, prohibited := range []string{"content", "hash", "sha", "secret", "yaml", "value", "token"} {
				if strings.Contains(strings.ToLower(name), prohibited) {
					columns.Close()
					t.Fatalf("%s schema contains prohibited recovery field %q", table, name)
				}
			}
		}
		if err := columns.Err(); err != nil {
			columns.Close()
			t.Fatalf("read %s columns: %v", table, err)
		}
		columns.Close()
	}

	rows, err := database.connection.Query("PRAGMA foreign_key_list(workspace_edit_journal_file)")
	if err != nil {
		t.Fatalf("inspect native-edit foreign key: %v", err)
	}
	defer rows.Close()
	foreignKeys := 0
	for rows.Next() {
		foreignKeys++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read native-edit foreign key: %v", err)
	}
	if foreignKeys != 1 {
		t.Fatalf("native-edit foreign-key columns = %d, want 1", foreignKeys)
	}
}

func TestWorkspaceMigrationCreatesBoundedRelationalEvidenceSchema(t *testing.T) {
	t.Parallel()

	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	for _, table := range []string{
		"workspace_selection",
		"workspace_path_observation",
		"workspace_component_observation",
		"workspace_review_diagnostic",
	} {
		var definition string
		if err := database.connection.QueryRow(
			"SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", table,
		).Scan(&definition); err != nil {
			t.Fatalf("inspect %s schema: %v", table, err)
		}
		columns, err := database.connection.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			t.Fatalf("inspect %s columns: %v", table, err)
		}
		for columns.Next() {
			var (
				columnID     int
				name         string
				columnType   string
				notNull      int
				defaultValue sql.NullString
				primaryKey   int
			)
			if err := columns.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				columns.Close()
				t.Fatalf("read %s columns: %v", table, err)
			}
			for _, prohibited := range []string{"yaml", "secret", "content", "certificate", "private_key"} {
				if strings.Contains(strings.ToLower(name), prohibited) {
					columns.Close()
					t.Fatalf("%s schema contains prohibited content field %q", table, name)
				}
			}
			if table == "workspace_component_observation" && name == "nlink_decimal" {
				columns.Close()
				t.Fatal("volatile component link counts must not be persisted")
			}
		}
		if err := columns.Err(); err != nil {
			columns.Close()
			t.Fatalf("read %s columns: %v", table, err)
		}
		columns.Close()
	}

	var foreignKeys int
	rows, err := database.connection.Query("PRAGMA foreign_key_list(workspace_component_observation)")
	if err != nil {
		t.Fatalf("inspect workspace component foreign keys: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		foreignKeys++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read workspace component foreign keys: %v", err)
	}
	if foreignKeys != 2 {
		t.Fatalf("workspace component foreign-key columns = %d, want 2", foreignKeys)
	}
}

func TestRuntimeReviewContinuityMigrationInvalidatesLegacySelection(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	createLegacyRuntimeState(t, directory)

	database, err := Open(directory)
	if err != nil {
		t.Fatalf("Open(upgrade) error = %v", err)
	}
	defer database.Close()

	var selections int
	if err := database.connection.QueryRow("SELECT COUNT(*) FROM runtime_selection").Scan(&selections); err != nil {
		t.Fatalf("count migrated runtime selections: %v", err)
	}
	if selections != 0 {
		t.Fatalf("migrated runtime selection count = %d, want 0", selections)
	}

	wantColumns := map[string]bool{
		"capabilities":                  false,
		"build_provenance_complete":     false,
		"build_command_path":            false,
		"build_dependency_graph_sha256": false,
	}
	rows, err := database.connection.Query("PRAGMA table_info(runtime_selection)")
	if err != nil {
		t.Fatalf("inspect migrated runtime schema: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			columnID     int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("read migrated runtime schema: %v", err)
		}
		if _, tracked := wantColumns[name]; tracked {
			if notNull != 1 {
				t.Fatalf("runtime_selection.%s NOT NULL = %d, want 1", name, notNull)
			}
			wantColumns[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("inspect migrated runtime schema: %v", err)
	}
	for name, found := range wantColumns {
		if !found {
			t.Fatalf("runtime_selection.%s was not added by migration", name)
		}
	}
}

func createLegacyRuntimeState(t *testing.T, directory string) {
	t.Helper()

	connection, err := sql.Open("sqlite", filepath.Join(directory, databaseFilename))
	if err != nil {
		t.Fatalf("open legacy SQLite fixture: %v", err)
	}
	if _, err := connection.Exec(`CREATE TABLE schema_migrations (
version TEXT PRIMARY KEY,
applied_at TEXT NOT NULL
)`); err != nil {
		connection.Close()
		t.Fatalf("create legacy migration ledger: %v", err)
	}
	for _, name := range []string{"001_foundation.sql", "002_identity.sql", "003_runtime.sql"} {
		contents, err := migrations.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			connection.Close()
			t.Fatalf("read legacy migration %s: %v", name, err)
		}
		if _, err := connection.Exec(string(contents)); err != nil {
			connection.Close()
			t.Fatalf("apply legacy migration %s: %v", name, err)
		}
		if _, err := connection.Exec(
			"INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)",
			name,
		); err != nil {
			connection.Close()
			t.Fatalf("record legacy migration %s: %v", name, err)
		}
	}
	if _, err := connection.Exec(`INSERT INTO runtime_selection (
    singleton_id, canonical_path, device_decimal, inode_decimal, mode, uid, gid,
    size_bytes, modified_at_utc, changed_at_utc, sha256, version_kind, version_value,
    platform_os, platform_arch, build_available, build_go_version, build_main_path,
    build_main_version, build_goos, build_goarch, build_vcs_revision,
    build_vcs_modified_known, build_vcs_modified_valid, build_vcs_modified,
    version_output, observed_at_utc, compatibility_manifest_id, reviewed_at_utc
) VALUES (
    1, '/usr/local/bin/lego', '1', '2', 33261, 0, 0,
    1, '2026-08-15T00:00:00Z', '2026-08-15T00:00:00Z',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'release', 'v5.3.1', 'linux', 'amd64', 1, 'go1.26.5',
    'github.com/go-acme/lego/v5', 'v5.3.1', 'linux', 'amd64',
    '589c84af4f26629fbdaa7fbca712f806632ccb7e', 1, 1, 0,
    'lego version 5.3.1 linux/amd64', '2026-08-15T00:00:00Z',
    'lego-v5.3.1', '2026-08-15T00:00:00Z'
)`); err != nil {
		connection.Close()
		t.Fatalf("insert legacy runtime selection: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close legacy SQLite fixture: %v", err)
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
