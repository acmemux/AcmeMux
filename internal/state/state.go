// Package state owns application-only SQLite state and forward-only migrations.
package state

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const databaseFilename = "acmemux.db"

//go:embed migrations/*.sql
var migrations embed.FS

// DB wraps the application-owned SQLite database.
type DB struct {
	connection *sql.DB
	path       string
}

const busyTimeoutMilliseconds = 5000

// Open creates restrictive application state, opens SQLite, and applies all
// embedded forward-only migrations transactionally.
func Open(directory string) (*DB, error) {
	if directory == "" {
		return nil, errors.New("state directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("restrict state directory: %w", err)
	}

	databasePath := filepath.Join(directory, databaseFilename)
	if info, err := os.Lstat(databasePath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("application database cannot be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect application database: %w", err)
	}
	file, err := os.OpenFile(databasePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create application database: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close new application database: %w", err)
	}
	if err := os.Chmod(databasePath, 0o600); err != nil {
		return nil, fmt.Errorf("restrict application database: %w", err)
	}

	connection, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	connection.SetMaxOpenConns(1)
	database := &DB{connection: connection, path: databasePath}

	context, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := database.initialize(context); err != nil {
		connection.Close()
		return nil, err
	}
	return database, nil
}

// Close closes the underlying database connection.
func (database *DB) Close() error {
	return database.connection.Close()
}

// PingContext reports whether application state is ready.
func (database *DB) PingContext(context context.Context) error {
	return database.connection.PingContext(context)
}

// BeginTx begins an application-state transaction. Internal application
// packages depend on this narrow forwarding surface rather than the concrete
// SQLite connection.
func (database *DB) BeginTx(context context.Context, options *sql.TxOptions) (*sql.Tx, error) {
	return database.connection.BeginTx(context, options)
}

// ExecContext executes a bounded application-state statement.
func (database *DB) ExecContext(context context.Context, query string, arguments ...any) (sql.Result, error) {
	return database.connection.ExecContext(context, query, arguments...)
}

// QueryRowContext queries one application-state row.
func (database *DB) QueryRowContext(context context.Context, query string, arguments ...any) *sql.Row {
	return database.connection.QueryRowContext(context, query, arguments...)
}

// Path returns the application-owned database path for operational diagnostics.
func (database *DB) Path() string {
	return database.path
}

func (database *DB) initialize(context context.Context) error {
	if _, err := database.connection.ExecContext(context, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable SQLite foreign keys: %w", err)
	}
	if _, err := database.connection.ExecContext(context, fmt.Sprintf("PRAGMA busy_timeout = %d", busyTimeoutMilliseconds)); err != nil {
		return fmt.Errorf("configure SQLite busy timeout: %w", err)
	}
	if _, err := database.connection.ExecContext(context, "PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("enable SQLite write-ahead log: %w", err)
	}
	if _, err := database.connection.ExecContext(context, "PRAGMA synchronous = FULL"); err != nil {
		return fmt.Errorf("configure SQLite synchronization: %w", err)
	}
	if _, err := database.connection.ExecContext(context, `CREATE TABLE IF NOT EXISTS schema_migrations (
version TEXT PRIMARY KEY,
applied_at TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	knownMigrations := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			knownMigrations[entry.Name()] = struct{}{}
		}
	}
	if err := database.rejectUnknownMigrations(context, knownMigrations); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		if err := database.applyMigration(context, entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (database *DB) rejectUnknownMigrations(context context.Context, known map[string]struct{}) error {
	rows, err := database.connection.QueryContext(context, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return fmt.Errorf("inspect applied migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return fmt.Errorf("read applied migration version: %w", err)
		}
		if _, exists := known[version]; !exists {
			return fmt.Errorf("application state contains unknown migration %q", version)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	return nil
}

func (database *DB) applyMigration(context context.Context, name string) error {
	contents, err := migrations.ReadFile(filepath.Join("migrations", name))
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	connection, err := database.connection.Conn(context)
	if err != nil {
		return fmt.Errorf("reserve connection for migration %s: %w", name, err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(context, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer connection.ExecContext(context, "ROLLBACK")

	var applied int
	if err := connection.QueryRowContext(context, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name).Scan(&applied); err != nil {
		return fmt.Errorf("inspect migration %s: %w", name, err)
	}
	if applied == 1 {
		if _, err := connection.ExecContext(context, "COMMIT"); err != nil {
			return fmt.Errorf("finish migration inspection %s: %w", name, err)
		}
		return nil
	}
	if _, err := connection.ExecContext(context, string(contents)); err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	if _, err := connection.ExecContext(context, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)", name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if _, err := connection.ExecContext(context, "COMMIT"); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}
