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

// Path returns the application-owned database path for operational diagnostics.
func (database *DB) Path() string {
	return database.path
}

func (database *DB) initialize(context context.Context) error {
	if _, err := database.connection.ExecContext(context, "PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("enable SQLite foreign keys: %w", err)
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

func (database *DB) applyMigration(context context.Context, name string) error {
	var applied int
	if err := database.connection.QueryRowContext(context, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", name).Scan(&applied); err != nil {
		return fmt.Errorf("inspect migration %s: %w", name, err)
	}
	if applied == 1 {
		return nil
	}
	contents, err := migrations.ReadFile(filepath.Join("migrations", name))
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	transaction, err := database.connection.BeginTx(context, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(context, string(contents)); err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	if _, err := transaction.ExecContext(context, "INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)", name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}
