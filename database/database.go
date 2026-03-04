// Package database provides shared database access for git-pkgs and extensions.
//
// This package serves two audiences:
//
// Extensions and external tools use [OpenReadOnly] to query dependency data
// without shelling out to CLI commands. It opens the database in SQLite
// read-only mode and validates the schema version on open, returning an error
// if the database was created by an incompatible version of git-pkgs.
//
// Tools like the proxy use [Open] for read-write access to the shared
// packages and versions tables, along with shared types and query methods
// that keep both projects in sync.
package database

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

const SchemaVersion = 8

// DB provides access to a git-pkgs dependency database.
type DB struct {
	db   *sqlx.DB
	path string
}

// Exists checks if a database file exists at the given path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Open opens a database with read pragmas applied (WAL, synchronous=NORMAL).
// This does not validate the schema version. Use this for tools that manage
// their own schema or write paths.
func Open(path string) (*DB, error) {
	sqlDB, err := sqlx.Open("sqlite", path+"?_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)

	db := &DB{db: sqlDB, path: path}
	if err := db.OptimizeForReads(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("optimizing database: %w", err)
	}

	return db, nil
}

// OpenReadOnly opens a database in read-only mode and validates that the
// schema version matches SchemaVersion. Returns an error if the database
// has a different schema version than expected.
func OpenReadOnly(path string) (*DB, error) {
	uri := "file:" + path + "?mode=ro"
	sqlDB, err := sqlx.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db := &DB{db: sqlDB, path: path}
	if err := db.OptimizeForReads(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("optimizing database: %w", err)
	}

	version, err := db.SchemaVersion()
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("reading schema version: %w", err)
	}
	if version != SchemaVersion {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("schema version mismatch: database has version %d, expected %d", version, SchemaVersion)
	}

	return db, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.db.Close()
}

// SQLX returns the underlying *sqlx.DB for callers that need direct access.
// Use this when you need to run queries not covered by the built-in methods.
func (db *DB) SQLX() *sqlx.DB {
	return db.db
}

// Rebind transforms a query from ? placeholders to the appropriate bindvar
// type for the database driver.
func (db *DB) Rebind(query string) string {
	return db.db.Rebind(query)
}

// Exec executes a query without returning any rows.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.db.Exec(query, args...)
}

// SchemaVersion reads the schema version from the database.
func (db *DB) SchemaVersion() (int, error) {
	var version int
	err := db.db.Get(&version, "SELECT version FROM schema_info LIMIT 1")
	if err != nil {
		return 0, err
	}
	return version, nil
}

// Path returns the database file path.
func (db *DB) Path() string {
	return db.path
}

// OptimizeForReads sets pragmas for read-optimized access.
func (db *DB) OptimizeForReads() error {
	_, err := db.db.Exec(`
		PRAGMA synchronous = NORMAL;
		PRAGMA journal_mode = WAL;
	`)
	return err
}

// OptimizeForBulkWrites sets pragmas for bulk write performance.
func (db *DB) OptimizeForBulkWrites() error {
	_, err := db.db.Exec(`
		PRAGMA synchronous = OFF;
		PRAGMA journal_mode = WAL;
		PRAGMA cache_size = -64000;
	`)
	return err
}
