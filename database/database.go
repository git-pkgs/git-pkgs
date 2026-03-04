// Package database provides read-only access to git-pkgs dependency databases.
//
// Extensions and external tools can use this package to query dependency data
// without shelling out to CLI commands or opening raw SQLite connections.
//
// Use [OpenReadOnly] for extensions that only need to read data. It opens the
// database in SQLite read-only mode and validates the schema version on open,
// returning an error if the database was created by an incompatible version of
// git-pkgs.
//
// Use [Open] for tools like the proxy that manage their own write paths and
// need shared connection helpers without schema validation.
package database

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 8

// DB provides read-only access to a git-pkgs dependency database.
// The underlying *sql.DB is unexported to prevent callers from
// running arbitrary SQL against the database.
type DB struct {
	db   *sql.DB
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
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

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
	sqlDB, err := sql.Open("sqlite", uri)
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

// SchemaVersion reads the schema version from the database.
func (db *DB) SchemaVersion() (int, error) {
	var version int
	err := db.db.QueryRow("SELECT version FROM schema_info LIMIT 1").Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
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
