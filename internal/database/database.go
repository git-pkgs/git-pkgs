package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 16

type DB struct {
	*sql.DB
	path string
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func Create(path string) (*DB, error) {
	if err := ensureParentDir(path); err != nil {
		return nil, err
	}

	if Exists(path) {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing existing database: %w", err)
		}
	}

	db, err := Open(path)
	if err != nil {
		return nil, err
	}

	if err := db.CreateSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}

	return db, nil
}

// OpenOrCreate opens an existing database or creates a new one if it doesn't exist.
func OpenOrCreate(path string) (*DB, bool, error) {
	existed := Exists(path)
	if existed {
		db, err := Open(path)
		return db, true, err
	}
	if err := ensureParentDir(path); err != nil {
		return nil, false, err
	}

	db, err := Open(path)
	if err != nil {
		return nil, false, err
	}

	if err := db.CreateSchema(); err != nil {
		_ = db.Close()
		return nil, false, fmt.Errorf("creating schema: %w", err)
	}

	return db, false, nil
}

func ensureParentDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating database directory: %w", err)
	}
	return nil
}

func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	db := &DB{DB: sqlDB, path: path}
	if err := db.OptimizeForReads(); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("optimizing database: %w", err)
	}

	return db, nil
}

func (db *DB) OptimizeForBulkWrites() error {
	_, err := db.Exec(`
		PRAGMA synchronous = OFF;
		PRAGMA journal_mode = WAL;
		PRAGMA cache_size = -64000;
	`)
	return err
}

func (db *DB) OptimizeForReads() error {
	_, err := db.Exec(`
		PRAGMA synchronous = NORMAL;
		PRAGMA journal_mode = WAL;
	`)
	return err
}
