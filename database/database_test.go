package database_test

import (
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/database"
	idb "github.com/git-pkgs/git-pkgs/internal/database"
)

func createTestDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := idb.Create(dbPath)
	if err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	_ = db.Close()
	return dbPath
}

func TestExists(t *testing.T) {
	t.Run("returns false when no database", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
		if database.Exists(dbPath) {
			t.Error("expected database to not exist")
		}
	})

	t.Run("returns true when database exists", func(t *testing.T) {
		dbPath := createTestDB(t)
		if !database.Exists(dbPath) {
			t.Error("expected database to exist")
		}
	})
}

func TestOpen(t *testing.T) {
	t.Run("opens existing database", func(t *testing.T) {
		dbPath := createTestDB(t)

		db, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = db.Close() }()

		version, err := db.SchemaVersion()
		if err != nil {
			t.Fatalf("reading schema version: %v", err)
		}
		if version != database.SchemaVersion {
			t.Errorf("got version %d, want %d", version, database.SchemaVersion)
		}
	})

	t.Run("does not validate schema version", func(t *testing.T) {
		// Open does not reject mismatched versions -- that's OpenReadOnly's job.
		dbPath := createTestDB(t)
		db, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = db.Close()
	})
}

func TestOpenReadOnly(t *testing.T) {
	t.Run("opens database in read-only mode", func(t *testing.T) {
		dbPath := createTestDB(t)

		db, err := database.OpenReadOnly(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = db.Close() }()

		version, err := db.SchemaVersion()
		if err != nil {
			t.Fatalf("reading schema version: %v", err)
		}
		if version != database.SchemaVersion {
			t.Errorf("got version %d, want %d", version, database.SchemaVersion)
		}
	})

	t.Run("rejects wrong schema version", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")

		// Create a database with a different schema version
		internalDB, err := idb.Create(dbPath)
		if err != nil {
			t.Fatalf("creating test database: %v", err)
		}
		// Manually change schema version
		_, err = internalDB.Exec("UPDATE schema_info SET version = 999")
		if err != nil {
			t.Fatalf("updating schema version: %v", err)
		}
		_ = internalDB.Close()

		_, err = database.OpenReadOnly(dbPath)
		if err == nil {
			t.Fatal("expected error for wrong schema version")
		}
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "nonexistent.sqlite3")
		_, err := database.OpenReadOnly(dbPath)
		if err == nil {
			t.Fatal("expected error for non-existent file")
		}
	})
}

func TestSchemaVersionConst(t *testing.T) {
	if database.SchemaVersion != idb.SchemaVersion {
		t.Errorf("public SchemaVersion %d != internal SchemaVersion %d",
			database.SchemaVersion, idb.SchemaVersion)
	}
}
