package database_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestExists(t *testing.T) {
	t.Run("returns false when no database", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		if database.Exists(dbPath) {
			t.Error("expected database to not exist")
		}
	})

	t.Run("returns true when database exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close: %v", err)
		}

		if !database.Exists(dbPath) {
			t.Error("expected database to exist")
		}
	})
}

func TestCreate(t *testing.T) {
	t.Run("creates database at path", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = db.Close() }()

		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			t.Error("database file was not created")
		}
	})

	t.Run("creates all tables", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = db.Close() }()

		tables := []string{
			"schema_info",
			"branches",
			"commits",
			"branch_commits",
			"manifests",
			"dependency_changes",
			"dependency_snapshots",
			"packages",
			"versions",
			"vulnerabilities",
			"vulnerability_packages",
		}

		for _, table := range tables {
			var name string
			err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
			if err != nil {
				t.Errorf("table %s not found: %v", table, err)
			}
		}
	})

	t.Run("sets schema version", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer func() { _ = db.Close() }()

		version, err := db.SchemaVersion()
		if err != nil {
			t.Fatalf("failed to get schema version: %v", err)
		}

		if version != database.SchemaVersion {
			t.Errorf("expected schema version %d, got %d", database.SchemaVersion, version)
		}
	})

	t.Run("recreates database when exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db1, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = db1.Exec("INSERT INTO branches (name) VALUES (?)", "test")
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}
		if err := db1.Close(); err != nil {
			t.Fatalf("failed to close db1: %v", err)
		}

		db2, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("unexpected error on recreate: %v", err)
		}
		defer func() { _ = db2.Close() }()

		var count int
		err = db2.QueryRow("SELECT COUNT(*) FROM branches").Scan(&count)
		if err != nil {
			t.Fatalf("failed to count: %v", err)
		}

		if count != 0 {
			t.Error("expected fresh database with no branches")
		}
	})
}

func TestOpen(t *testing.T) {
	t.Run("opens existing database", func(t *testing.T) {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

		db1, err := database.Create(dbPath)
		if err != nil {
			t.Fatalf("failed to create: %v", err)
		}

		_, err = db1.Exec("INSERT INTO branches (name) VALUES (?)", "main")
		if err != nil {
			t.Fatalf("failed to insert: %v", err)
		}
		if err := db1.Close(); err != nil {
			t.Fatalf("failed to close db1: %v", err)
		}

		db2, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to open: %v", err)
		}
		defer func() { _ = db2.Close() }()

		var name string
		err = db2.QueryRow("SELECT name FROM branches WHERE name = ?", "main").Scan(&name)
		if err != nil {
			t.Errorf("expected to find branch: %v", err)
		}
	})
}

func TestSchemaIndexes(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = db.Close() }()

	indexes := []struct {
		table string
		index string
	}{
		{"branches", "idx_branches_name"},
		{"commits", "idx_commits_sha"},
		{"branch_commits", "idx_branch_commits_unique"},
		{"manifests", "idx_manifests_path"},
		{"dependency_changes", "idx_dependency_changes_name"},
		{"dependency_changes", "idx_dependency_changes_ecosystem"},
		{"dependency_changes", "idx_dependency_changes_purl"},
		{"dependency_snapshots", "idx_snapshots_unique"},
		{"packages", "idx_packages_purl"},
		{"packages", "idx_packages_ecosystem_name"},
		{"versions", "idx_versions_purl"},
		{"versions", "idx_versions_package_purl"},
		{"vulnerability_packages", "idx_vuln_packages_ecosystem_name"},
	}

	for _, idx := range indexes {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx.index).Scan(&name)
		if err != nil {
			t.Errorf("index %s on %s not found: %v", idx.index, idx.table, err)
		}
	}
}
