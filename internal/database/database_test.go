package database_test

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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
			"version_lists",
			"vulnerabilities",
			"vulnerability_packages",
			"notes",
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

func TestOpenUpgradesSchema(t *testing.T) {
	t.Run("upgrades version 5 in place and preserves rows", testUpgradeVersion5Schema)
	t.Run("rebuilds version 5 and preserves cached rows", testRebuildVersion5Schema)
	t.Run("handles the origin column added without a version bump", testUpgradeVersion8Origin)
	t.Run("adopts a current database created before index versioning", testAdoptLegacyCurrentIndex)
	t.Run("rejects a schema created by a newer binary", testRejectNewerSchema)
	t.Run("rejects an index created by a newer binary", testRejectNewerIndex)
	t.Run("rolls back a failed migration", testMigrationRollback)
	t.Run("keeps the previous database when a rebuild fails", testFailedRebuild)
	t.Run("serializes concurrent upgrades", testConcurrentRebuild)
	t.Run("preserves database file permissions", testRebuildPreservesPermissions)
}

func testAdoptLegacyCurrentIndex(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 0"); err != nil {
		t.Fatalf("failed to clear index version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}

	db, err = database.Open(dbPath)
	if err != nil {
		t.Fatalf("failed to adopt current database: %v", err)
	}
	defer func() { _ = db.Close() }()

	var indexVersion int
	if err := db.QueryRow("PRAGMA user_version").Scan(&indexVersion); err != nil {
		t.Fatalf("failed to read index version: %v", err)
	}
	if indexVersion != database.IndexVersion {
		t.Errorf("expected index version %d, got %d", database.IndexVersion, indexVersion)
	}
}

func testRebuildVersion5Schema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	createVersion5Database(t, dbPath)

	db, result, err := database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
		return nil
	})
	if err != nil {
		t.Fatalf("failed to rebuild database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if !result.Rebuilt {
		t.Fatal("expected indexed data to be rebuilt")
	}

	var latestVersion, repositoryURL, packageSource string
	if err := db.QueryRow(`
		SELECT latest_version, repository_url, source
		FROM packages WHERE purl = 'pkg:gem/rails'
	`).Scan(&latestVersion, &repositoryURL, &packageSource); err != nil {
		t.Fatalf("failed to read preserved package cache: %v", err)
	}
	if latestVersion != "8.0.0" || repositoryURL != "https://example.com/rails" || packageSource != "registry-cache" {
		t.Errorf("unexpected preserved package cache: %q, %q, %q", latestVersion, repositoryURL, packageSource)
	}

	var versionLicense, versionIntegrity, versionSource string
	if err := db.QueryRow(`
		SELECT license, integrity, source
		FROM versions WHERE purl = 'pkg:gem/rails@8.0.0'
	`).Scan(&versionLicense, &versionIntegrity, &versionSource); err != nil {
		t.Fatalf("failed to read preserved version cache: %v", err)
	}
	if versionLicense != "MIT" || versionIntegrity != "sha256-test" || versionSource != "registry-cache" {
		t.Errorf("unexpected preserved version cache: %q, %q, %q", versionLicense, versionIntegrity, versionSource)
	}

	var summary, packageName string
	if err := db.QueryRow("SELECT summary FROM vulnerabilities WHERE id = 'TEST-1'").Scan(&summary); err != nil {
		t.Fatalf("failed to read preserved vulnerability: %v", err)
	}
	if err := db.QueryRow("SELECT package_name FROM vulnerability_packages WHERE vulnerability_id = 'TEST-1'").Scan(&packageName); err != nil {
		t.Fatalf("failed to read preserved vulnerability package: %v", err)
	}
	if summary != "test vulnerability" || packageName != "rails" {
		t.Errorf("unexpected preserved vulnerability cache: %q, %q", summary, packageName)
	}
}

func testUpgradeVersion5Schema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	createVersion5Database(t, dbPath)

	rebuildErr := errors.New("stop after schema migration")
	_, result, err := database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
		return rebuildErr
	})
	if !errors.Is(err, rebuildErr) {
		t.Fatalf("expected rebuild to stop after migration, got: %v", err)
	}

	if result.FromSchemaVersion != 5 || result.ToSchemaVersion != database.SchemaVersion {
		t.Fatalf("unexpected upgrade result: %+v", result)
	}
	if !result.RequiresRebuild() {
		t.Fatal("expected old indexed data to require a rebuild")
	}

	db := openRawDatabase(t, dbPath)
	defer func() { _ = db.Close() }()

	var version int
	if err := db.QueryRow("SELECT version FROM schema_info LIMIT 1").Scan(&version); err != nil {
		t.Fatalf("failed to read schema version: %v", err)
	}
	if version != database.SchemaVersion {
		t.Fatalf("expected schema version %d, got %d", database.SchemaVersion, version)
	}

	var packageName string
	if err := db.QueryRow("SELECT name FROM packages WHERE id = 1").Scan(&packageName); err != nil {
		t.Fatalf("failed to read preserved package: %v", err)
	}
	if packageName != "rails" {
		t.Errorf("expected preserved package, got %q", packageName)
	}

	var direct int
	if err := db.QueryRow("SELECT direct FROM dependency_snapshots WHERE id = 1").Scan(&direct); err != nil {
		t.Fatalf("failed to read migrated snapshot: %v", err)
	}
	if direct != 0 {
		t.Errorf("expected migrated direct value 0, got %d", direct)
	}

	var indexSQL string
	if err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_snapshots_unique'").Scan(&indexSQL); err != nil {
		t.Fatalf("failed to read snapshot index: %v", err)
	}
	if !strings.Contains(indexSQL, "requirement") {
		t.Errorf("expected snapshot index to include requirement, got %q", indexSQL)
	}

	if _, err := db.Exec("INSERT INTO notes (purl, namespace) VALUES (?, ?)", "pkg:gem/rails", "test"); err != nil {
		t.Fatalf("failed to insert migrated note: %v", err)
	}
	var origin string
	if err := db.QueryRow("SELECT origin FROM notes WHERE purl = ?", "pkg:gem/rails").Scan(&origin); err != nil {
		t.Fatalf("failed to read migrated note: %v", err)
	}
	if origin != "git-pkgs" {
		t.Errorf("expected default note origin, got %q", origin)
	}
}

func testUpgradeVersion8Origin(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	createVersion8DatabaseWithOrigin(t, dbPath)

	db, result, err := database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
		return nil
	})
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if !result.Rebuilt {
		t.Fatal("expected indexed data to be rebuilt")
	}

	var origin string
	if err := db.QueryRow("SELECT origin FROM notes WHERE id = 1").Scan(&origin); err != nil {
		t.Fatalf("failed to read preserved note: %v", err)
	}
	if origin != "extension" {
		t.Errorf("expected preserved origin, got %q", origin)
	}
}

func testRejectNewerSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec("UPDATE schema_info SET version = ?", database.SchemaVersion+1); err != nil {
		t.Fatalf("failed to set newer schema version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}

	_, err = database.Open(dbPath)
	if err == nil {
		t.Fatal("expected newer schema to be rejected")
	}
	if !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testRejectNewerIndex(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", database.IndexVersion+1)); err != nil {
		t.Fatalf("failed to set newer index version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}

	_, err = database.Open(dbPath)
	if err == nil {
		t.Fatal("expected newer index to be rejected")
	}
	if !strings.Contains(err.Error(), "index version") || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testMigrationRollback(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	rawDB := openRawDatabase(t, dbPath)
	if _, err := rawDB.Exec(`
			CREATE TABLE schema_info (version INTEGER NOT NULL);
			INSERT INTO schema_info (version) VALUES (14);
			CREATE TABLE sentinel (value TEXT);
			INSERT INTO sentinel (value) VALUES ('preserved');
		`); err != nil {
		t.Fatalf("failed to create incomplete database: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("failed to close incomplete database: %v", err)
	}

	_, err := database.Open(dbPath)
	if err == nil {
		t.Fatal("expected migration to fail")
	}

	rawDB = openRawDatabase(t, dbPath)
	defer func() { _ = rawDB.Close() }()
	var version int
	if err := rawDB.QueryRow("SELECT version FROM schema_info").Scan(&version); err != nil {
		t.Fatalf("failed to read rolled back schema version: %v", err)
	}
	if version != 14 {
		t.Errorf("expected schema version 14 after rollback, got %d", version)
	}
	var value string
	if err := rawDB.QueryRow("SELECT value FROM sentinel").Scan(&value); err != nil {
		t.Fatalf("failed to read preserved row: %v", err)
	}
	if value != "preserved" {
		t.Errorf("expected preserved row, got %q", value)
	}
}

func testFailedRebuild(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec(`
			INSERT INTO notes (purl, namespace, message) VALUES ('pkg:gem/rails', 'test', 'keep me');
			PRAGMA user_version = 2147483647;
		`); err != nil {
		t.Fatalf("failed to prepare database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}

	rebuildErr := errors.New("rebuild failed")
	_, _, err = database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
		return rebuildErr
	})
	if !errors.Is(err, rebuildErr) {
		t.Fatalf("expected rebuild error, got %v", err)
	}

	rawDB := openRawDatabase(t, dbPath)
	defer func() { _ = rawDB.Close() }()
	var indexVersion int
	if err := rawDB.QueryRow("PRAGMA user_version").Scan(&indexVersion); err != nil {
		t.Fatalf("failed to read pending index version: %v", err)
	}
	if indexVersion == database.IndexVersion {
		t.Fatal("expected failed rebuild to remain pending")
	}

	var message string
	if err := rawDB.QueryRow("SELECT message FROM notes WHERE purl = 'pkg:gem/rails'").Scan(&message); err != nil {
		t.Fatalf("failed to read preserved note: %v", err)
	}
	if message != "keep me" {
		t.Errorf("expected preserved note, got %q", message)
	}
}

func testConcurrentRebuild(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}
	rawDB := openRawDatabase(t, dbPath)
	const rebuildRequiredVersion = 2_147_483_647
	if _, err := rawDB.Exec("PRAGMA user_version = " + fmt.Sprint(rebuildRequiredVersion)); err != nil {
		t.Fatalf("failed to mark database for rebuild: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("failed to close raw database: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var rebuilds int
	var wg sync.WaitGroup
	var rebuildMu sync.Mutex
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			db, _, err := database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
				rebuildMu.Lock()
				rebuilds++
				rebuildMu.Unlock()
				return nil
			})
			if db != nil {
				_ = db.Close()
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("concurrent open failed: %v", err)
		}
	}
	if rebuilds != 1 {
		t.Errorf("expected one rebuild, got %d", rebuilds)
	}
}

func testRebuildPreservesPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows only supports changing a file's writable bit")
	}

	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 2147483647"); err != nil {
		t.Fatalf("failed to mark database for rebuild: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close database: %v", err)
	}
	if err := os.Chmod(dbPath, 0o640); err != nil {
		t.Fatalf("failed to set database permissions: %v", err)
	}

	db, _, err = database.OpenWithRebuild(dbPath, func(previous, replacement *database.DB) error {
		return nil
	})
	if err != nil {
		t.Fatalf("failed to rebuild database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close rebuilt database: %v", err)
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("failed to read rebuilt database permissions: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("expected permissions 0640, got %04o", info.Mode().Perm())
	}
}

func openRawDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("failed to open raw database: %v", err)
	}
	return db
}

func createVersion5Database(t *testing.T, path string) {
	t.Helper()
	db := openRawDatabase(t, path)
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
		CREATE TABLE schema_info (version INTEGER NOT NULL);
		INSERT INTO schema_info (version) VALUES (5);
		CREATE TABLE branch_commits (
			id INTEGER PRIMARY KEY,
			branch_id INTEGER,
			commit_id INTEGER,
			position INTEGER
		);
		CREATE TABLE dependency_snapshots (
			id INTEGER PRIMARY KEY,
			commit_id INTEGER,
			manifest_id INTEGER,
			name TEXT NOT NULL,
			ecosystem TEXT,
			purl TEXT,
			requirement TEXT,
			dependency_type TEXT,
			integrity TEXT,
			created_at DATETIME,
			updated_at DATETIME
		);
		CREATE UNIQUE INDEX idx_snapshots_unique ON dependency_snapshots(commit_id, manifest_id, name);
		CREATE TABLE dependency_changes (
			id INTEGER PRIMARY KEY,
			commit_id INTEGER,
			manifest_id INTEGER,
			name TEXT NOT NULL,
			ecosystem TEXT,
			purl TEXT,
			change_type TEXT NOT NULL,
			requirement TEXT,
			previous_requirement TEXT,
			dependency_type TEXT,
			created_at DATETIME,
			updated_at DATETIME
		);
		CREATE TABLE packages (
			id INTEGER PRIMARY KEY,
			purl TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			latest_version TEXT,
			license TEXT,
			description TEXT,
			homepage TEXT,
			repository_url TEXT,
			supplier_name TEXT,
			supplier_type TEXT,
			source TEXT,
			enriched_at DATETIME,
			vulns_synced_at DATETIME,
			created_at DATETIME,
			updated_at DATETIME
		);
		CREATE TABLE versions (
			id INTEGER PRIMARY KEY,
			purl TEXT NOT NULL,
			package_purl TEXT NOT NULL,
			license TEXT,
			published_at DATETIME,
			integrity TEXT,
			source TEXT,
			enriched_at DATETIME,
			created_at DATETIME,
			updated_at DATETIME
		);
		CREATE TABLE vulnerabilities (
			id TEXT PRIMARY KEY,
			aliases TEXT,
			severity TEXT,
			cvss_score REAL,
			cvss_vector TEXT,
			refs TEXT,
			summary TEXT,
			details TEXT,
			published_at DATETIME,
			withdrawn_at DATETIME,
			modified_at DATETIME,
			fetched_at DATETIME NOT NULL
		);
		CREATE TABLE vulnerability_packages (
			id INTEGER PRIMARY KEY,
			vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
			ecosystem TEXT NOT NULL,
			package_name TEXT NOT NULL,
			affected_versions TEXT,
			fixed_versions TEXT
		);
		INSERT INTO branch_commits (id, branch_id, commit_id, position) VALUES (1, 1, 1, 0);
		INSERT INTO dependency_snapshots (id, commit_id, manifest_id, name, requirement) VALUES (1, 1, 1, 'rails', '8.0.0');
		INSERT INTO dependency_changes (id, name, change_type) VALUES (1, 'rails', 'added');
		INSERT INTO packages (
			id, purl, ecosystem, name, latest_version, license, description, homepage,
			repository_url, supplier_name, supplier_type, source
		) VALUES (
			1, 'pkg:gem/rails', 'rubygems', 'rails', '8.0.0', 'MIT', 'web framework',
			'https://rubyonrails.org', 'https://example.com/rails', 'Rails team', 'organization',
			'registry-cache'
		);
		INSERT INTO versions (id, purl, package_purl, license, integrity, source)
		VALUES (1, 'pkg:gem/rails@8.0.0', 'pkg:gem/rails', 'MIT', 'sha256-test', 'registry-cache');
		INSERT INTO vulnerabilities (id, summary, fetched_at)
		VALUES ('TEST-1', 'test vulnerability', '2026-01-01');
		INSERT INTO vulnerability_packages (id, vulnerability_id, ecosystem, package_name)
		VALUES (1, 'TEST-1', 'rubygems', 'rails');
	`); err != nil {
		t.Fatalf("failed to create version 5 database: %v", err)
	}
}

func createVersion8DatabaseWithOrigin(t *testing.T, path string) {
	t.Helper()
	db, err := database.Create(path)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO notes (id, purl, origin) VALUES (1, 'pkg:gem/rails', 'extension');
		UPDATE schema_info SET version = 8;
		PRAGMA user_version = 0;
	`); err != nil {
		t.Fatalf("failed to prepare version 8 database: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("failed to close version 8 database: %v", err)
	}
}

func TestMultipleVersionsSamePackage(t *testing.T) {
	// Regression test for https://github.com/git-pkgs/git-pkgs/issues/37
	// A package can appear multiple times with different versions (e.g., isexe@2.0.0 and isexe@3.1.1)
	// Both should be stored in the database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	writer := database.NewBatchWriter(db)

	if err := writer.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	manifest := database.ManifestInfo{
		Path:      "package-lock.json",
		Ecosystem: "npm",
		Kind:      "lockfile",
	}

	writer.AddCommit(database.CommitInfo{
		SHA:     "abc123",
		Message: "test commit",
	}, true)

	// Insert isexe@2.0.0 (runtime)
	writer.AddSnapshot("abc123", manifest, database.SnapshotInfo{
		ManifestPath:   "package-lock.json",
		Name:           "isexe",
		Ecosystem:      "npm",
		Requirement:    "2.0.0",
		DependencyType: "runtime",
	})

	// Insert isexe@3.1.1 (development) - same package name, different version
	writer.AddSnapshot("abc123", manifest, database.SnapshotInfo{
		ManifestPath:   "package-lock.json",
		Name:           "isexe",
		Ecosystem:      "npm",
		Requirement:    "3.1.1",
		DependencyType: "development",
	})

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	// Verify both versions are stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE name = 'isexe'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 isexe entries, got %d", count)
	}

	// Verify we can retrieve both with correct dependency types
	rows, err := db.Query("SELECT requirement, dependency_type FROM dependency_snapshots WHERE name = 'isexe' ORDER BY requirement")
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type entry struct {
		requirement string
		depType     string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.requirement, &e.depType); err != nil {
			t.Fatalf("failed to scan: %v", err)
		}
		entries = append(entries, e)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].requirement != "2.0.0" || entries[0].depType != "runtime" {
		t.Errorf("first entry: got %s/%s, want 2.0.0/runtime", entries[0].requirement, entries[0].depType)
	}
	if entries[1].requirement != "3.1.1" || entries[1].depType != "development" {
		t.Errorf("second entry: got %s/%s, want 3.1.1/development", entries[1].requirement, entries[1].depType)
	}
}

func TestStoreSnapshotWithDuplicates(t *testing.T) {
	// Test that StoreSnapshot handles duplicate entries gracefully.
	// This can happen when a manifest parser returns the same dependency
	// multiple times (e.g., different platforms or groups in Gemfile.lock).
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create a branch
	branch, err := db.GetOrCreateBranch("main")
	if err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	// Create snapshots with duplicates (same manifest, name, requirement)
	snapshots := []database.SnapshotInfo{
		{
			ManifestPath:   "Gemfile.lock",
			Name:           "rails",
			Ecosystem:      "rubygems",
			Requirement:    "7.0.0",
			DependencyType: "runtime",
		},
		{
			ManifestPath:   "Gemfile.lock",
			Name:           "rails",
			Ecosystem:      "rubygems",
			Requirement:    "7.0.0",
			DependencyType: "runtime",
		},
		{
			ManifestPath:   "Gemfile.lock",
			Name:           "rails",
			Ecosystem:      "rubygems",
			Requirement:    "7.0.0",
			DependencyType: "development", // Different dep type, same key
		},
		{
			ManifestPath:   "Gemfile.lock",
			Name:           "puma",
			Ecosystem:      "rubygems",
			Requirement:    "6.0.0",
			DependencyType: "runtime",
		},
	}

	commit := database.CommitInfo{
		SHA:     "abc123def456",
		Message: "test commit",
	}

	// This should not fail even with duplicates
	err = db.StoreSnapshot(branch.ID, commit, snapshots)
	if err != nil {
		t.Fatalf("StoreSnapshot failed with duplicates: %v", err)
	}

	// Verify only unique entries were stored
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE name = 'rails'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 rails entry (deduplicated), got %d", count)
	}

	// Verify puma was also stored
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE name = 'puma'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count puma: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 puma entry, got %d", count)
	}

	// Calling StoreSnapshot again for the same commit should be a no-op
	err = db.StoreSnapshot(branch.ID, commit, snapshots)
	if err != nil {
		t.Fatalf("StoreSnapshot failed on second call: %v", err)
	}

	// Count should still be 1
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE name = 'rails'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count after second call: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 rails entry after second call, got %d", count)
	}
}

func TestBatchWriterSharedCommits(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	sharedSHA := "shared123"
	sharedCommit := database.CommitInfo{
		SHA:     sharedSHA,
		Message: "shared commit",
	}
	manifest := database.ManifestInfo{
		Path:      "package-lock.json",
		Ecosystem: "npm",
		Kind:      "lockfile",
	}
	change := database.ChangeInfo{
		Name:       "lodash",
		Ecosystem:  "npm",
		ChangeType: "added",
	}
	snapshot := database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "lodash",
		Ecosystem:    "npm",
		Requirement:  "4.17.21",
	}

	// Index shared commit on branch "main"
	w1 := database.NewBatchWriter(db)
	if err := w1.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create main branch: %v", err)
	}
	w1.AddCommit(sharedCommit, true)
	w1.IncrementDepCommitCount()
	w1.AddChange(sharedSHA, manifest, change)
	w1.AddSnapshot(sharedSHA, manifest, snapshot)
	if err := w1.Flush(); err != nil {
		t.Fatalf("flush on main failed: %v", err)
	}

	// Index the same commit on branch "feature" — should not fail
	w2 := database.NewBatchWriter(db)
	if err := w2.CreateBranch("feature"); err != nil {
		t.Fatalf("failed to create feature branch: %v", err)
	}
	w2.AddCommit(sharedCommit, true)
	w2.IncrementDepCommitCount()
	w2.AddChange(sharedSHA, manifest, change)
	w2.AddSnapshot(sharedSHA, manifest, snapshot)
	if err := w2.Flush(); err != nil {
		t.Fatalf("flush on feature failed: %v", err)
	}

	// Verify the commit is linked to both branches
	var branchCount int
	err = db.QueryRow("SELECT COUNT(*) FROM branch_commits WHERE commit_id = (SELECT id FROM commits WHERE sha = ?)", sharedSHA).Scan(&branchCount)
	if err != nil {
		t.Fatalf("failed to count branch_commits: %v", err)
	}
	if branchCount != 2 {
		t.Errorf("expected commit linked to 2 branches, got %d", branchCount)
	}

	// Verify no duplicate dependency_changes
	var changeCount int
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_changes WHERE name = 'lodash'").Scan(&changeCount)
	if err != nil {
		t.Fatalf("failed to count changes: %v", err)
	}
	if changeCount != 1 {
		t.Errorf("expected 1 change row, got %d", changeCount)
	}
}

func TestBatchWriterSharedCommitsMultiManifest(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	sharedSHA := "multi456"
	sharedCommit := database.CommitInfo{
		SHA:     sharedSHA,
		Message: "add npm and pip deps",
	}
	npmManifest := database.ManifestInfo{
		Path:      "package-lock.json",
		Ecosystem: "npm",
		Kind:      "lockfile",
	}
	pipManifest := database.ManifestInfo{
		Path:      "Pipfile.lock",
		Ecosystem: "pip",
		Kind:      "lockfile",
	}
	npmChange := database.ChangeInfo{
		Name:       "express",
		Ecosystem:  "npm",
		ChangeType: "added",
	}
	pipChange := database.ChangeInfo{
		Name:       "requests",
		Ecosystem:  "pip",
		ChangeType: "added",
	}
	npmSnapshot := database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "express",
		Ecosystem:    "npm",
		Requirement:  "4.18.0",
	}
	pipSnapshot := database.SnapshotInfo{
		ManifestPath: "Pipfile.lock",
		Name:         "requests",
		Ecosystem:    "pip",
		Requirement:  "2.31.0",
	}

	// Index on main with both manifests
	w1 := database.NewBatchWriter(db)
	if err := w1.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create main branch: %v", err)
	}
	w1.AddCommit(sharedCommit, true)
	w1.IncrementDepCommitCount()
	w1.AddChange(sharedSHA, npmManifest, npmChange)
	w1.AddChange(sharedSHA, pipManifest, pipChange)
	w1.AddSnapshot(sharedSHA, npmManifest, npmSnapshot)
	w1.AddSnapshot(sharedSHA, pipManifest, pipSnapshot)
	if err := w1.Flush(); err != nil {
		t.Fatalf("flush on main failed: %v", err)
	}

	// Index same commit on feature — should not fail
	w2 := database.NewBatchWriter(db)
	if err := w2.CreateBranch("feature"); err != nil {
		t.Fatalf("failed to create feature branch: %v", err)
	}
	w2.AddCommit(sharedCommit, true)
	w2.IncrementDepCommitCount()
	w2.AddChange(sharedSHA, npmManifest, npmChange)
	w2.AddChange(sharedSHA, pipManifest, pipChange)
	w2.AddSnapshot(sharedSHA, npmManifest, npmSnapshot)
	w2.AddSnapshot(sharedSHA, pipManifest, pipSnapshot)
	if err := w2.Flush(); err != nil {
		t.Fatalf("flush on feature failed: %v", err)
	}

	// Commit linked to both branches
	var branchCount int
	err = db.QueryRow("SELECT COUNT(*) FROM branch_commits WHERE commit_id = (SELECT id FROM commits WHERE sha = ?)", sharedSHA).Scan(&branchCount)
	if err != nil {
		t.Fatalf("failed to count branch_commits: %v", err)
	}
	if branchCount != 2 {
		t.Errorf("expected commit linked to 2 branches, got %d", branchCount)
	}

	// Exactly 2 change rows (one per manifest, not duplicated)
	var changeCount int
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_changes").Scan(&changeCount)
	if err != nil {
		t.Fatalf("failed to count changes: %v", err)
	}
	if changeCount != 2 {
		t.Errorf("expected 2 change rows (npm + pip), got %d", changeCount)
	}

	// Exactly 2 snapshot rows (one per manifest, not duplicated)
	var snapCount int
	err = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots").Scan(&snapCount)
	if err != nil {
		t.Fatalf("failed to count snapshots: %v", err)
	}
	if snapCount != 2 {
		t.Errorf("expected 2 snapshot rows (npm + pip), got %d", snapCount)
	}

	// Verify both ecosystems present in snapshots
	var npmSnapCount, pipSnapCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE ecosystem = 'npm'").Scan(&npmSnapCount)
	_ = db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots WHERE ecosystem = 'pip'").Scan(&pipSnapCount)
	if npmSnapCount != 1 || pipSnapCount != 1 {
		t.Errorf("expected 1 npm and 1 pip snapshot, got npm=%d pip=%d", npmSnapCount, pipSnapCount)
	}
}

func TestInsertNoteUpsert(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	note := database.Note{
		PURL:      "pkg:npm/lodash@4.17.21",
		Namespace: "default",
		Message:   "first message",
	}

	// First insert should work
	if err := db.InsertNote(note); err != nil {
		t.Fatalf("first InsertNote failed: %v", err)
	}

	// Second insert with same purl+namespace should upsert, not fail
	note.Message = "updated message"
	if err := db.InsertNote(note); err != nil {
		t.Fatalf("second InsertNote failed (should upsert): %v", err)
	}

	// Verify the note was updated
	got, err := db.GetNote(note.PURL, note.Namespace)
	if err != nil {
		t.Fatalf("GetNote failed: %v", err)
	}
	if got.Message != "updated message" {
		t.Errorf("expected 'updated message', got %q", got.Message)
	}

	// Verify only one note exists
	notes, err := db.ListNotes("", "")
	if err != nil {
		t.Fatalf("ListNotes failed: %v", err)
	}
	if len(notes) != 1 {
		t.Errorf("expected 1 note, got %d", len(notes))
	}
}

func TestSearchDependenciesCrossEcosystem(t *testing.T) {
	// Regression test for https://github.com/git-pkgs/git-pkgs/issues/241
	// When the same package name exists in two ecosystems (e.g. npm and pip)
	// with different commit dates, SearchDependencies must return the correct
	// FirstSeen and LastChanged per ecosystem — not inherit from the other.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	npmDate := time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC)
	pipDate := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	npmManifest := database.ManifestInfo{
		Path:      "package-lock.json",
		Ecosystem: "npm",
		Kind:      "lockfile",
	}
	pipManifest := database.ManifestInfo{
		Path:      "Pipfile.lock",
		Ecosystem: "pip",
		Kind:      "lockfile",
	}

	writer := database.NewBatchWriter(db)
	if err := writer.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	// First commit: add "requests" in npm ecosystem
	npmCommit := database.CommitInfo{
		SHA:         "aaa111",
		Message:     "add npm requests",
		CommittedAt: npmDate,
	}
	writer.AddCommit(npmCommit, true)
	writer.IncrementDepCommitCount()
	writer.AddChange("aaa111", npmManifest, database.ChangeInfo{
		Name:       "requests",
		Ecosystem:  "npm",
		ChangeType: "added",
	})
	writer.AddSnapshot("aaa111", npmManifest, database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "requests",
		Ecosystem:    "npm",
		Requirement:  "1.0.0",
	})

	// Second commit: add "requests" in pip ecosystem (different date)
	// The npm dep is still present, so it appears in this snapshot too.
	pipCommit := database.CommitInfo{
		SHA:         "bbb222",
		Message:     "add pip requests",
		CommittedAt: pipDate,
	}
	writer.AddCommit(pipCommit, true)
	writer.IncrementDepCommitCount()
	writer.AddChange("bbb222", pipManifest, database.ChangeInfo{
		Name:       "requests",
		Ecosystem:  "pip",
		ChangeType: "added",
	})
	writer.AddSnapshot("bbb222", pipManifest, database.SnapshotInfo{
		ManifestPath: "Pipfile.lock",
		Name:         "requests",
		Ecosystem:    "pip",
		Requirement:  "2.31.0",
	})
	// npm's "requests" is still in the project at this commit
	writer.AddSnapshot("bbb222", npmManifest, database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "requests",
		Ecosystem:    "npm",
		Requirement:  "1.0.0",
	})

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	// Look up the branchID for SearchDependencies
	branch, err := db.GetOrCreateBranch("main")
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	results, err := db.SearchDependencies(branch.ID, "requests", "", false)
	if err != nil {
		t.Fatalf("SearchDependencies failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results (npm + pip), got %d", len(results))
	}

	npmExpected := npmDate.UTC().Format("2006-01-02 15:04:05")
	pipExpected := pipDate.UTC().Format("2006-01-02 15:04:05")

	for _, r := range results {
		switch r.Ecosystem {
		case "npm":
			if r.FirstSeen != npmExpected {
				t.Errorf("npm FirstSeen: got %q, want %q", r.FirstSeen, npmExpected)
			}
			if r.LastChanged != npmExpected {
				t.Errorf("npm LastChanged: got %q, want %q", r.LastChanged, npmExpected)
			}
			if r.AddedIn != "aaa111" {
				t.Errorf("npm AddedIn: got %q, want %q", r.AddedIn, "aaa111")
			}
		case "pip":
			if r.FirstSeen != pipExpected {
				t.Errorf("pip FirstSeen: got %q, want %q", r.FirstSeen, pipExpected)
			}
			if r.LastChanged != pipExpected {
				t.Errorf("pip LastChanged: got %q, want %q", r.LastChanged, pipExpected)
			}
			if r.AddedIn != "bbb222" {
				t.Errorf("pip AddedIn: got %q, want %q", r.AddedIn, "bbb222")
			}
		default:
			t.Errorf("unexpected ecosystem: %s", r.Ecosystem)
		}
	}
}

func TestSearchDependenciesAddedInSHA(t *testing.T) {
	// Regression test: added_in must return the SHA of the chronologically
	// earliest commit, not the lexicographically smallest SHA.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pkgs.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() { _ = db.Close() }()

	earlyDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	lateDate := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)

	manifest := database.ManifestInfo{
		Path:      "package-lock.json",
		Ecosystem: "npm",
		Kind:      "lockfile",
	}

	writer := database.NewBatchWriter(db)
	if err := writer.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}

	// First chronological commit: SHA "zzz999" (lex-large but earliest)
	writer.AddCommit(database.CommitInfo{
		SHA:         "zzz999",
		Message:     "first add",
		CommittedAt: earlyDate,
	}, true)
	writer.IncrementDepCommitCount()
	writer.AddChange("zzz999", manifest, database.ChangeInfo{
		Name:       "lodash",
		Ecosystem:  "npm",
		ChangeType: "added",
	})
	writer.AddSnapshot("zzz999", manifest, database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "lodash",
		Ecosystem:    "npm",
		Requirement:  "4.17.0",
	})

	// Second chronological commit: SHA "aaa000" (lex-small, removed then re-added)
	writer.AddCommit(database.CommitInfo{
		SHA:         "aaa000",
		Message:     "re-add lodash",
		CommittedAt: lateDate,
	}, true)
	writer.IncrementDepCommitCount()
	writer.AddChange("aaa000", manifest, database.ChangeInfo{
		Name:       "lodash",
		Ecosystem:  "npm",
		ChangeType: "added",
	})
	writer.AddSnapshot("aaa000", manifest, database.SnapshotInfo{
		ManifestPath: "package-lock.json",
		Name:         "lodash",
		Ecosystem:    "npm",
		Requirement:  "4.17.21",
	})

	if err := writer.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	branch, err := db.GetOrCreateBranch("main")
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	results, err := db.SearchDependencies(branch.ID, "lodash", "", false)
	if err != nil {
		t.Fatalf("SearchDependencies failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// added_in should be the earliest commit SHA "zzz999", NOT "aaa000"
	if results[0].AddedIn != "zzz999" {
		t.Errorf("AddedIn: got %q, want %q (should be earliest commit, not lex-smallest SHA)",
			results[0].AddedIn, "zzz999")
	}

	expectedFirst := earlyDate.UTC().Format("2006-01-02 15:04:05")
	if results[0].FirstSeen != expectedFirst {
		t.Errorf("FirstSeen: got %q, want %q", results[0].FirstSeen, expectedFirst)
	}
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
