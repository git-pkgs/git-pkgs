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
