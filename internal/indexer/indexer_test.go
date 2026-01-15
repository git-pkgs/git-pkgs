package indexer_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	gitpkg "github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
)

func createTestRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	commands := [][]string{
		{"git", "init", "--initial-branch=main"},
		{"git", "config", "user.email", "test@example.com"},
		{"git", "config", "user.name", "Test User"},
		{"git", "config", "commit.gpgsign", "false"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run %v: %v", args, err)
		}
	}

	return tmpDir
}

func addFileAndCommit(t *testing.T, repoDir, path, content, message string) {
	t.Helper()
	fullPath := filepath.Join(repoDir, path)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	gitCmd := exec.Command("git", "add", path)
	gitCmd.Dir = repoDir
	if err := gitCmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}

	gitCmd = exec.Command("git", "commit", "-m", message)
	gitCmd.Dir = repoDir
	if err := gitCmd.Run(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}
}

func TestIndexerWithGemfile(t *testing.T) {
	repoDir := createTestRepo(t)

	gemfile1 := `source "https://rubygems.org"
gem "rails", "~> 7.0"
gem "puma"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile1, "Add Gemfile")

	gemfile2 := `source "https://rubygems.org"
gem "rails", "~> 7.1"
gem "puma"
gem "sidekiq"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile2, "Update rails, add sidekiq")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var output bytes.Buffer
	idx := indexer.New(repo, db, indexer.Options{
		Output: &output,
		Quiet:  false,
	})

	result, err := idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	if result.CommitsAnalyzed != 2 {
		t.Errorf("expected 2 commits analyzed, got %d", result.CommitsAnalyzed)
	}

	if result.CommitsWithChanges != 2 {
		t.Errorf("expected 2 commits with changes, got %d", result.CommitsWithChanges)
	}

	if result.TotalChanges != 4 {
		t.Errorf("expected 4 total changes, got %d", result.TotalChanges)
	}

	// Verify database contents
	var branchCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM branches").Scan(&branchCount); err != nil {
		t.Fatalf("failed to count branches: %v", err)
	}
	if branchCount != 1 {
		t.Errorf("expected 1 branch, got %d", branchCount)
	}

	var commitCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM commits").Scan(&commitCount); err != nil {
		t.Fatalf("failed to count commits: %v", err)
	}
	if commitCount != 2 {
		t.Errorf("expected 2 commits, got %d", commitCount)
	}

	var changeCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dependency_changes").Scan(&changeCount); err != nil {
		t.Fatalf("failed to count changes: %v", err)
	}
	if changeCount != 4 {
		t.Errorf("expected 4 changes, got %d", changeCount)
	}
}

func TestIndexerWithPackageJSON(t *testing.T) {
	repoDir := createTestRepo(t)

	pkgJSON := `{
  "name": "test-app",
  "dependencies": {
    "lodash": "^4.0.0",
    "express": "^4.18.0"
  }
}
`
	addFileAndCommit(t, repoDir, "package.json", pkgJSON, "Add package.json")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{Quiet: true})

	result, err := idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	if result.TotalChanges != 2 {
		t.Errorf("expected 2 total changes (lodash and express), got %d", result.TotalChanges)
	}
}

func TestIndexerWithNoManifests(t *testing.T) {
	repoDir := createTestRepo(t)

	addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{Quiet: true})

	result, err := idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	if result.CommitsAnalyzed != 1 {
		t.Errorf("expected 1 commit analyzed, got %d", result.CommitsAnalyzed)
	}

	if result.CommitsWithChanges != 0 {
		t.Errorf("expected 0 commits with changes, got %d", result.CommitsWithChanges)
	}
}

func TestIndexerWithRemovedDependency(t *testing.T) {
	repoDir := createTestRepo(t)

	gemfile1 := `source "https://rubygems.org"
gem "rails"
gem "puma"
gem "sidekiq"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile1, "Add Gemfile")

	gemfile2 := `source "https://rubygems.org"
gem "rails"
gem "puma"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile2, "Remove sidekiq")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{Quiet: true})

	result, err := idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	// First commit: 3 adds, second commit: 1 remove
	if result.TotalChanges != 4 {
		t.Errorf("expected 4 total changes, got %d", result.TotalChanges)
	}

	// Verify we have a removed change
	var removedCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dependency_changes WHERE change_type = 'removed'").Scan(&removedCount); err != nil {
		t.Fatalf("failed to count removed: %v", err)
	}
	if removedCount != 1 {
		t.Errorf("expected 1 removed change, got %d", removedCount)
	}
}

func TestIndexerWithBranchOption(t *testing.T) {
	repoDir := createTestRepo(t)

	addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{
		Branch: "main",
		Quiet:  true,
	})

	_, err = idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	var branchName string
	if err := db.QueryRow("SELECT name FROM branches LIMIT 1").Scan(&branchName); err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}
	if branchName != "main" {
		t.Errorf("expected branch 'main', got %q", branchName)
	}
}

func TestIndexerStoresSnapshots(t *testing.T) {
	repoDir := createTestRepo(t)

	gemfile := `source "https://rubygems.org"
gem "rails", "~> 7.0"
gem "puma"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile, "Add Gemfile")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{Quiet: true})

	_, err = idx.Run()
	if err != nil {
		t.Fatalf("indexer failed: %v", err)
	}

	var snapshotCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dependency_snapshots").Scan(&snapshotCount); err != nil {
		t.Fatalf("failed to count snapshots: %v", err)
	}
	if snapshotCount != 2 {
		t.Errorf("expected 2 snapshots (rails and puma), got %d", snapshotCount)
	}
}
