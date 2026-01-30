package indexer_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func gitRun(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
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

func sampleGemfileLock(gems map[string]string) string {
	// Sort gem names for deterministic output
	var names []string
	for name := range gems {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[i] > names[j] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	lines := []string{
		"GEM",
		"  remote: https://rubygems.org/",
		"  specs:",
	}
	for _, name := range names {
		lines = append(lines, "    "+name+" ("+gems[name]+")")
	}
	lines = append(lines, "", "PLATFORMS", "  ruby", "", "DEPENDENCIES")
	for _, name := range names {
		lines = append(lines, "  "+name)
	}
	lines = append(lines, "", "BUNDLED WITH", "   2.5.0", "")
	return strings.Join(lines, "\n")
}

func TestSnapshotNoDuplicateVersions(t *testing.T) {
	repoDir := createTestRepo(t)

	// Commit 1: initial lockfile
	lock1 := sampleGemfileLock(map[string]string{
		"actioncable": "7.0.4",
		"rails":       "7.0.4",
		"puma":        "6.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock1, "Add lockfile")

	// Commit 2: update actioncable and rails
	lock2 := sampleGemfileLock(map[string]string{
		"actioncable": "7.1.0",
		"rails":       "7.1.0",
		"puma":        "6.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock2, "Update rails")

	// Commit 3: another update
	lock3 := sampleGemfileLock(map[string]string{
		"actioncable": "7.2.0",
		"rails":       "7.2.0",
		"puma":        "6.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock3, "Update rails again")

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

	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	deps, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		t.Fatalf("failed to get latest deps: %v", err)
	}

	// Count occurrences of each package name
	nameCounts := make(map[string][]string)
	for _, d := range deps {
		nameCounts[d.Name] = append(nameCounts[d.Name], d.Requirement)
	}

	for name, versions := range nameCounts {
		if len(versions) > 1 {
			t.Errorf("package %s appears %d times with versions %v, expected exactly 1",
				name, len(versions), versions)
		}
	}

	// Should have exactly 3 deps
	if len(deps) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(deps))
	}
}

func TestSnapshotNoDuplicatesAfterMerge(t *testing.T) {
	repoDir := createTestRepo(t)

	// Commit 1: initial lockfile on main
	lock1 := sampleGemfileLock(map[string]string{
		"actioncable": "5.0.1",
		"rails":       "5.0.1",
		"puma":        "3.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock1, "Add lockfile")

	// Create a feature branch and update the lockfile there
	gitRun(t, repoDir, "checkout", "-b", "feature")
	lock2 := sampleGemfileLock(map[string]string{
		"actioncable": "5.0.2",
		"rails":       "5.0.2",
		"puma":        "3.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock2, "Update rails on feature")

	// Go back to main and merge (creates a merge commit)
	gitRun(t, repoDir, "checkout", "main")
	gitRun(t, repoDir, "merge", "--no-ff", "feature", "-m", "Merge feature")

	// Now make another change on main (this will diff against the merge commit)
	lock3 := sampleGemfileLock(map[string]string{
		"actioncable": "5.1.0",
		"rails":       "5.1.0",
		"puma":        "3.0.0",
	})
	addFileAndCommit(t, repoDir, "Gemfile.lock", lock3, "Update to 5.1")

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

	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	deps, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		t.Fatalf("GetLatestDependencies failed: %v", err)
	}

	// Each package should appear exactly once (this is a Gemfile.lock)
	nameCounts := make(map[string][]string)
	for _, d := range deps {
		nameCounts[d.Name] = append(nameCounts[d.Name], d.Requirement)
	}

	for name, versions := range nameCounts {
		if len(versions) > 1 {
			t.Errorf("package %s appears %d times with versions %v, want 1",
				name, len(versions), versions)
		}
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(deps))
		for _, d := range deps {
			t.Logf("  %s %s", d.Name, d.Requirement)
		}
	}
}

func samplePackageLockJSON(deps map[string]string) string {
	var sb strings.Builder
	sb.WriteString("{\n  \"name\": \"test\",\n  \"version\": \"1.0.0\",\n  \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {\n")
	sb.WriteString("    \"\": {\n      \"name\": \"test\",\n      \"version\": \"1.0.0\"\n    }")
	for path, version := range deps {
		sb.WriteString(fmt.Sprintf(",\n    \"node_modules/%s\": {\n      \"version\": \"%s\"\n    }", path, version))
	}
	sb.WriteString("\n  }\n}\n")
	return sb.String()
}

func TestNpmMultipleVersionsSurviveModifiedLockfile(t *testing.T) {
	repoDir := createTestRepo(t)

	// npm can legitimately have multiple versions of the same package
	// in a single lockfile (nested node_modules). Verify these survive
	// when the lockfile is modified across a merge commit.
	lock1 := samplePackageLockJSON(map[string]string{
		"isexe":                      "3.1.1",
		"some-pkg/node_modules/isexe": "2.0.0",
		"lodash":                     "4.17.21",
	})
	addFileAndCommit(t, repoDir, "package-lock.json", lock1, "Add lockfile")

	// Feature branch: update lodash
	gitRun(t, repoDir, "checkout", "-b", "feature")
	lock2 := samplePackageLockJSON(map[string]string{
		"isexe":                      "3.1.1",
		"some-pkg/node_modules/isexe": "2.0.0",
		"lodash":                     "4.17.22",
	})
	addFileAndCommit(t, repoDir, "package-lock.json", lock2, "Update lodash")

	// Merge back to main
	gitRun(t, repoDir, "checkout", "main")
	gitRun(t, repoDir, "merge", "--no-ff", "feature", "-m", "Merge feature")

	// Another change on main
	lock3 := samplePackageLockJSON(map[string]string{
		"isexe":                      "3.1.1",
		"some-pkg/node_modules/isexe": "2.0.0",
		"lodash":                     "4.17.23",
	})
	addFileAndCommit(t, repoDir, "package-lock.json", lock3, "Update lodash again")

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

	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	deps, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		t.Fatalf("GetLatestDependencies failed: %v", err)
	}

	// Count isexe versions -- should still have both 3.1.1 and 2.0.0
	var isexeVersions []string
	for _, d := range deps {
		if d.Name == "isexe" {
			isexeVersions = append(isexeVersions, d.Requirement)
		}
	}

	if len(isexeVersions) != 2 {
		t.Errorf("expected 2 isexe versions (npm multi-version), got %d: %v",
			len(isexeVersions), isexeVersions)
	}

	// lodash should appear exactly once
	var lodashVersions []string
	for _, d := range deps {
		if d.Name == "lodash" {
			lodashVersions = append(lodashVersions, d.Requirement)
		}
	}

	if len(lodashVersions) != 1 {
		t.Errorf("expected 1 lodash version, got %d: %v",
			len(lodashVersions), lodashVersions)
	}
}

func TestStatsCurrentDepsNonZeroWhenLastCommitHasNoChanges(t *testing.T) {
	repoDir := createTestRepo(t)

	// Commit 1: add Gemfile (has dependency changes)
	addFileAndCommit(t, repoDir, "Gemfile", "source \"https://rubygems.org\"\ngem \"rails\", \"~> 7.0\"\ngem \"puma\"\n", "Add Gemfile")

	// Commit 2: non-manifest change (no dependency changes)
	addFileAndCommit(t, repoDir, "README.md", "# Hello", "Add readme")

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

	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("failed to get branch: %v", err)
	}

	stats, err := db.GetStats(database.StatsOptions{BranchID: branch.ID})
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats.CurrentDeps != 2 {
		t.Errorf("expected 2 current deps, got %d", stats.CurrentDeps)
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

func TestIndexerStoresSnapshotsAtTagsAndBranches(t *testing.T) {
	repoDir := createTestRepo(t)

	// Commit 1: add Gemfile
	gemfile1 := `source "https://rubygems.org"
gem "rails", "~> 7.0"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile1, "Add Gemfile")
	gitRun(t, repoDir, "tag", "v1.0.0")

	// Commit 2: update Gemfile
	gemfile2 := `source "https://rubygems.org"
gem "rails", "~> 7.1"
gem "puma"
`
	addFileAndCommit(t, repoDir, "Gemfile", gemfile2, "Update deps")

	// Commit 3: non-manifest change (no dep changes)
	addFileAndCommit(t, repoDir, "README.md", "# Test", "Add readme")
	gitRun(t, repoDir, "tag", "v1.1.0")

	// Create a feature branch at this point
	gitRun(t, repoDir, "checkout", "-b", "feature")
	addFileAndCommit(t, repoDir, "feature.txt", "feature", "Add feature file")

	// Go back to main
	gitRun(t, repoDir, "checkout", "main")

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

	// Count unique commits with snapshots
	var snapshotCommitCount int
	if err := db.QueryRow("SELECT COUNT(DISTINCT commit_id) FROM dependency_snapshots").Scan(&snapshotCommitCount); err != nil {
		t.Fatalf("failed to count snapshot commits: %v", err)
	}

	// We should have snapshots at:
	// 1. v1.0.0 tag (commit 1) - has dep changes
	// 2. commit 2 - has dep changes
	// 3. v1.1.0 tag (commit 3) - no dep changes but tagged, should still have snapshot
	// 4. main branch head (commit 3 in this case, same as v1.1.0)
	// So at least 3 distinct commits should have snapshots
	if snapshotCommitCount < 3 {
		t.Errorf("expected at least 3 commits with snapshots (tags and branch heads), got %d", snapshotCommitCount)
	}

	// Verify we have a snapshot at the tagged commit without dep changes (v1.1.0)
	// Get the SHA for v1.1.0
	cmd := exec.Command("git", "rev-parse", "v1.1.0")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get v1.1.0 SHA: %v", err)
	}
	v110SHA := strings.TrimSpace(string(out))

	var v110SnapshotCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM dependency_snapshots ds
		JOIN commits c ON c.id = ds.commit_id
		WHERE c.sha = ?
	`, v110SHA).Scan(&v110SnapshotCount); err != nil {
		t.Fatalf("failed to count v1.1.0 snapshots: %v", err)
	}

	if v110SnapshotCount != 2 {
		t.Errorf("expected 2 snapshots at v1.1.0 (rails and puma), got %d", v110SnapshotCount)
	}
}
