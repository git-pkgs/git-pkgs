package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestBisectCommand(t *testing.T) {
	t.Run("start requires git repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		cleanup := chdir(t, tmpDir)
		defer cleanup()

		_, _, err := runCmd(t, "bisect", "start")
		if err == nil {
			t.Error("expected error outside git repo")
		}
	})

	t.Run("start requires database", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "bisect", "start")
		if err == nil {
			t.Error("expected error without database")
		}
		if !strings.Contains(err.Error(), "init") {
			t.Errorf("error should mention init, got: %v", err)
		}
	})

	t.Run("start creates state files", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		stdout, _, err := runCmd(t, "bisect", "start")
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		if !strings.Contains(stdout, "Bisect session started") {
			t.Errorf("expected success message, got: %s", stdout)
		}

		// State file should exist
		statePath := filepath.Join(repoDir, ".git", "PKGS_BISECT_STATE")
		if _, err := os.Stat(statePath); os.IsNotExist(err) {
			t.Error("state file not created")
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("start with bad and good commits", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Get HEAD and first commit
		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")

		stdout, _, err := runCmd(t, "bisect", "start", headSHA[:7], firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// Should show bisecting message
		if !strings.Contains(stdout, "Bisecting") {
			t.Errorf("expected bisecting message, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("reset restores HEAD", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		originalHead := getGitSHA(t, repoDir, "HEAD")

		// Start bisect
		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")
		_, _, err := runCmd(t, "bisect", "start", headSHA[:7], firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// HEAD may have changed (checked out a middle commit)
		// It could also be the same if the middle commit is HEAD
		_ = getGitSHA(t, repoDir, "HEAD")

		// Reset
		_, _, err = runCmd(t, "bisect", "reset")
		if err != nil {
			t.Fatalf("bisect reset failed: %v", err)
		}

		// HEAD should be restored
		restoredHead := getGitSHA(t, repoDir, "HEAD")
		if restoredHead != originalHead {
			t.Errorf("HEAD not restored: expected %s, got %s", originalHead[:7], restoredHead[:7])
		}

		// State file should be gone
		statePath := filepath.Join(repoDir, ".git", "PKGS_BISECT_STATE")
		if _, err := os.Stat(statePath); !os.IsNotExist(err) {
			t.Error("state file should be deleted after reset")
		}
	})

	t.Run("good and bad mark commits", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Start bisect without specifying commits
		_, _, err := runCmd(t, "bisect", "start")
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// Mark bad
		stdout, _, err := runCmd(t, "bisect", "bad")
		if err != nil {
			t.Fatalf("bisect bad failed: %v", err)
		}
		if !strings.Contains(stdout, "Marked") && !strings.Contains(stdout, "bad") {
			t.Errorf("expected marked message, got: %s", stdout)
		}

		// Mark good
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")
		stdout, _, err = runCmd(t, "bisect", "good", firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect good failed: %v", err)
		}
		if !strings.Contains(stdout, "Marked") || !strings.Contains(stdout, "good") {
			t.Errorf("expected marked message, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("log shows history", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Start bisect
		_, _, _ = runCmd(t, "bisect", "start")
		_, _, _ = runCmd(t, "bisect", "bad")

		// Check log
		stdout, _, err := runCmd(t, "bisect", "log")
		if err != nil {
			t.Fatalf("bisect log failed: %v", err)
		}

		if !strings.Contains(stdout, "bisect") {
			t.Errorf("log should contain bisect commands, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("skip marks commit as skipped", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, _ = runCmd(t, "bisect", "start")

		stdout, _, err := runCmd(t, "bisect", "skip")
		if err != nil {
			t.Fatalf("bisect skip failed: %v", err)
		}

		if !strings.Contains(stdout, "Skipped") {
			t.Errorf("expected skipped message, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("start fails if already in progress", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Start first bisect
		_, _, err := runCmd(t, "bisect", "start")
		if err != nil {
			t.Fatalf("first bisect start failed: %v", err)
		}

		// Try to start again
		_, _, err = runCmd(t, "bisect", "start")
		if err == nil {
			t.Error("expected error when starting bisect twice")
		}
		if !strings.Contains(err.Error(), "already in progress") {
			t.Errorf("error should mention already in progress, got: %v", err)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("ecosystem filter", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		stdout, _, err := runCmd(t, "bisect", "start", "--ecosystem=npm")
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		if !strings.Contains(stdout, "ecosystem") && !strings.Contains(stdout, "npm") {
			t.Errorf("expected ecosystem filter message, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("reset when no bisect in progress", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		stdout, _, err := runCmd(t, "bisect", "reset")
		if err != nil {
			t.Fatalf("bisect reset failed: %v", err)
		}

		if !strings.Contains(stdout, "No bisect in progress") {
			t.Errorf("expected no bisect message, got: %s", stdout)
		}
	})
}

func TestBisectRun(t *testing.T) {
	t.Run("run requires bad and good commits", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, _ = runCmd(t, "bisect", "start")

		_, _, err := runCmd(t, "bisect", "run", "true")
		if err == nil {
			t.Error("expected error without bad/good commits")
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("run with always-good script finds first commit", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")

		_, _, err := runCmd(t, "bisect", "start", headSHA[:7], firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// Run with script that always returns good (exit 0)
		stdout, _, err := runCmd(t, "bisect", "run", "true")
		if err != nil {
			t.Fatalf("bisect run failed: %v", err)
		}

		// Should find the bad commit (HEAD since everything else is good)
		if !strings.Contains(stdout, "first bad commit") {
			t.Errorf("expected to find first bad commit, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})

	t.Run("run with always-bad script finds good boundary", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")

		_, _, err := runCmd(t, "bisect", "start", headSHA[:7], firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// Run with script that always returns bad (exit 1)
		stdout, _, err := runCmd(t, "bisect", "run", "false")
		if err != nil {
			t.Fatalf("bisect run failed: %v", err)
		}

		// Should find the first commit after good as the bad one
		if !strings.Contains(stdout, "first bad commit") {
			t.Errorf("expected to find first bad commit, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})
}

// createBisectTestRepo creates a repo with multiple commits that have dependency changes
func createBisectTestRepo(t *testing.T) string {
	t.Helper()
	repoDir := createTestRepo(t)

	// Commit 1: Initial package.json
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.0"
  }
}`, "Initial commit with lodash")

	// Commit 2: Add another dependency
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.0",
    "express": "4.18.0"
  }
}`, "Add express")

	// Commit 3: Update lodash
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.0"
  }
}`, "Update lodash")

	// Commit 4: Add axios
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.0",
    "axios": "1.0.0"
  }
}`, "Add axios")

	// Initialize git-pkgs database
	cleanup := chdir(t, repoDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"init", "--no-hooks"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("failed to init git-pkgs: %v", err)
	}

	return repoDir
}

func getGitSHA(t *testing.T, repoDir, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", ref)
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get SHA for %s: %v", ref, err)
	}
	return strings.TrimSpace(string(output))
}

// TestBisectDatabaseQueries tests the database queries used by bisect
func TestBisectDatabaseQueries(t *testing.T) {
	t.Run("GetBisectCandidates returns commits with changes", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
		db, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer func() { _ = db.Close() }()

		branchInfo, err := db.GetDefaultBranch()
		if err != nil {
			t.Fatalf("failed to get branch: %v", err)
		}

		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")

		candidates, err := db.GetBisectCandidates(database.BisectOptions{
			BranchID: branchInfo.ID,
			StartSHA: firstSHA,
			EndSHA:   headSHA,
		})
		if err != nil {
			t.Fatalf("GetBisectCandidates failed: %v", err)
		}

		// Should have 3 candidates (commits 2, 3, 4 - all have dep changes)
		if len(candidates) < 1 {
			t.Errorf("expected at least 1 candidate, got %d", len(candidates))
		}

		// Candidates should be ordered by position (oldest to newest)
		for i := 1; i < len(candidates); i++ {
			if candidates[i].Position < candidates[i-1].Position {
				t.Error("candidates should be ordered by position ascending")
			}
		}
	})

	t.Run("GetBisectCandidates filters by ecosystem", func(t *testing.T) {
		repoDir := createBisectTestRepo(t)
		cleanup := chdir(t, repoDir)
		defer cleanup()

		dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
		db, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to open database: %v", err)
		}
		defer func() { _ = db.Close() }()

		branchInfo, err := db.GetDefaultBranch()
		if err != nil {
			t.Fatalf("failed to get branch: %v", err)
		}

		headSHA := getGitSHA(t, repoDir, "HEAD")
		firstSHA := getGitSHA(t, repoDir, "HEAD~3")

		// Filter by npm (should find commits)
		candidates, err := db.GetBisectCandidates(database.BisectOptions{
			BranchID:  branchInfo.ID,
			StartSHA:  firstSHA,
			EndSHA:    headSHA,
			Ecosystem: "npm",
		})
		if err != nil {
			t.Fatalf("GetBisectCandidates failed: %v", err)
		}

		if len(candidates) < 1 {
			t.Errorf("expected npm candidates, got %d", len(candidates))
		}

		// Filter by nonexistent ecosystem (should find nothing)
		candidates, err = db.GetBisectCandidates(database.BisectOptions{
			BranchID:  branchInfo.ID,
			StartSHA:  firstSHA,
			EndSHA:    headSHA,
			Ecosystem: "rubygems",
		})
		if err != nil {
			t.Fatalf("GetBisectCandidates failed: %v", err)
		}

		if len(candidates) != 0 {
			t.Errorf("expected no rubygems candidates, got %d", len(candidates))
		}
	})

	t.Run("printCulprit resolves author via mailmap", func(t *testing.T) {
		repoDir := createTestRepo(t)

		// Create .mailmap file first
		mailmapContent := `Canonical Author <canonical@example.com> <test@example.com>
`
		addFileAndCommit(t, repoDir, ".mailmap", mailmapContent, "Add mailmap")

		// Now create commits with dependency changes
		addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.0"
  }
}`, "Initial commit with lodash")

		addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.0",
    "express": "4.18.0"
  }
}`, "Add express")

		addFileAndCommit(t, repoDir, "package.json", `{
  "name": "test-project",
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.0"
  }
}`, "Update lodash")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Initialize git-pkgs database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init", "--no-hooks"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("failed to init git-pkgs: %v", err)
		}

		// Start bisect with first and last dependency commit
		firstSHA := getGitSHA(t, repoDir, "HEAD~2") // First dep commit
		headSHA := getGitSHA(t, repoDir, "HEAD")

		_, _, err := runCmd(t, "bisect", "start", headSHA[:7], firstSHA[:7])
		if err != nil {
			t.Fatalf("bisect start failed: %v", err)
		}

		// Mark everything as bad to force finding the first commit
		stdout, _, err := runCmd(t, "bisect", "run", "false")
		if err != nil {
			t.Fatalf("bisect run failed: %v", err)
		}

		// Check that the output contains the canonical author name from .mailmap
		if !strings.Contains(stdout, "Canonical Author") {
			t.Errorf("expected canonical author name from mailmap, got: %s", stdout)
		}
		if !strings.Contains(stdout, "canonical@example.com") {
			t.Errorf("expected canonical email from mailmap, got: %s", stdout)
		}

		// Clean up
		_, _, _ = runCmd(t, "bisect", "reset")
	})
}
