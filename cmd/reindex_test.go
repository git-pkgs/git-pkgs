package cmd_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReindex(t *testing.T) {
	t.Run("reindexes a tracked branch", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.21\n", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Add a new commit after init
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n", "Bump go version")

		stdout, _, err := runCmd(t, "reindex")
		if err != nil {
			t.Fatalf("reindex failed: %v", err)
		}

		if !strings.Contains(stdout, "new commits") && !strings.Contains(stdout, "up to date") {
			t.Errorf("unexpected output: %s", stdout)
		}
	})

	t.Run("reindexes all tracked branches", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.21\n", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Create a feature branch and add a commit with dependency changes
		gitCmd := exec.Command("git", "checkout", "-b", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.0\n", "Add dependency on feature")

		// Track the feature branch
		_, _, err = runCmd(t, "branch", "add", "feature")
		if err != nil {
			t.Fatalf("branch add failed: %v", err)
		}

		// Go back to main and add a commit
		gitCmd = exec.Command("git", "checkout", "main")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout main: %v", err)
		}
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n", "Bump go on main")

		// Add another commit on feature
		gitCmd = exec.Command("git", "checkout", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout feature: %v", err)
		}
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n\nrequire golang.org/x/text v0.4.0\n", "Update dependency on feature")

		// Reindex without -b should update both branches
		stdout, _, err := runCmd(t, "reindex")
		if err != nil {
			t.Fatalf("reindex failed: %v", err)
		}

		if !strings.Contains(stdout, "feature") {
			t.Errorf("expected output to mention feature branch, got: %s", stdout)
		}
		if !strings.Contains(stdout, "main") {
			t.Errorf("expected output to mention main branch, got: %s", stdout)
		}
	})

	t.Run("reindexes single branch with -b flag", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.21\n", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Create feature branch and track it
		gitCmd := exec.Command("git", "checkout", "-b", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n", "Change on feature")

		_, _, err = runCmd(t, "branch", "add", "feature")
		if err != nil {
			t.Fatalf("branch add failed: %v", err)
		}

		// Add another commit on feature
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.23\n", "Another change on feature")

		// Add a commit on main too
		gitCmd = exec.Command("git", "checkout", "main")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout main: %v", err)
		}
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.22\n", "Change on main")

		// Reindex only feature branch
		stdout, _, err := runCmd(t, "reindex", "-b", "feature")
		if err != nil {
			t.Fatalf("reindex -b feature failed: %v", err)
		}

		if !strings.Contains(stdout, "feature") {
			t.Errorf("expected output to mention feature, got: %s", stdout)
		}
		// main should not have been updated
		if strings.Contains(stdout, "main") {
			t.Errorf("expected output to NOT mention main, got: %s", stdout)
		}
	})

	t.Run("auto-adds untracked branch with -b flag", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "go.mod", "module example.com/test\n\ngo 1.21\n", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Create an orphan branch so it has no shared commits with main
		gitCmd := exec.Command("git", "checkout", "--orphan", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}
		// Remove staged files from main
		gitCmd = exec.Command("git", "rm", "-rf", ".")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to clean staged files: %v", err)
		}
		addFileAndCommit(t, repoDir, "new.txt", "hello", "Add file on feature branch")

		stdout, _, err := runCmd(t, "reindex", "-b", "feature")
		if err != nil {
			t.Fatalf("reindex with -b failed: %v", err)
		}

		if !strings.Contains(stdout, "Added branch") {
			t.Errorf("expected output to indicate branch was added, got: %s", stdout)
		}

		// Verify branch is now tracked
		stdout, _, err = runCmd(t, "branch", "list")
		if err != nil {
			t.Fatalf("branch list failed: %v", err)
		}
		if !strings.Contains(stdout, "feature") {
			t.Errorf("expected feature branch to be tracked, got: %s", stdout)
		}
	})

	t.Run("fails without init", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "reindex")
		if err == nil {
			t.Fatal("expected error without init")
		}

		if !strings.Contains(err.Error(), "init") {
			t.Errorf("expected error to mention init, got: %v", err)
		}
	})
}
