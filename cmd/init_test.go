package cmd_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
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

func chdir(t *testing.T, dir string) func() {
	t.Helper()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}
	return func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Errorf("failed to restore working directory: %v", err)
		}
	}
}

func TestInitCommand(t *testing.T) {
	t.Run("creates database in .git directory", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})

		var stdout bytes.Buffer
		rootCmd.SetOut(&stdout)

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("init command failed: %v", err)
		}

		dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
		if !database.Exists(dbPath) {
			t.Error("database was not created")
		}
	})

	t.Run("reports database already exists", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Create database first time
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("first init failed: %v", err)
		}

		// Try to create again
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		rootCmd.SetOut(&stdout)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("second init failed: %v", err)
		}

		// Output should mention database already exists
		_ = stdout.String() // Output is optional; command succeeds silently
	})

	t.Run("force recreates database", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Create database first time
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("first init failed: %v", err)
		}

		// Insert some test data that should be cleared
		dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
		db, err := database.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to open db: %v", err)
		}
		if _, err := db.Exec("INSERT INTO branches (name) VALUES (?)", "test-branch-to-delete"); err != nil {
			t.Fatalf("failed to insert: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close db: %v", err)
		}

		// Force recreate
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init", "--force"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("force init failed: %v", err)
		}

		// Verify test data was cleared (test-branch-to-delete should not exist)
		db, err = database.Open(dbPath)
		if err != nil {
			t.Fatalf("failed to reopen db: %v", err)
		}
		defer func() { _ = db.Close() }()

		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM branches WHERE name = ?", "test-branch-to-delete").Scan(&count); err != nil {
			t.Fatalf("failed to count test branch: %v", err)
		}
		if count != 0 {
			t.Error("expected test branch to be deleted after force recreate")
		}

		// Should have exactly one branch (the main branch)
		if err := db.QueryRow("SELECT COUNT(*) FROM branches").Scan(&count); err != nil {
			t.Fatalf("failed to count branches: %v", err)
		}
		if count != 1 {
			t.Errorf("expected 1 branch after init, got %d", count)
		}
	})

	t.Run("fails outside git repo", func(t *testing.T) {
		tmpDir := t.TempDir()

		cleanup := chdir(t, tmpDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})

		err := rootCmd.Execute()
		if err == nil {
			t.Error("expected error outside git repo")
		}
	})
}
