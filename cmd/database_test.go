package cmd_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestBranchCommand(t *testing.T) {
	t.Run("lists tracked branches", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Init database
		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// List branches
		stdout, _, err := runCmd(t, "branch", "list")
		if err != nil {
			t.Fatalf("branch list failed: %v", err)
		}

		if !strings.Contains(stdout, "main") {
			t.Errorf("expected 'main' in branch list, got: %s", stdout)
		}
		if !strings.Contains(stdout, "Tracked branches") {
			t.Errorf("expected 'Tracked branches' header, got: %s", stdout)
		}
	})

	t.Run("branch command without subcommand lists branches", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "branch")
		if err != nil {
			t.Fatalf("branch failed: %v", err)
		}

		if !strings.Contains(stdout, "main") {
			t.Errorf("expected 'main' in output, got: %s", stdout)
		}
	})

	t.Run("adds new branch", func(t *testing.T) {
		repoDir := createTestRepo(t)

		// Create initial commit on main
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		// Create orphan feature branch with completely separate history
		gitCmd := exec.Command("git", "checkout", "--orphan", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create orphan branch: %v", err)
		}

		// Clean staging area
		gitCmd = exec.Command("git", "rm", "-rf", "--cached", ".")
		gitCmd.Dir = repoDir
		_ = gitCmd.Run() // Ignore error if no files

		// Add different commit on feature branch
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"axios":"^1.0.0"}}`, "Add axios")

		// Switch back to main
		gitCmd = exec.Command("git", "checkout", "main")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout main: %v", err)
		}

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Add feature branch
		stdout, _, err := runCmd(t, "branch", "add", "feature")
		if err != nil {
			t.Fatalf("branch add failed: %v", err)
		}

		if !strings.Contains(stdout, "feature") {
			t.Errorf("expected 'feature' in output, got: %s", stdout)
		}

		// Verify branch is listed
		stdout, _, err = runCmd(t, "branch", "list")
		if err != nil {
			t.Fatalf("branch list failed: %v", err)
		}

		if !strings.Contains(stdout, "main") || !strings.Contains(stdout, "feature") {
			t.Errorf("expected both branches in list, got: %s", stdout)
		}
	})

	t.Run("removes branch", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		// Create orphan feature branch with separate history
		gitCmd := exec.Command("git", "checkout", "--orphan", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create orphan branch: %v", err)
		}

		gitCmd = exec.Command("git", "rm", "-rf", "--cached", ".")
		gitCmd.Dir = repoDir
		_ = gitCmd.Run()

		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"axios":"^1.0.0"}}`, "Add axios")

		gitCmd = exec.Command("git", "checkout", "main")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout main: %v", err)
		}

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Add then remove
		_, _, err = runCmd(t, "branch", "add", "feature")
		if err != nil {
			t.Fatalf("branch add failed: %v", err)
		}

		stdout, _, err := runCmd(t, "branch", "remove", "feature")
		if err != nil {
			t.Fatalf("branch remove failed: %v", err)
		}

		if !strings.Contains(stdout, "Removed") {
			t.Errorf("expected 'Removed' message, got: %s", stdout)
		}

		// Verify branch is gone
		stdout, _, err = runCmd(t, "branch", "list")
		if err != nil {
			t.Fatalf("branch list failed: %v", err)
		}

		if strings.Contains(stdout, "feature") {
			t.Errorf("feature should be removed, got: %s", stdout)
		}
	})

	t.Run("add fails for non-existent branch", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		_, _, err = runCmd(t, "branch", "add", "nonexistent")
		if err == nil {
			t.Error("expected error for non-existent branch")
		}
	})
}

func TestInfoCommand(t *testing.T) {
	t.Run("shows database info", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "info")
		if err != nil {
			t.Fatalf("info failed: %v", err)
		}

		if !strings.Contains(stdout, "Database Info") {
			t.Errorf("expected 'Database Info' header, got: %s", stdout)
		}
		if !strings.Contains(stdout, "Schema version") {
			t.Errorf("expected 'Schema version' in output, got: %s", stdout)
		}
		if !strings.Contains(stdout, "Branch") {
			t.Errorf("expected 'Branch' in output, got: %s", stdout)
		}
	})

	t.Run("shows ecosystems flag", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "info", "--ecosystems")
		if err != nil {
			t.Fatalf("info --ecosystems failed: %v", err)
		}

		if !strings.Contains(stdout, "npm") {
			t.Errorf("expected 'npm' ecosystem, got: %s", stdout)
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "info", "-f", "json")
		if err != nil {
			t.Fatalf("info json failed: %v", err)
		}

		var info map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &info); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if _, ok := info["schema_version"]; !ok {
			t.Error("expected 'schema_version' in JSON")
		}
		if _, ok := info["row_counts"]; !ok {
			t.Error("expected 'row_counts' in JSON")
		}
	})
}

func TestSchemaCommand(t *testing.T) {
	t.Run("shows database schema", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "schema")
		if err != nil {
			t.Fatalf("schema failed: %v", err)
		}

		// Should show table names
		tables := []string{"branches", "commits", "manifests", "dependency_changes", "dependency_snapshots"}
		for _, table := range tables {
			if !strings.Contains(stdout, table) {
				t.Errorf("expected table '%s' in schema, got: %s", table, stdout)
			}
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "schema", "-f", "json")
		if err != nil {
			t.Fatalf("schema json failed: %v", err)
		}

		var tables []map[string]interface{}
		if err := json.Unmarshal([]byte(stdout), &tables); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if len(tables) == 0 {
			t.Error("expected tables in schema JSON")
		}

		// Check structure
		found := false
		for _, table := range tables {
			if name, _ := table["name"].(string); name == "commits" {
				found = true
				if _, ok := table["columns"]; !ok {
					t.Error("expected 'columns' in table schema")
				}
				break
			}
		}
		if !found {
			t.Error("expected 'commits' table in schema")
		}
	})

	t.Run("outputs sql format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "schema", "-f", "sql")
		if err != nil {
			t.Fatalf("schema sql failed: %v", err)
		}

		if !strings.Contains(stdout, "CREATE TABLE") {
			t.Errorf("expected CREATE TABLE statements, got: %s", stdout)
		}
	})

	t.Run("outputs markdown format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		stdout, _, err := runCmd(t, "schema", "-f", "markdown")
		if err != nil {
			t.Fatalf("schema markdown failed: %v", err)
		}

		if !strings.Contains(stdout, "# Database Schema") {
			t.Errorf("expected markdown header, got: %s", stdout)
		}
		if !strings.Contains(stdout, "| Column |") {
			t.Errorf("expected markdown table, got: %s", stdout)
		}
	})
}

func TestReindexCommand(t *testing.T) {
	t.Run("reports already up to date", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Reindex without any new commits
		stdout, _, err := runCmd(t, "reindex")
		if err != nil {
			t.Fatalf("reindex failed: %v", err)
		}

		if !strings.Contains(stdout, "Already up to date") {
			t.Errorf("expected 'Already up to date' message, got: %s", stdout)
		}
	})

	t.Run("indexes new commits", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "init")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Add new commit
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"express":"^5.0.0"}}`, "Update express")

		// Reindex
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"reindex"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("reindex failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "Analyzed") && !strings.Contains(output, "1") {
			t.Errorf("expected reindex to report new commits, got: %s", output)
		}
	})

	t.Run("fails without database", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "reindex")
		if err == nil {
			t.Error("expected error without database")
		}
		if !strings.Contains(err.Error(), "database not found") {
			t.Errorf("expected 'database not found' error, got: %v", err)
		}
	})
}
