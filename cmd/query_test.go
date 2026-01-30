package cmd_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

// Sample package.json content
const packageJSON = `{
  "name": "test-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
`

// Sample package-lock.json content
const packageLockJSON = `{
  "name": "test-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-app",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.0",
        "lodash": "^4.17.21"
      },
      "devDependencies": {
        "jest": "^29.0.0"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
    },
    "node_modules/jest": {
      "version": "29.7.0",
      "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz",
      "integrity": "sha512-NIy3oAFp9shda19ez4HgzXfkzNkFXGj2V8m5xk6xWe/5ESrq7+IzhPRXbqAIEr5E0F5FDp8w1DQFV8+SqGbNwg==",
      "dev": true
    }
  }
}
`

func TestListCommand(t *testing.T) {
	t.Run("lists dependencies from database", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add package-lock.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Initialize database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Run list command
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list failed: %v", err)
		}

		output := stdout.String()

		// Should contain our dependencies
		if !strings.Contains(output, "express") {
			t.Error("expected output to contain 'express'")
		}
		if !strings.Contains(output, "lodash") {
			t.Error("expected output to contain 'lodash'")
		}
	})

	t.Run("filters by ecosystem", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list", "--ecosystem", "npm"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected npm packages in output")
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list failed: %v", err)
		}

		var deps []map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &deps); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(deps) == 0 {
			t.Error("expected at least one dependency in JSON output")
		}

		// Validate structure of first dependency
		first := deps[0]
		if _, ok := first["name"]; !ok {
			t.Error("expected 'name' field in dependency JSON")
		}
		if _, ok := first["requirement"]; !ok {
			t.Error("expected 'requirement' field in dependency JSON")
		}

		// Check that express or lodash is in the list
		foundExpected := false
		for _, dep := range deps {
			name, _ := dep["name"].(string)
			if name == "express" || name == "lodash" {
				foundExpected = true
				break
			}
		}
		if !foundExpected {
			t.Error("expected 'express' or 'lodash' in JSON output")
		}
	})

	t.Run("on-demand indexing without init", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Don't init - should create database on demand
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list with on-demand indexing failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected output to contain 'express'")
		}
	})

	t.Run("on-demand indexing with manifest and lockfile", func(t *testing.T) {
		repoDir := createTestRepo(t)
		// Add both package.json and package-lock.json which have overlapping dependencies
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add package-lock.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Don't init - should create database on demand
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list with on-demand indexing failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected output to contain 'express'")
		}
		if !strings.Contains(output, "lodash") {
			t.Error("expected output to contain 'lodash'")
		}

		// Verify database was created
		if _, err := os.Stat(filepath.Join(repoDir, ".git", "pkgs.sqlite3")); os.IsNotExist(err) {
			t.Error("expected database to be created on demand")
		}
	})
}

func TestShowCommand(t *testing.T) {
	t.Run("shows changes in commit", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add dependencies")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"show"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("show failed: %v", err)
		}

		output := stdout.String()
		// HEAD commit added dependencies, should show express as added
		if !strings.Contains(output, "express") {
			t.Errorf("expected 'express' in show output, got: %s", output)
		}
		if !strings.Contains(output, "added") && !strings.Contains(output, "Added") && !strings.Contains(output, "+") {
			t.Errorf("expected addition indicator in show output, got: %s", output)
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add dependencies")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"show", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("show failed: %v", err)
		}

		// Should be valid JSON array of changes
		var result []map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(result) == 0 {
			t.Error("expected at least one change in show JSON")
		}

		// Validate structure of changes
		first := result[0]
		if _, ok := first["name"]; !ok {
			t.Error("expected 'name' field in show JSON")
		}
		if _, ok := first["change_type"]; !ok {
			t.Error("expected 'change_type' field in show JSON")
		}
	})

	t.Run("on-demand indexing without init", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add dependencies")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Don't init - should create database on demand
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"show"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("show with on-demand indexing failed: %v", err)
		}
	})
}

func writeFile(t *testing.T, repoDir, path, content string) {
	t.Helper()
	fullPath := filepath.Join(repoDir, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}
}

func TestDiffCommand(t *testing.T) {
	t.Run("clean working tree shows no changes", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps")
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Initialize database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Run diff with no args (HEAD vs working tree) - working tree is clean
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "No dependency changes") {
			t.Errorf("expected 'No dependency changes' for clean working tree, got: %s", output)
		}
	})

	t.Run("clean working tree with github actions shows no changes", func(t *testing.T) {
		repoDir := createTestRepo(t)

		workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
`
		addFileAndCommit(t, repoDir, ".github/workflows/ci.yml", workflow, "Add workflow")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Initialize database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Run diff with no args - working tree is clean
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "No dependency changes") {
			t.Errorf("expected 'No dependency changes' for clean working tree with actions, got: %s", output)
		}
	})

	t.Run("no args shows working tree changes", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Modify the file without committing
		writeFile(t, repoDir, "package.json", packageJSON)

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Errorf("expected 'express' in diff output, got: %s", output)
		}
	})

	t.Run("explicit range still works", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Update deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Errorf("expected 'express' in diff output, got: %s", output)
		}
	})

	t.Run("shows diff between commits", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Update deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		// Should show express was added
		if !strings.Contains(output, "express") {
			t.Errorf("expected 'express' in diff output, got: %s", output)
		}
		// Should indicate it was added
		if !strings.Contains(output, "added") && !strings.Contains(output, "Added") && !strings.Contains(output, "+") {
			t.Errorf("expected addition indicator in diff output, got: %s", output)
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Update deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		// Diff returns an object with added/removed/updated arrays (may be omitted if empty)
		if _, ok := result["added"]; !ok {
			t.Error("expected 'added' field in JSON output")
		}

		// Verify express is in the added list
		added, ok := result["added"].([]interface{})
		if !ok {
			t.Error("expected 'added' to be an array")
		} else {
			foundExpress := false
			for _, item := range added {
				if dep, ok := item.(map[string]interface{}); ok {
					if name, _ := dep["name"].(string); name == "express" {
						foundExpress = true
						break
					}
				}
			}
			if !foundExpress {
				t.Error("expected 'express' in added dependencies")
			}
		}
	})

	t.Run("on-demand indexing without init", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Update deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Don't init - should create database on demand
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff with on-demand indexing failed: %v", err)
		}
	})
}

func TestLogCommand(t *testing.T) {
	t.Run("shows commits with changes", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Add lodash")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add more deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"log"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("log failed: %v", err)
		}

		output := stdout.String()
		// Should list commits with dependency changes
		if !strings.Contains(output, "Add") {
			t.Errorf("expected commit message containing 'Add' in log output, got: %s", output)
		}
	})

	t.Run("respects limit flag", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"a":"1.0.0"}}`, "Commit 1")
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"b":"1.0.0"}}`, "Commit 2")
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"c":"1.0.0"}}`, "Commit 3")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"log", "--limit", "1", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("log failed: %v", err)
		}

		var commits []map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &commits); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}

		if len(commits) > 1 {
			t.Errorf("expected at most 1 commit, got %d", len(commits))
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"log", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("log failed: %v", err)
		}

		var commits []map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &commits); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(commits) == 0 {
			t.Error("expected at least one commit in JSON output")
		}

		// Validate commit structure
		first := commits[0]
		if _, ok := first["sha"]; !ok {
			t.Error("expected 'sha' field in commit JSON")
		}
		if _, ok := first["message"]; !ok {
			t.Error("expected 'message' field in commit JSON")
		}
	})
}

func TestHistoryCommand(t *testing.T) {
	t.Run("shows package history", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Add lodash")
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.21"}}`, "Update lodash")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"history", "lodash"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("history failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "lodash") {
			t.Errorf("expected 'lodash' in history output, got: %s", output)
		}
		// Should show both versions
		if !strings.Contains(output, "4.17.0") {
			t.Errorf("expected old version '4.17.0' in history output, got: %s", output)
		}
		if !strings.Contains(output, "4.17.21") {
			t.Errorf("expected new version '4.17.21' in history output, got: %s", output)
		}
	})

	t.Run("shows all history without package name", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"history"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("history failed: %v", err)
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"history", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("history failed: %v", err)
		}

		var result []map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(result) == 0 {
			t.Error("expected at least one history entry in JSON output")
		}

		// Validate structure
		first := result[0]
		if _, ok := first["name"]; !ok {
			t.Error("expected 'name' field in history JSON")
		}
		if _, ok := first["requirement"]; !ok {
			t.Error("expected 'requirement' field in history JSON")
		}
		if _, ok := first["change_type"]; !ok {
			t.Error("expected 'change_type' field in history JSON")
		}
	})
}

func TestBranchBehavior(t *testing.T) {
	t.Run("list works on feature branch", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps on main")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Create and switch to feature branch
		gitCmd := exec.Command("git", "checkout", "-b", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}

		// Add different deps on feature branch
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"axios":"^1.0.0"}}`, "Add axios on feature")

		// Initialize database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// List should show feature branch deps
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "axios") {
			t.Errorf("expected 'axios' from feature branch, got: %s", output)
		}
	})

	t.Run("branch flag queries specific branch", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps on main")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Create feature branch with different deps
		gitCmd := exec.Command("git", "checkout", "-b", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}

		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"axios":"^1.0.0"}}`, "Add axios")

		// Initialize database (will index current branch)
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Query current (feature) branch - should have axios
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "axios") {
			t.Errorf("expected 'axios' on feature branch, got: %s", output)
		}

		// Switch back to main and re-init to index main branch
		gitCmd = exec.Command("git", "checkout", "main")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to checkout main: %v", err)
		}

		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init", "--force"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init main failed: %v", err)
		}

		// Query main branch - should have express
		stdout.Reset()
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list main failed: %v", err)
		}

		output = stdout.String()
		if !strings.Contains(output, "express") {
			t.Errorf("expected 'express' on main branch, got: %s", output)
		}
	})

	t.Run("diff between branches", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add deps on main")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Create feature branch
		gitCmd := exec.Command("git", "checkout", "-b", "feature")
		gitCmd.Dir = repoDir
		if err := gitCmd.Run(); err != nil {
			t.Fatalf("failed to create branch: %v", err)
		}

		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"express":"^4.18.0","axios":"^1.0.0"}}`, "Add axios")

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Diff main..feature should show axios added
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "main..feature"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "axios") {
			t.Errorf("expected 'axios' in diff output, got: %s", output)
		}
	})
}
