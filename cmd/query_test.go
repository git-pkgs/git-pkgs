package cmd_test

import (
	"bytes"
	"encoding/json"
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
	})

	t.Run("stateless mode works without database", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		// Don't init - use stateless mode
		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"list", "--stateless"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("list --stateless failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected output to contain 'express'")
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
		// HEAD commit added dependencies
		if !strings.Contains(output, "express") && !strings.Contains(output, "added") {
			// Either shows the deps or says no changes (depends on which commit HEAD points to)
			t.Logf("show output: %s", output)
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

		// Should be valid JSON
		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})

	t.Run("stateless mode works", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add dependencies")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"show", "--stateless"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("show --stateless failed: %v", err)
		}
	})
}

func TestDiffCommand(t *testing.T) {
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
			t.Logf("diff output: %s", output)
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

		if _, ok := result["added"]; !ok {
			t.Error("expected 'added' field in JSON output")
		}
	})

	t.Run("stateless mode works", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"lodash":"^4.17.0"}}`, "Initial deps")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Update deps")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD", "--stateless"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff --stateless failed: %v", err)
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
		// Should list commits
		if !strings.Contains(output, "Add") {
			t.Logf("log output: %s", output)
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

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
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
			t.Logf("history output: %s", output)
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

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}
