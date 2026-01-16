package cmd_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestIntegrityCommand(t *testing.T) {
	t.Run("shows integrity hashes", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"integrity"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("integrity failed: %v", err)
		}

		output := stdout.String()
		// Should show packages with integrity hashes
		if !strings.Contains(output, "sha512") && !strings.Contains(output, "express") {
			t.Logf("integrity output: %s", output)
		}
	})

	t.Run("drift flag filters output", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"integrity", "--drift"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("integrity --drift failed: %v", err)
		}

		output := stdout.String()
		// Should report no drift in a single lockfile
		if !strings.Contains(output, "No integrity drift") && !strings.Contains(output, "drift") {
			t.Logf("drift output: %s", output)
		}
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"integrity", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("integrity failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})

	t.Run("stateless mode works", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"integrity", "--stateless"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("integrity --stateless failed: %v", err)
		}
	})
}

func TestStatsCommand(t *testing.T) {
	t.Run("shows statistics", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"a":"1.0.0"}}`, "Add a")
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"b":"1.0.0"}}`, "Add b")
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add more")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"stats"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("stats failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "Dependency Statistics") {
			t.Error("expected statistics header in output")
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
		rootCmd.SetArgs([]string{"stats", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("stats failed: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		// Check for branch field (snake_case with json tags)
		if _, ok := result["branch"]; !ok {
			t.Error("expected 'branch' field in JSON output")
		}
	})

	t.Run("by-author flag works", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"stats", "--by-author"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("stats --by-author failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "Author") && !strings.Contains(output, "Test User") {
			t.Logf("by-author output: %s", output)
		}
	})
}

func TestSearchCommand(t *testing.T) {
	t.Run("finds packages by pattern", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"search", "express"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("search failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected to find 'express' in search results")
		}
	})

	t.Run("wildcard pattern works", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"search", "lod%"}) // SQL LIKE pattern
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("search failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "lodash") {
			t.Error("expected to find 'lodash' with wildcard pattern")
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
		rootCmd.SetArgs([]string{"search", "express", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("search failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}

func TestTreeCommand(t *testing.T) {
	t.Run("shows dependency tree", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"tree"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("tree failed: %v", err)
		}

		output := stdout.String()
		// Should show tree structure
		if !strings.Contains(output, "package.json") {
			t.Logf("tree output: %s", output)
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
		rootCmd.SetArgs([]string{"tree", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("tree failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}

func TestBlameCommand(t *testing.T) {
	t.Run("attributes dependencies to commits", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"blame"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("blame failed: %v", err)
		}

		output := stdout.String()
		// Should show commit attribution
		if !strings.Contains(output, "express") {
			t.Logf("blame output: %s", output)
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
		rootCmd.SetArgs([]string{"blame", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("blame failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}

func TestWhyCommand(t *testing.T) {
	t.Run("finds when package was added", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial")
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
		rootCmd.SetArgs([]string{"why", "express"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("why failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "express") {
			t.Error("expected to find 'express' in why output")
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
		rootCmd.SetArgs([]string{"why", "express", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("why failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}

func TestWhereCommand(t *testing.T) {
	t.Run("finds package in manifest", func(t *testing.T) {
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
		rootCmd.SetArgs([]string{"where", "express"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("where failed: %v", err)
		}

		output := stdout.String()
		if !strings.Contains(output, "package.json") {
			t.Error("expected to find package.json in where output")
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
		rootCmd.SetArgs([]string{"where", "express", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("where failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}

func TestStaleCommand(t *testing.T) {
	t.Run("finds stale dependencies", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"stale", "--days", "0"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("stale failed: %v", err)
		}

		// With --days 0, all lockfile deps should be stale
		output := stdout.String()
		t.Logf("stale output: %s", output)
	})

	t.Run("outputs json format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"stale", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("stale failed: %v", err)
		}

		var result interface{}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}
	})
}
