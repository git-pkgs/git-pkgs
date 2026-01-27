package cmd_test

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestTreeMultipleVersionsSamePackage(t *testing.T) {
	// Regression test for https://github.com/git-pkgs/git-pkgs/issues/37
	// npm can have multiple versions of the same package (e.g., isexe@2.0.0 runtime, isexe@3.1.1 dev)
	// Both should appear in the tree output
	// Uses real-world fixture from github.com/ericcornelissen/shescape

	repoDir := createTestRepo(t)

	// Use actual shescape package-lock.json fixture
	packageLock, err := os.ReadFile("testdata/shescape-package-lock.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	addFileAndCommit(t, repoDir, "package-lock.json", string(packageLock), "Add package-lock.json")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	// Initialize the database
	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"init"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Run tree command
	var stdout bytes.Buffer
	rootCmd = cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"tree"})
	rootCmd.SetOut(&stdout)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("tree failed: %v", err)
	}

	output := stdout.String()

	// Count occurrences of "isexe" in output
	isexeCount := strings.Count(output, "isexe")
	if isexeCount != 2 {
		t.Errorf("expected 2 isexe entries in tree output, got %d\nOutput:\n%s", isexeCount, output)
	}

	// Verify both versions are present
	if !strings.Contains(output, "isexe 2.0.0") {
		t.Errorf("expected isexe 2.0.0 in tree output\nOutput:\n%s", output)
	}
	if !strings.Contains(output, "isexe 3.1.1") {
		t.Errorf("expected isexe 3.1.1 in tree output\nOutput:\n%s", output)
	}
}

func TestTreeGoSumNotSeparateManifest(t *testing.T) {
	// go.sum should not appear as a separate manifest in tree output.
	// Instead, its integrity hashes should be merged into go.mod dependencies.

	repoDir := createTestRepo(t)

	goMod, err := os.ReadFile("testdata/ades-go.mod")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	goSum, err := os.ReadFile("testdata/ades-go.sum")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	addFileAndCommit(t, repoDir, "go.mod", string(goMod), "Add go.mod")
	addFileAndCommit(t, repoDir, "go.sum", string(goSum), "Add go.sum")

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

	// go.sum should NOT appear as a separate manifest section
	if strings.Contains(output, "go.sum") {
		t.Errorf("go.sum should not appear as a separate manifest in tree output\nOutput:\n%s", output)
	}

	// go.mod should appear
	if !strings.Contains(output, "go.mod") {
		t.Errorf("expected go.mod in tree output\nOutput:\n%s", output)
	}

	// Dependencies should still be present
	if !strings.Contains(output, "golang.org/x/mod") {
		t.Errorf("expected golang.org/x/mod in tree output\nOutput:\n%s", output)
	}
}

func TestTreeGoToolDependencies(t *testing.T) {
	// Regression test for https://github.com/git-pkgs/git-pkgs/issues/38
	// Go tool dependencies should be classified as "development" not "runtime"
	// Uses real-world fixture from github.com/ericcornelissen/ades

	repoDir := createTestRepo(t)

	goMod, err := os.ReadFile("testdata/ades-go.mod")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	addFileAndCommit(t, repoDir, "go.mod", string(goMod), "Add go.mod")

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

	// mvdan.cc/unparam is a tool dependency and should be under development, not runtime
	if strings.Contains(output, "runtime") && strings.Contains(output, "mvdan.cc/unparam") {
		// Check if unparam appears after "runtime" header but before "development" header
		runtimeIdx := strings.Index(output, "runtime")
		devIdx := strings.Index(output, "development")
		unparamIdx := strings.Index(output, "mvdan.cc/unparam")

		if devIdx == -1 || (runtimeIdx != -1 && unparamIdx > runtimeIdx && unparamIdx < devIdx) {
			t.Errorf("mvdan.cc/unparam should be under development, not runtime\nOutput:\n%s", output)
		}
	}

	// Verify development section exists and contains tool dependencies
	if !strings.Contains(output, "development") {
		t.Errorf("expected development section in tree output\nOutput:\n%s", output)
	}

	// gochecknoinits is a tool dependency
	if !strings.Contains(output, "4d63.com/gochecknoinits") {
		t.Errorf("expected 4d63.com/gochecknoinits in tree output\nOutput:\n%s", output)
	}
}
