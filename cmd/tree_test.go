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
