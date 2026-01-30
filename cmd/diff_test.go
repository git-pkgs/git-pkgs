package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDiff_ManifestDeleted(t *testing.T) {
	// Create a temp repo
	dir := t.TempDir()

	// Initialize git
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test")

	// Create package.json with deps
	pkgJSON := `{
  "name": "test",
  "dependencies": {
    "lodash": "^4.0.0",
    "react": "^18.0.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	run("add", "package.json")
	run("commit", "-m", "Initial")

	// Now delete the manifest
	if err := os.Remove(filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}

	// Change to repo dir
	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	// Run diff (HEAD vs working tree)
	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"diff"})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out := buf.String()

	// Should show both packages as removed
	if !containsString(out, "lodash") {
		t.Errorf("expected lodash to be shown as removed, got:\n%s", out)
	}
	if !containsString(out, "react") {
		t.Errorf("expected react to be shown as removed, got:\n%s", out)
	}
	if !containsString(out, "Removed") {
		t.Errorf("expected 'Removed' section, got:\n%s", out)
	}
}

func TestDiff_ManifestDeletedBetweenCommits(t *testing.T) {
	// Create a temp repo
	dir := t.TempDir()

	// Initialize git
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test")

	// Create package.json with deps
	pkgJSON := `{
  "name": "test",
  "dependencies": {
    "lodash": "^4.0.0",
    "react": "^18.0.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	run("add", "package.json")
	run("commit", "-m", "Add package.json")

	// Delete manifest and commit
	if err := os.Remove(filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}
	run("add", "package.json")
	run("commit", "-m", "Remove package.json")

	// Change to repo dir
	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	// Initialize database
	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"init"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Run diff HEAD~1..HEAD (should show packages removed)
	rootCmd = NewRootCmd()
	rootCmd.SetArgs([]string{"diff", "HEAD~1..HEAD"})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out := buf.String()

	// Should show both packages as removed
	if !containsString(out, "lodash") {
		t.Errorf("expected lodash to be shown as removed, got:\n%s", out)
	}
	if !containsString(out, "react") {
		t.Errorf("expected react to be shown as removed, got:\n%s", out)
	}
	if !containsString(out, "Removed") {
		t.Errorf("expected 'Removed' section, got:\n%s", out)
	}
}

func TestDiff_ManifestRenamed(t *testing.T) {
	// Create a temp repo
	dir := t.TempDir()

	// Initialize git
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "Test")

	// Create initial workflow file
	workflow := `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
`
	if err := os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github/workflows/test.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-m", "Add workflow")

	// Rename the workflow file
	run("mv", ".github/workflows/test.yml", ".github/workflows/ci.yml")
	run("commit", "-am", "Rename workflow")

	// Add more commits so there's history
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Test"), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "Add readme")

	// Change to repo dir
	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	// Initialize database (this exercises the PrefetchDiffs rename handling)
	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"init"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Run diff - should show no changes since HEAD and working tree are identical
	rootCmd = NewRootCmd()
	rootCmd.SetArgs([]string{"diff"})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out := buf.String()

	// Should NOT show old test.yml as removed (the bug we fixed)
	if containsString(out, "test.yml") {
		t.Errorf("expected test.yml to NOT appear (it was renamed, not deleted), got:\n%s", out)
	}

	// Should show no dependency changes
	if !containsString(out, "No dependency changes") {
		t.Errorf("expected 'No dependency changes', got:\n%s", out)
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
