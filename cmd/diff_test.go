package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
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

func TestDiff_TypeFilter(t *testing.T) {
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

	// Create package.json with both runtime and dev dependencies
	pkgJSON := `{
  "name": "test",
  "dependencies": {
    "lodash": "^4.0.0"
  },
  "devDependencies": {
    "eslint": "^8.0.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	run("add", "package.json")
	run("commit", "-m", "Initial")

	// Update both dependencies
	pkgJSON2 := `{
  "name": "test",
  "dependencies": {
    "lodash": "^4.1.0"
  },
  "devDependencies": {
    "eslint": "^8.1.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON2), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to repo dir
	oldDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldDir) }()

	// Run diff with --type=runtime (should only show lodash)
	rootCmd := NewRootCmd()
	rootCmd.SetArgs([]string{"diff", "--type=runtime"})

	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out := buf.String()

	if !containsString(out, "lodash") {
		t.Errorf("expected lodash (runtime) to be shown, got:\n%s", out)
	}
	if containsString(out, "eslint") {
		t.Errorf("expected eslint (development) to NOT be shown, got:\n%s", out)
	}

	// Run diff with --type=development (should only show eslint)
	rootCmd = NewRootCmd()
	rootCmd.SetArgs([]string{"diff", "--type=development"})

	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out = buf.String()

	if containsString(out, "lodash") {
		t.Errorf("expected lodash (runtime) to NOT be shown, got:\n%s", out)
	}
	if !containsString(out, "eslint") {
		t.Errorf("expected eslint (development) to be shown, got:\n%s", out)
	}

	// Run diff without filter (should show both)
	rootCmd = NewRootCmd()
	rootCmd.SetArgs([]string{"diff"})

	buf.Reset()
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&bytes.Buffer{})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("diff command failed: %v", err)
	}
	out = buf.String()

	if !containsString(out, "lodash") {
		t.Errorf("expected lodash to be shown, got:\n%s", out)
	}
	if !containsString(out, "eslint") {
		t.Errorf("expected eslint to be shown, got:\n%s", out)
	}
}

func TestComputeDiff_Modified(t *testing.T) {
	fromDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json"},
		{Name: "react", Ecosystem: "npm", Requirement: "^17.0.0", ManifestPath: "package.json"},
		{Name: "express", Ecosystem: "npm", Requirement: "^4.18.0", ManifestPath: "package.json"},
	}
	toDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.1.0", ManifestPath: "package.json"},
		{Name: "react", Ecosystem: "npm", Requirement: "^17.0.0", ManifestPath: "package.json"},
		{Name: "axios", Ecosystem: "npm", Requirement: "^1.0.0", ManifestPath: "package.json"},
	}

	result := computeDiff(fromDeps, toDeps)

	// lodash changed version: should be modified
	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if result.Modified[0].Name != "lodash" {
		t.Errorf("expected modified entry for lodash, got %s", result.Modified[0].Name)
	}
	if result.Modified[0].FromRequirement != "^4.0.0" {
		t.Errorf("expected FromRequirement '^4.0.0', got %s", result.Modified[0].FromRequirement)
	}
	if result.Modified[0].ToRequirement != "^4.1.0" {
		t.Errorf("expected ToRequirement '^4.1.0', got %s", result.Modified[0].ToRequirement)
	}

	// axios added
	if len(result.Added) != 1 {
		t.Fatalf("expected 1 added, got %d: %+v", len(result.Added), result.Added)
	}
	if result.Added[0].Name != "axios" {
		t.Errorf("expected added entry for axios, got %s", result.Added[0].Name)
	}

	// express removed
	if len(result.Removed) != 1 {
		t.Fatalf("expected 1 removed, got %d: %+v", len(result.Removed), result.Removed)
	}
	if result.Removed[0].Name != "express" {
		t.Errorf("expected removed entry for express, got %s", result.Removed[0].Name)
	}
}

func TestComputeDiff_SamePackageDifferentManifests(t *testing.T) {
	// Same package in different manifests should be tracked independently
	fromDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^3.0.0", ManifestPath: "packages/a/package.json"},
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "packages/b/package.json"},
	}
	toDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^3.1.0", ManifestPath: "packages/a/package.json"},
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "packages/b/package.json"},
	}

	result := computeDiff(fromDeps, toDeps)

	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if result.Modified[0].ManifestPath != "packages/a/package.json" {
		t.Errorf("expected modified in packages/a/package.json, got %s", result.Modified[0].ManifestPath)
	}
	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d", len(result.Added))
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d", len(result.Removed))
	}
}

func TestComputeDiff_DuplicatePackageVersionsInLockfile(t *testing.T) {
	// npm lockfiles can contain the same package at multiple versions due to
	// dependency hoisting. For example, package-lock.json might have:
	//   node_modules/ini (version 6.0.0)
	//   node_modules/some-dep/node_modules/ini (version 4.1.1)
	// The manifests parser returns both as separate dependencies with the same
	// name and manifest path but different versions.
	//
	// When from and to have identical deps, computeDiff should report no changes,
	// regardless of iteration order.
	fromDeps := []database.Dependency{
		{Name: "ini", Ecosystem: "npm", Requirement: "6.0.0", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "ini", Ecosystem: "npm", Requirement: "4.1.1", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "minipass", Ecosystem: "npm", Requirement: "7.1.2", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "minipass", Ecosystem: "npm", Requirement: "3.3.6", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "debug", Ecosystem: "npm", Requirement: "4.4.3", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "debug", Ecosystem: "npm", Requirement: "2.6.9", ManifestPath: "package-lock.json", DependencyType: "development"},
	}
	// Same deps, different order (simulating different iteration paths)
	toDeps := []database.Dependency{
		{Name: "ini", Ecosystem: "npm", Requirement: "4.1.1", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "ini", Ecosystem: "npm", Requirement: "6.0.0", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "minipass", Ecosystem: "npm", Requirement: "3.3.6", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "minipass", Ecosystem: "npm", Requirement: "7.1.2", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "debug", Ecosystem: "npm", Requirement: "2.6.9", ManifestPath: "package-lock.json", DependencyType: "development"},
		{Name: "debug", Ecosystem: "npm", Requirement: "4.4.3", ManifestPath: "package-lock.json", DependencyType: "development"},
	}

	result := computeDiff(fromDeps, toDeps)

	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d: %+v", len(result.Added), result.Added)
	}
	if len(result.Modified) != 0 {
		t.Errorf("expected 0 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d: %+v", len(result.Removed), result.Removed)
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
