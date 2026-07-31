package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestDiffStat(t *testing.T) {
	result := &DiffResult{
		Added: []DiffEntry{
			{Name: "axios"},
			{Name: "zod"},
		},
		Removed: []DiffEntry{
			{Name: "request"},
		},
		Modified: []DiffEntry{
			{Name: "major", FromRequirement: "1.0.0", ToRequirement: "2.0.0"},
			{Name: "minor", FromRequirement: "1.0.0", ToRequirement: "1.1.0"},
			{Name: "patch", FromRequirement: "1.0.0", ToRequirement: "1.0.1"},
		},
	}

	stat := buildDiffStat(result)
	if stat.Added != 2 {
		t.Fatalf("added = %d, want 2", stat.Added)
	}
	if stat.Removed != 1 {
		t.Fatalf("removed = %d, want 1", stat.Removed)
	}
	if stat.Updated != 3 {
		t.Fatalf("updated = %d, want 3", stat.Updated)
	}
	if stat.MajorUpdates != 1 {
		t.Fatalf("major updates = %d, want 1", stat.MajorUpdates)
	}
	if stat.MinorUpdates != 1 {
		t.Fatalf("minor updates = %d, want 1", stat.MinorUpdates)
	}
	if stat.PatchUpdates != 1 {
		t.Fatalf("patch updates = %d, want 1", stat.PatchUpdates)
	}
}

func TestOutputDiffStat(t *testing.T) {
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)

	outputDiffStat(root, DiffStat{
		Added:        2,
		Removed:      1,
		Updated:      3,
		MajorUpdates: 1,
		MinorUpdates: 1,
		PatchUpdates: 1,
	})

	got := strings.TrimSpace(buf.String())
	want := "2 added, 1 removed, 3 updated (1 major, 1 minor, 1 patch)"
	if got != want {
		t.Fatalf("diff stat output = %q, want %q", got, want)
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

func TestComputeDiffByEcosystem_IgnoresLockfileMigration(t *testing.T) {
	fromDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: "manifest", DependencyType: "runtime"},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.21", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile, DependencyType: "development"},
		{Name: "express", Ecosystem: "npm", Requirement: "4.18.2", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile, DependencyType: "runtime"},
	}
	toDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: "manifest", DependencyType: "runtime"},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.21", ManifestPath: "pnpm-lock.yaml", ManifestKind: manifestKindLockfile},
		{Name: "express", Ecosystem: "npm", Requirement: "4.18.2", ManifestPath: "pnpm-lock.yaml", ManifestKind: manifestKindLockfile},
	}

	defaultResult := computeDiff(fromDeps, toDeps)
	if len(defaultResult.Added) != 2 {
		t.Fatalf("default added = %d, want 2: %+v", len(defaultResult.Added), defaultResult.Added)
	}
	if len(defaultResult.Removed) != 2 {
		t.Fatalf("default removed = %d, want 2: %+v", len(defaultResult.Removed), defaultResult.Removed)
	}

	result := computeDiffBy(fromDeps, toDeps, diffByEcosystem)
	if len(result.Added) != 0 {
		t.Fatalf("added = %d, want 0: %+v", len(result.Added), result.Added)
	}
	if len(result.Modified) != 0 {
		t.Fatalf("modified = %d, want 0: %+v", len(result.Modified), result.Modified)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("removed = %d, want 0: %+v", len(result.Removed), result.Removed)
	}
}

func TestDiffKindFilter(t *testing.T) {
	fromDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: manifestKindManifest},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.20", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
		{Name: "chalk", Ecosystem: "npm", Requirement: "5.3.0", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
	}
	toDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: manifestKindManifest},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.21", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
		{Name: "express", Ecosystem: "npm", Requirement: "^4.18.0", ManifestPath: "package.json", ManifestKind: manifestKindManifest},
		{Name: "express", Ecosystem: "npm", Requirement: "4.18.2", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
	}

	lock := computeDiff(filterDepsByKind(fromDeps, manifestKindLockfile), filterDepsByKind(toDeps, manifestKindLockfile))
	if len(lock.Added) != 1 || lock.Added[0].ManifestPath != "package-lock.json" || lock.Added[0].ManifestKind != manifestKindLockfile {
		t.Fatalf("lockfile added = %+v, want 1 from package-lock.json", lock.Added)
	}
	if len(lock.Modified) != 1 || lock.Modified[0].ToRequirement != "4.17.21" {
		t.Fatalf("lockfile modified = %+v, want 1 lodash 4.17.21", lock.Modified)
	}
	if len(lock.Removed) != 1 || lock.Removed[0].Name != "chalk" {
		t.Fatalf("lockfile removed = %+v, want 1 chalk", lock.Removed)
	}

	manifest := computeDiff(filterDepsByKind(fromDeps, manifestKindManifest), filterDepsByKind(toDeps, manifestKindManifest))
	if len(manifest.Added) != 1 || manifest.Added[0].ManifestPath != "package.json" {
		t.Fatalf("manifest added = %+v, want 1 from package.json", manifest.Added)
	}
	if len(manifest.Modified) != 0 {
		t.Fatalf("manifest modified = %+v, want 0", manifest.Modified)
	}
	if len(manifest.Removed) != 0 {
		t.Fatalf("manifest removed = %+v, want 0", manifest.Removed)
	}
}

func TestDiffKindFilter_ByEcosystem(t *testing.T) {
	// Manifest row first in the slice, lockfile row second: without pre-
	// filtering, --by ecosystem would key both under (npm, lodash) and pick
	// the manifest row as the reference, hiding the lockfile bump.
	fromDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: manifestKindManifest},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.20", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
	}
	toDeps := []database.Dependency{
		{Name: "lodash", Ecosystem: "npm", Requirement: "^4.0.0", ManifestPath: "package.json", ManifestKind: manifestKindManifest},
		{Name: "lodash", Ecosystem: "npm", Requirement: "4.17.21", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
	}

	result := computeDiffBy(
		filterDepsByKind(fromDeps, manifestKindLockfile),
		filterDepsByKind(toDeps, manifestKindLockfile),
		diffByEcosystem,
	)
	if len(result.Modified) != 1 {
		t.Fatalf("modified = %+v, want 1", result.Modified)
	}
	m := result.Modified[0]
	if m.FromRequirement != "4.17.20" || m.ToRequirement != "4.17.21" {
		t.Fatalf("requirements = %s -> %s, want 4.17.20 -> 4.17.21", m.FromRequirement, m.ToRequirement)
	}
	if m.ManifestKind != manifestKindLockfile {
		t.Fatalf("manifest kind = %q, want lockfile", m.ManifestKind)
	}
}

func TestComputeDiffByEcosystem_ReportsVersionChangeAcrossLockfileMigration(t *testing.T) {
	fromDeps := []database.Dependency{
		{Name: "express", Ecosystem: "npm", Requirement: "4.18.2", ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile},
	}
	toDeps := []database.Dependency{
		{Name: "express", Ecosystem: "npm", Requirement: "5.0.0", ManifestPath: "pnpm-lock.yaml", ManifestKind: manifestKindLockfile},
	}

	result := computeDiffBy(fromDeps, toDeps, diffByEcosystem)
	if len(result.Added) != 0 {
		t.Fatalf("added = %d, want 0: %+v", len(result.Added), result.Added)
	}
	if len(result.Removed) != 0 {
		t.Fatalf("removed = %d, want 0: %+v", len(result.Removed), result.Removed)
	}
	if len(result.Modified) != 1 {
		t.Fatalf("modified = %d, want 1: %+v", len(result.Modified), result.Modified)
	}
	entry := result.Modified[0]
	if entry.FromRequirement != "4.18.2" || entry.ToRequirement != "5.0.0" {
		t.Fatalf("requirements = %s -> %s, want 4.18.2 -> 5.0.0", entry.FromRequirement, entry.ToRequirement)
	}
	if entry.ManifestPath != "pnpm-lock.yaml" {
		t.Fatalf("manifest path = %q, want pnpm-lock.yaml", entry.ManifestPath)
	}
}

func TestComputeDiff_MultiVersionUpgrade(t *testing.T) {
	// glob exists at three versions; one version gets a patch bump.
	// Should produce 1 Modified, not 1 Added + 1 Removed.
	fromDeps := []database.Dependency{
		{Name: "glob", Ecosystem: "npm", Requirement: "7.2.3", ManifestPath: "package-lock.json"},
		{Name: "glob", Ecosystem: "npm", Requirement: "10.5.0", ManifestPath: "package-lock.json"},
		{Name: "glob", Ecosystem: "npm", Requirement: "13.0.0", ManifestPath: "package-lock.json"},
	}
	toDeps := []database.Dependency{
		{Name: "glob", Ecosystem: "npm", Requirement: "7.2.3", ManifestPath: "package-lock.json"},
		{Name: "glob", Ecosystem: "npm", Requirement: "10.5.0", ManifestPath: "package-lock.json"},
		{Name: "glob", Ecosystem: "npm", Requirement: "13.0.1", ManifestPath: "package-lock.json"},
	}

	result := computeDiff(fromDeps, toDeps)

	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d: %+v", len(result.Added), result.Added)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d: %+v", len(result.Removed), result.Removed)
	}
	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if result.Modified[0].FromRequirement != "13.0.0" {
		t.Errorf("expected FromRequirement '13.0.0', got %s", result.Modified[0].FromRequirement)
	}
	if result.Modified[0].ToRequirement != "13.0.1" {
		t.Errorf("expected ToRequirement '13.0.1', got %s", result.Modified[0].ToRequirement)
	}
}

func TestComputeDiff_VersionCountChangeWithUpgrade(t *testing.T) {
	// isexe goes from 1 copy at 3.1.1 to 5 copies at 3.1.5.
	// Should produce 1 Modified + 4 Added.
	fromDeps := []database.Dependency{
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.1", ManifestPath: "package-lock.json"},
	}
	toDeps := []database.Dependency{
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.5", ManifestPath: "package-lock.json"},
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.5", ManifestPath: "package-lock.json"},
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.5", ManifestPath: "package-lock.json"},
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.5", ManifestPath: "package-lock.json"},
		{Name: "isexe", Ecosystem: "npm", Requirement: "3.1.5", ManifestPath: "package-lock.json"},
	}

	result := computeDiff(fromDeps, toDeps)

	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d: %+v", len(result.Removed), result.Removed)
	}
	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if result.Modified[0].FromRequirement != "3.1.1" {
		t.Errorf("expected FromRequirement '3.1.1', got %s", result.Modified[0].FromRequirement)
	}
	if result.Modified[0].ToRequirement != "3.1.5" {
		t.Errorf("expected ToRequirement '3.1.5', got %s", result.Modified[0].ToRequirement)
	}
	if len(result.Added) != 4 {
		t.Errorf("expected 4 added, got %d: %+v", len(result.Added), result.Added)
	}
}

func TestComputeDiff_MultiVersionMixed(t *testing.T) {
	// Two versions on both sides. One version unchanged, the other upgraded.
	// semver stays at 6.3.1 on both sides, 7.7.3 upgrades to 7.7.4.
	fromDeps := []database.Dependency{
		{Name: "semver", Ecosystem: "npm", Requirement: "6.3.1", ManifestPath: "package-lock.json"},
		{Name: "semver", Ecosystem: "npm", Requirement: "7.7.3", ManifestPath: "package-lock.json"},
	}
	toDeps := []database.Dependency{
		{Name: "semver", Ecosystem: "npm", Requirement: "6.3.1", ManifestPath: "package-lock.json"},
		{Name: "semver", Ecosystem: "npm", Requirement: "7.7.4", ManifestPath: "package-lock.json"},
	}

	result := computeDiff(fromDeps, toDeps)

	if len(result.Added) != 0 {
		t.Errorf("expected 0 added, got %d: %+v", len(result.Added), result.Added)
	}
	if len(result.Removed) != 0 {
		t.Errorf("expected 0 removed, got %d: %+v", len(result.Removed), result.Removed)
	}
	if len(result.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d: %+v", len(result.Modified), result.Modified)
	}
	if result.Modified[0].FromRequirement != "7.7.3" {
		t.Errorf("expected FromRequirement '7.7.3', got %s", result.Modified[0].FromRequirement)
	}
	if result.Modified[0].ToRequirement != "7.7.4" {
		t.Errorf("expected ToRequirement '7.7.4', got %s", result.Modified[0].ToRequirement)
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
