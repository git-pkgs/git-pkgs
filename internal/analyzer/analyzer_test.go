package analyzer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

func addFile(t *testing.T, repoDir, path, content string) {
	t.Helper()
	fullPath := filepath.Join(repoDir, path)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cmd := exec.Command("git", "add", path)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}
}

func commit(t *testing.T, repoDir, message string) string {
	t.Helper()
	cmd := exec.Command("git", "commit", "-m", message)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get commit sha: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func openRepo(t *testing.T, path string) *git.Repository {
	t.Helper()
	repo, err := git.PlainOpen(path)
	if err != nil {
		t.Fatalf("failed to open repo: %v", err)
	}
	return repo
}

func getCommit(t *testing.T, repo *git.Repository, sha string) *plumbing.Hash {
	t.Helper()
	hash := plumbing.NewHash(sha)
	return &hash
}

func sampleGemfile(gems map[string]string) string {
	lines := []string{`source "https://rubygems.org"`, ""}
	for name, version := range gems {
		if version != "" {
			lines = append(lines, `gem "`+name+`", "`+version+`"`)
		} else {
			lines = append(lines, `gem "`+name+`"`)
		}
	}
	return strings.Join(lines, "\n")
}

func samplePackageJSON(deps map[string]string) string {
	depsStr := ""
	for name, version := range deps {
		if depsStr != "" {
			depsStr += ","
		}
		depsStr += `"` + name + `":"` + version + `"`
	}
	return `{"name":"test","version":"1.0.0","dependencies":{` + depsStr + `}}`
}

func TestAnalyzeCommitWithNoManifests(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	sha := commit(t, repoDir, "Initial commit")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	result, err := a.AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != nil {
		t.Error("expected nil result for commit with no manifests")
	}
}

func TestAnalyzeCommitWithAddedGemfile(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{
		"rails": "~> 7.0",
		"puma":  "~> 6.0",
	}))
	sha := commit(t, repoDir, "Add Gemfile")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	result, err := a.AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}

	if len(result.Changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(result.Changes))
	}

	var railsChange *analyzer.Change
	for i, ch := range result.Changes {
		if ch.Name == "rails" {
			railsChange = &result.Changes[i]
			break
		}
	}

	if railsChange == nil {
		t.Fatal("expected rails change")
		return
	}

	if railsChange.ChangeType != "added" {
		t.Errorf("expected change type 'added', got %s", railsChange.ChangeType)
	}

	if railsChange.Requirement != "~> 7.0" {
		t.Errorf("expected requirement '~> 7.0', got %s", railsChange.Requirement)
	}

	if railsChange.Ecosystem != "gem" {
		t.Errorf("expected ecosystem 'gem', got %s", railsChange.Ecosystem)
	}
}

func TestAnalyzeCommitWithModifiedGemfile(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{"rails": "~> 7.0"}))
	firstSha := commit(t, repoDir, "Add Gemfile")

	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{"rails": "~> 7.1"}))
	secondSha := commit(t, repoDir, "Update rails")

	repo := openRepo(t, repoDir)
	a := analyzer.New()

	firstHash := getCommit(t, repo, firstSha)
	firstCommit, _ := repo.CommitObject(*firstHash)
	firstResult, _ := a.AnalyzeCommit(firstCommit, nil)

	secondHash := getCommit(t, repo, secondSha)
	secondCommit, _ := repo.CommitObject(*secondHash)
	result, err := a.AnalyzeCommit(secondCommit, firstResult.Snapshot)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}

	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}

	ch := result.Changes[0]
	if ch.ChangeType != "modified" {
		t.Errorf("expected change type 'modified', got %s", ch.ChangeType)
	}

	if ch.PreviousRequirement != "~> 7.0" {
		t.Errorf("expected previous requirement '~> 7.0', got %s", ch.PreviousRequirement)
	}

	if ch.Requirement != "~> 7.1" {
		t.Errorf("expected requirement '~> 7.1', got %s", ch.Requirement)
	}
}

func TestAnalyzeCommitWithRemovedDependency(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{
		"rails": "~> 7.0",
		"puma":  "~> 6.0",
	}))
	firstSha := commit(t, repoDir, "Add Gemfile")

	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{"rails": "~> 7.0"}))
	secondSha := commit(t, repoDir, "Remove puma")

	repo := openRepo(t, repoDir)
	a := analyzer.New()

	firstHash := getCommit(t, repo, firstSha)
	firstCommit, _ := repo.CommitObject(*firstHash)
	firstResult, _ := a.AnalyzeCommit(firstCommit, nil)

	secondHash := getCommit(t, repo, secondSha)
	secondCommit, _ := repo.CommitObject(*secondHash)
	result, err := a.AnalyzeCommit(secondCommit, firstResult.Snapshot)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}

	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(result.Changes))
	}

	ch := result.Changes[0]
	if ch.Name != "puma" {
		t.Errorf("expected puma to be removed, got %s", ch.Name)
	}

	if ch.ChangeType != "removed" {
		t.Errorf("expected change type 'removed', got %s", ch.ChangeType)
	}
}

func TestAnalyzeCommitWithPackageJSON(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	addFile(t, repoDir, "package.json", samplePackageJSON(map[string]string{
		"lodash": "^4.17.21",
		"react":  "^18.0.0",
	}))
	sha := commit(t, repoDir, "Add package.json")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	result, err := a.AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
		return
	}

	if len(result.Changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(result.Changes))
	}

	for _, ch := range result.Changes {
		if ch.Ecosystem != "npm" {
			t.Errorf("expected ecosystem 'npm', got %s", ch.Ecosystem)
		}
	}
}

func TestDependenciesAtCommit(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{
		"rails": "~> 7.0",
		"puma":  "~> 6.0",
	}))
	addFile(t, repoDir, "package.json", samplePackageJSON(map[string]string{
		"lodash": "^4.17.21",
	}))
	sha := commit(t, repoDir, "Add manifests")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	deps, err := a.DependenciesAtCommit(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(deps))
	}

	ecosystems := make(map[string]int)
	for _, d := range deps {
		ecosystems[d.Ecosystem]++
	}

	if ecosystems["gem"] != 2 {
		t.Errorf("expected 2 gem dependencies, got %d", ecosystems["gem"])
	}

	if ecosystems["npm"] != 1 {
		t.Errorf("expected 1 npm dependency, got %d", ecosystems["npm"])
	}
}

func TestDependenciesInWorkingDir(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{
		"rails": "~> 7.0",
		"puma":  "~> 6.0",
	}))
	addFile(t, repoDir, "package.json", samplePackageJSON(map[string]string{
		"lodash": "^4.17.21",
	}))
	commit(t, repoDir, "Add manifests")

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(deps))
	}

	ecosystems := make(map[string]int)
	for _, d := range deps {
		ecosystems[d.Ecosystem]++
	}

	if ecosystems["gem"] != 2 {
		t.Errorf("expected 2 gem dependencies, got %d", ecosystems["gem"])
	}

	if ecosystems["npm"] != 1 {
		t.Errorf("expected 1 npm dependency, got %d", ecosystems["npm"])
	}
}

func TestDependenciesInWorkingDirUncommitted(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Write a manifest file without committing
	if err := os.WriteFile(filepath.Join(repoDir, "Gemfile"), []byte(sampleGemfile(map[string]string{
		"rails": "~> 7.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}

	if deps[0].Name != "rails" {
		t.Errorf("expected rails, got %s", deps[0].Name)
	}
}

func TestDependenciesInWorkingDirRespectsGitignore(t *testing.T) {
	repoDir := createTestRepo(t)

	// Create .gitignore that ignores vendor/ and a specific file
	addFile(t, repoDir, ".gitignore", "vendor/\nignored-Gemfile\n")
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Add a tracked manifest
	if err := os.WriteFile(filepath.Join(repoDir, "Gemfile"), []byte(sampleGemfile(map[string]string{
		"rails": "~> 7.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add an ignored manifest in vendor/
	if err := os.MkdirAll(filepath.Join(repoDir, "vendor"), 0755); err != nil {
		t.Fatalf("failed to create vendor dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "vendor", "Gemfile"), []byte(sampleGemfile(map[string]string{
		"sinatra": "~> 3.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add an ignored manifest by name
	if err := os.WriteFile(filepath.Join(repoDir, "ignored-Gemfile"), []byte(sampleGemfile(map[string]string{
		"puma": "~> 6.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only see rails from the non-ignored Gemfile
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d: %+v", len(deps), deps)
	}

	if deps[0].Name != "rails" {
		t.Errorf("expected rails, got %s", deps[0].Name)
	}
}

func TestDependenciesInWorkingDirIgnoresSubmodules(t *testing.T) {
	repoDir := createTestRepo(t)

	// Create .gitmodules with submodules
	gitmodulesContent := `[submodule "vendor/lib"]
	path = vendor/lib
	url = https://github.com/example/lib.git
[submodule "external/tool"]
	path = external/tool
	url = https://github.com/example/tool.git
`
	addFile(t, repoDir, ".gitmodules", gitmodulesContent)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Add a tracked manifest at root
	if err := os.WriteFile(filepath.Join(repoDir, "Gemfile"), []byte(sampleGemfile(map[string]string{
		"rails": "~> 7.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add manifests in submodule directories (should be ignored)
	if err := os.MkdirAll(filepath.Join(repoDir, "vendor", "lib"), 0755); err != nil {
		t.Fatalf("failed to create vendor/lib dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "vendor", "lib", "Gemfile"), []byte(sampleGemfile(map[string]string{
		"sinatra": "~> 3.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(repoDir, "external", "tool"), 0755); err != nil {
		t.Fatalf("failed to create external/tool dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "external", "tool", "package.json"), []byte(`{
		"name": "test",
		"dependencies": {
			"lodash": "^4.17.21"
		}
	}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should see rails from root Gemfile + 2 submodules from .gitmodules, but not manifests inside submodule dirs
	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d: %+v", len(deps), deps)
	}

	names := make(map[string]bool)
	for _, dep := range deps {
		names[dep.Name] = true
	}
	for _, expected := range []string{"rails", "vendor/lib", "external/tool"} {
		if !names[expected] {
			t.Errorf("expected %s dependency", expected)
		}
	}
}

func TestDependenciesInWorkingDirIncludesSubmodules(t *testing.T) {
	repoDir := createTestRepo(t)

	// Create .gitmodules with submodules
	gitmodulesContent := `[submodule "vendor/lib"]
	path = vendor/lib
	url = https://github.com/example/lib.git
[submodule "external/tool"]
	path = external/tool
	url = https://github.com/example/tool.git
`
	addFile(t, repoDir, ".gitmodules", gitmodulesContent)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Add a tracked manifest at root
	if err := os.WriteFile(filepath.Join(repoDir, "Gemfile"), []byte(sampleGemfile(map[string]string{
		"rails": "~> 7.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add manifests in submodule directories (should be included when flag is true)
	if err := os.MkdirAll(filepath.Join(repoDir, "vendor", "lib"), 0755); err != nil {
		t.Fatalf("failed to create vendor/lib dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "vendor", "lib", "Gemfile"), []byte(sampleGemfile(map[string]string{
		"sinatra": "~> 3.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(repoDir, "external", "tool"), 0755); err != nil {
		t.Fatalf("failed to create external/tool dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "external", "tool", "package.json"), []byte(`{
		"name": "test",
		"dependencies": {
			"lodash": "^4.17.21"
		}
	}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should see all dependencies including those from submodules + .gitmodules entries
	if len(deps) != 5 {
		t.Fatalf("expected 5 dependencies, got %d: %+v", len(deps), deps)
	}

	// Verify we have deps from all manifests
	names := make(map[string]bool)
	for _, dep := range deps {
		names[dep.Name] = true
	}

	expected := []string{"rails", "sinatra", "lodash", "vendor/lib", "external/tool"}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("expected to find %s in dependencies", name)
		}
	}
}

func TestDependenciesInWorkingDirNegationGitignore(t *testing.T) {
	repoDir := createTestRepo(t)

	// First commit with a simple .gitignore, then update to deny-by-default
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Now write the deny-by-default .gitignore directly (don't git add it)
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte("/*\n!.github/\n!src/\n"), 0644); err != nil {
		t.Fatalf("failed to write .gitignore: %v", err)
	}

	// Add manifest in allowed .github directory
	if err := os.MkdirAll(filepath.Join(repoDir, ".github", "workflows"), 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, ".github", "workflows", "ci.yml"), []byte(`name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add manifest in allowed src directory
	if err := os.MkdirAll(filepath.Join(repoDir, "src"), 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "src", "Gemfile"), []byte(sampleGemfile(map[string]string{
		"rails": "~> 7.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add manifest in ignored root (should be skipped)
	if err := os.WriteFile(filepath.Join(repoDir, "Gemfile"), []byte(sampleGemfile(map[string]string{
		"sinatra": "~> 3.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	// Add manifest in ignored other directory (should be skipped)
	if err := os.MkdirAll(filepath.Join(repoDir, "vendor"), 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "vendor", "Gemfile"), []byte(sampleGemfile(map[string]string{
		"puma": "~> 6.0",
	})), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	a := analyzer.New()
	deps, err := a.DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should see rails from src/Gemfile and actions/checkout from .github, but not sinatra or puma
	names := make(map[string]bool)
	for _, dep := range deps {
		names[dep.Name] = true
	}

	if !names["rails"] {
		t.Error("expected to find rails from src/Gemfile")
	}
	if !names["actions/checkout"] {
		t.Errorf("expected to find actions/checkout from .github/workflows/ci.yml, got deps: %+v", deps)
	}
	if names["sinatra"] {
		t.Error("expected sinatra from root Gemfile to be ignored")
	}
	if names["puma"] {
		t.Error("expected puma from vendor/Gemfile to be ignored")
	}
}

func TestAnalyzeCommitWithGitHubActionsWorkflow(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
`
	addFile(t, repoDir, ".github/workflows/ci.yml", workflow)
	sha := commit(t, repoDir, "Add CI workflow")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	result, err := a.AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result for commit with GitHub Actions workflow")
		return
	}

	if len(result.Changes) != 2 {
		t.Fatalf("expected 2 changes (checkout and setup-node), got %d", len(result.Changes))
	}

	names := make(map[string]bool)
	for _, ch := range result.Changes {
		names[ch.Name] = true
		if ch.Ecosystem != "github-actions" {
			t.Errorf("expected ecosystem 'github-actions', got %s", ch.Ecosystem)
		}
	}

	if !names["actions/checkout"] {
		t.Error("expected actions/checkout in changes")
	}
	if !names["actions/setup-node"] {
		t.Error("expected actions/setup-node in changes")
	}
}

func TestDependenciesAtCommitWithGitHubActions(t *testing.T) {
	repoDir := createTestRepo(t)

	workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	addFile(t, repoDir, ".github/workflows/ci.yml", workflow)
	addFile(t, repoDir, "Gemfile", sampleGemfile(map[string]string{"rails": "~> 7.0"}))
	sha := commit(t, repoDir, "Add workflow and Gemfile")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	deps, err := a.DependenciesAtCommit(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ecosystems := make(map[string]int)
	for _, d := range deps {
		ecosystems[d.Ecosystem]++
	}

	if ecosystems["github-actions"] != 1 {
		t.Errorf("expected 1 github-actions dependency, got %d", ecosystems["github-actions"])
	}
	if ecosystems["gem"] != 1 {
		t.Errorf("expected 1 gem dependency, got %d", ecosystems["gem"])
	}
}

func TestAnalyzeCommitMultiVersionModified(t *testing.T) {
	// When a lockfile has the same package at multiple versions and one version
	// changes, PreviousRequirement should reflect the actual old version, not
	// whichever version happened to be last in the map.
	//
	// Before: shared@2.0.0 (under dep-a) and shared@1.5.0 (under dep-b)
	// After:  shared@2.1.0 (under dep-a) and shared@1.5.0 (under dep-b)
	// Expected change: shared modified 2.0.0 -> 2.1.0
	// Bug: beforeByName["shared"] = 1.5.0 (last wins), so PreviousRequirement = "1.5.0"
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	before, err := os.ReadFile("testdata/multi-version-before.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	addFile(t, repoDir, "package-lock.json", string(before))
	firstSha := commit(t, repoDir, "Add lockfile with shared@2.0.0 and shared@1.5.0")

	after, err := os.ReadFile("testdata/multi-version-after.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	addFile(t, repoDir, "package-lock.json", string(after))
	secondSha := commit(t, repoDir, "Update shared 2.0.0 -> 2.1.0")

	repo := openRepo(t, repoDir)
	a := analyzer.New()

	firstHash := getCommit(t, repo, firstSha)
	firstCommit, _ := repo.CommitObject(*firstHash)
	firstResult, err := a.AnalyzeCommit(firstCommit, nil)
	if err != nil {
		t.Fatalf("analyzing first commit: %v", err)
	}

	secondHash := getCommit(t, repo, secondSha)
	secondCommit, _ := repo.CommitObject(*secondHash)
	result, err := a.AnalyzeCommit(secondCommit, firstResult.Snapshot)
	if err != nil {
		t.Fatalf("analyzing second commit: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Should have exactly one change: shared modified 2.0.0 -> 2.1.0
	var modifiedChanges []analyzer.Change
	for _, ch := range result.Changes {
		if ch.ChangeType == "modified" {
			modifiedChanges = append(modifiedChanges, ch)
		}
	}

	if len(modifiedChanges) != 1 {
		t.Fatalf("expected 1 modified change, got %d: %+v", len(modifiedChanges), result.Changes)
	}

	ch := modifiedChanges[0]
	if ch.Name != "shared" {
		t.Errorf("expected modified package 'shared', got %q", ch.Name)
	}
	if ch.PreviousRequirement != "2.0.0" {
		t.Errorf("expected PreviousRequirement '2.0.0', got %q", ch.PreviousRequirement)
	}
	if ch.Requirement != "2.1.0" {
		t.Errorf("expected Requirement '2.1.0', got %q", ch.Requirement)
	}
}

func TestMultipleVersionsSamePackage(t *testing.T) {
	// Regression test for https://github.com/git-pkgs/git-pkgs/issues/37
	// npm can have multiple versions of the same package (e.g., isexe@2.0.0 runtime, isexe@3.1.1 dev)
	// Uses real-world fixture from github.com/ericcornelissen/shescape
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	// Use actual shescape package-lock.json fixture
	packageLock, err := os.ReadFile("testdata/shescape-package-lock.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	addFile(t, repoDir, "package-lock.json", string(packageLock))
	sha := commit(t, repoDir, "Add package-lock.json with multiple isexe versions")

	repo := openRepo(t, repoDir)
	hash := getCommit(t, repo, sha)
	c, _ := repo.CommitObject(*hash)

	a := analyzer.New()
	result, err := a.AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Count isexe entries in the snapshot
	isexeCount := 0
	var isexeVersions []string
	for key, entry := range result.Snapshot {
		if key.Name == "isexe" {
			isexeCount++
			isexeVersions = append(isexeVersions, entry.Requirement)
		}
	}

	if isexeCount != 2 {
		t.Errorf("expected 2 isexe entries in snapshot, got %d (versions: %v)", isexeCount, isexeVersions)
	}

	// Verify both versions are present
	hasV2 := false
	hasV3 := false
	for key, entry := range result.Snapshot {
		if key.Name == "isexe" {
			if entry.Requirement == "2.0.0" {
				hasV2 = true
			}
			if entry.Requirement == "3.1.1" {
				hasV3 = true
			}
		}
	}

	if !hasV2 {
		t.Error("expected isexe@2.0.0 in snapshot")
	}
	if !hasV3 {
		t.Error("expected isexe@3.1.1 in snapshot")
	}
}
