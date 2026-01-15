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
	}

	if len(result.Changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(result.Changes))
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
	}

	if len(result.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(result.Changes))
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
	}

	if len(result.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(result.Changes))
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
	}

	if len(result.Changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(result.Changes))
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
