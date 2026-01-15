package analyzer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func setupBenchRepo(b *testing.B) (string, *git.Repository) {
	b.Helper()
	tmpDir := b.TempDir()

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
			b.Fatalf("failed to run %v: %v", args, err)
		}
	}

	repo, err := git.PlainOpen(tmpDir)
	if err != nil {
		b.Fatalf("failed to open repo: %v", err)
	}

	return tmpDir, repo
}

func addBenchFile(b *testing.B, repoDir, path, content string) {
	b.Helper()
	fullPath := filepath.Join(repoDir, path)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		b.Fatalf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		b.Fatalf("failed to write file: %v", err)
	}

	cmd := exec.Command("git", "add", path)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		b.Fatalf("failed to git add: %v", err)
	}
}

func benchCommit(b *testing.B, repoDir, message string) *object.Commit {
	b.Helper()
	cmd := exec.Command("git", "commit", "-m", message)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		b.Fatalf("failed to commit: %v", err)
	}

	repo, _ := git.PlainOpen(repoDir)
	head, _ := repo.Head()
	commit, _ := repo.CommitObject(head.Hash())
	return commit
}

func generateLargePackageJSON(numDeps int) string {
	deps := make([]string, numDeps)
	for i := 0; i < numDeps; i++ {
		deps[i] = `"package-` + string(rune('a'+i%26)) + `-` + string(rune('0'+i/26)) + `": "^1.0.0"`
	}
	return `{"name":"test","version":"1.0.0","dependencies":{` + strings.Join(deps, ",") + `}}`
}

func generateLargeGemfile(numDeps int) string {
	lines := []string{`source "https://rubygems.org"`, ""}
	for i := 0; i < numDeps; i++ {
		lines = append(lines, `gem "gem-`+string(rune('a'+i%26))+`-`+string(rune('0'+i/26))+`", "~> 1.0"`)
	}
	return strings.Join(lines, "\n")
}

func BenchmarkAnalyzeCommit_SmallManifest(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "README.md", "# Test")
	benchCommit(b, repoDir, "Initial")

	addBenchFile(b, repoDir, "package.json", `{"name":"test","dependencies":{"lodash":"^4.0.0","react":"^18.0.0"}}`)
	commit := benchCommit(b, repoDir, "Add package.json")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.AnalyzeCommit(commit, nil)
	}
}

func BenchmarkAnalyzeCommit_MediumManifest(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "README.md", "# Test")
	benchCommit(b, repoDir, "Initial")

	addBenchFile(b, repoDir, "package.json", generateLargePackageJSON(50))
	commit := benchCommit(b, repoDir, "Add package.json")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.AnalyzeCommit(commit, nil)
	}
}

func BenchmarkAnalyzeCommit_LargeManifest(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "README.md", "# Test")
	benchCommit(b, repoDir, "Initial")

	addBenchFile(b, repoDir, "package.json", generateLargePackageJSON(200))
	commit := benchCommit(b, repoDir, "Add package.json")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.AnalyzeCommit(commit, nil)
	}
}

func BenchmarkAnalyzeCommit_MultipleManifests(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "README.md", "# Test")
	benchCommit(b, repoDir, "Initial")

	addBenchFile(b, repoDir, "package.json", generateLargePackageJSON(30))
	addBenchFile(b, repoDir, "Gemfile", generateLargeGemfile(30))
	addBenchFile(b, repoDir, "frontend/package.json", generateLargePackageJSON(20))
	commit := benchCommit(b, repoDir, "Add manifests")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.AnalyzeCommit(commit, nil)
	}
}

func BenchmarkAnalyzeCommit_WithSnapshot(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "README.md", "# Test")
	benchCommit(b, repoDir, "Initial")

	addBenchFile(b, repoDir, "package.json", generateLargePackageJSON(100))
	firstCommit := benchCommit(b, repoDir, "Add package.json")

	a := analyzer.New()
	firstResult, _ := a.AnalyzeCommit(firstCommit, nil)

	// Modify one dependency
	content := strings.Replace(generateLargePackageJSON(100), `"^1.0.0"`, `"^2.0.0"`, 1)
	addBenchFile(b, repoDir, "package.json", content)
	secondCommit := benchCommit(b, repoDir, "Update dep")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.AnalyzeCommit(secondCommit, firstResult.Snapshot)
	}
}

func BenchmarkDependenciesAtCommit_Small(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "package.json", `{"name":"test","dependencies":{"lodash":"^4.0.0"}}`)
	commit := benchCommit(b, repoDir, "Add package.json")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.DependenciesAtCommit(commit)
	}
}

func BenchmarkDependenciesAtCommit_Large(b *testing.B) {
	repoDir, _ := setupBenchRepo(b)
	addBenchFile(b, repoDir, "package.json", generateLargePackageJSON(200))
	addBenchFile(b, repoDir, "Gemfile", generateLargeGemfile(100))
	commit := benchCommit(b, repoDir, "Add manifests")

	a := analyzer.New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = a.DependenciesAtCommit(commit)
	}
}
