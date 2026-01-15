package indexer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
)

func setupBenchIndexerRepo(b *testing.B, numCommits, depsPerCommit int) (string, *git.Repository, *database.DB) {
	b.Helper()
	tmpDir := b.TempDir()

	// Initialize git repo
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

	// Create commits with varying package.json
	for i := 0; i < numCommits; i++ {
		content := generatePackageJSON(depsPerCommit, i)
		path := filepath.Join(tmpDir, "package.json")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			b.Fatalf("failed to write file: %v", err)
		}

		cmd := exec.Command("git", "add", "package.json")
		cmd.Dir = tmpDir
		if err := cmd.Run(); err != nil {
			b.Fatalf("failed to git add: %v", err)
		}

		cmd = exec.Command("git", "commit", "-m", "Commit "+string(rune('0'+i%10)))
		cmd.Dir = tmpDir
		if err := cmd.Run(); err != nil {
			b.Fatalf("failed to commit: %v", err)
		}
	}

	repo, err := git.OpenRepository(tmpDir)
	if err != nil {
		b.Fatalf("failed to open repo: %v", err)
	}

	// Create database
	dbPath := filepath.Join(tmpDir, ".git", "pkgs", "pkgs.sqlite3")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		b.Fatalf("failed to create db dir: %v", err)
	}

	db, err := database.Create(dbPath)
	if err != nil {
		b.Fatalf("failed to create database: %v", err)
	}

	return tmpDir, repo, db
}

func generatePackageJSON(numDeps, version int) string {
	deps := make([]string, numDeps)
	for i := 0; i < numDeps; i++ {
		// Vary some versions based on commit number
		v := "1.0.0"
		if i < version {
			v = "2.0.0"
		}
		deps[i] = `"package-` + string(rune('a'+i%26)) + `-` + string(rune('0'+i/26)) + `": "^` + v + `"`
	}
	return `{"name":"test","version":"1.0.0","dependencies":{` + strings.Join(deps, ",") + `}}`
}

func BenchmarkIndexer_SmallRepo(b *testing.B) {
	_, repo, db := setupBenchIndexerRepo(b, 10, 20)
	defer func() { _ = db.Close() }()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Recreate database for each run
		b.StopTimer()
		dbPath := repo.DatabasePath()
		_ = db.Close()
		db, _ = database.Create(dbPath)
		b.StartTimer()

		idx := indexer.New(repo, db, indexer.Options{
			Branch: "main",
			Quiet:  true,
		})
		_, _ = idx.Run()
	}
}

func BenchmarkIndexer_MediumRepo(b *testing.B) {
	_, repo, db := setupBenchIndexerRepo(b, 50, 50)
	defer func() { _ = db.Close() }()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dbPath := repo.DatabasePath()
		_ = db.Close()
		db, _ = database.Create(dbPath)
		b.StartTimer()

		idx := indexer.New(repo, db, indexer.Options{
			Branch: "main",
			Quiet:  true,
		})
		_, _ = idx.Run()
	}
}

func BenchmarkIndexer_LargeRepo(b *testing.B) {
	_, repo, db := setupBenchIndexerRepo(b, 100, 100)
	defer func() { _ = db.Close() }()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		dbPath := repo.DatabasePath()
		_ = db.Close()
		db, _ = database.Create(dbPath)
		b.StartTimer()

		idx := indexer.New(repo, db, indexer.Options{
			Branch: "main",
			Quiet:  true,
		})
		_, _ = idx.Run()
	}
}

func BenchmarkIndexer_IncrementalUpdate(b *testing.B) {
	tmpDir, repo, db := setupBenchIndexerRepo(b, 50, 30)
	defer func() { _ = db.Close() }()

	// Do initial index
	idx := indexer.New(repo, db, indexer.Options{
		Branch: "main",
		Quiet:  true,
	})
	_, _ = idx.Run()

	// Add more commits
	for i := 0; i < 5; i++ {
		content := generatePackageJSON(30, 50+i)
		path := filepath.Join(tmpDir, "package.json")
		_ = os.WriteFile(path, []byte(content), 0644)

		cmd := exec.Command("git", "add", "package.json")
		cmd.Dir = tmpDir
		_ = cmd.Run()

		cmd = exec.Command("git", "commit", "-m", "New commit")
		cmd.Dir = tmpDir
		_ = cmd.Run()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		idx := indexer.New(repo, db, indexer.Options{
			Branch: "main",
			Quiet:  true,
		})
		_, _ = idx.Run()
	}
}
