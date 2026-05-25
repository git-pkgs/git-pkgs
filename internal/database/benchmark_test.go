package database_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func setupBenchDB(b *testing.B) *database.DB {
	b.Helper()
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.sqlite3")

	db, err := database.Create(dbPath)
	if err != nil {
		b.Fatalf("failed to create database: %v", err)
	}

	return db
}

func populateBenchDB(b *testing.B, db *database.DB, numCommits, depsPerCommit int) int64 {
	b.Helper()

	writer := database.NewBatchWriter(db)

	if err := writer.CreateBranch("main"); err != nil {
		b.Fatalf("failed to create branch: %v", err)
	}

	branchID := int64(1) // First branch

	manifest := database.ManifestInfo{
		Path:      "package.json",
		Ecosystem: "npm",
		Kind:      "manifest",
	}

	for i := 0; i < numCommits; i++ {
		sha := fmt.Sprintf("%040d", i)
		commitInfo := database.CommitInfo{
			SHA:         sha,
			Message:     fmt.Sprintf("Commit %d", i),
			AuthorName:  "Test User",
			AuthorEmail: "test@example.com",
			CommittedAt: time.Now().Add(-time.Duration(numCommits-i) * time.Hour),
		}

		writer.AddCommit(commitInfo, true)

		for j := 0; j < depsPerCommit; j++ {
			change := database.ChangeInfo{
				ManifestPath: "package.json",
				Name:         fmt.Sprintf("package-%d", j),
				Ecosystem:    "npm",
				PURL:         fmt.Sprintf("pkg:npm/package-%d", j),
				Requirement:  fmt.Sprintf("^%d.0.0", i%10),
				ChangeType:   "added",
			}
			writer.AddChange(sha, manifest, change)
		}

		if writer.ShouldFlush() {
			if err := writer.Flush(); err != nil {
				b.Fatalf("failed to flush: %v", err)
			}
		}
	}

	if err := writer.Flush(); err != nil {
		b.Fatalf("failed to flush: %v", err)
	}

	if err := writer.UpdateBranchLastSHA(fmt.Sprintf("%040d", numCommits-1)); err != nil {
		b.Fatalf("failed to update branch: %v", err)
	}

	return branchID
}

func BenchmarkBatchWriter_AddCommit(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	writer := database.NewBatchWriter(db)

	_ = writer.CreateBranch("main")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sha := fmt.Sprintf("%040d", i)
		commitInfo := database.CommitInfo{
			SHA:         sha,
			Message:     "Test commit",
			AuthorName:  "Test User",
			AuthorEmail: "test@example.com",
			CommittedAt: time.Now(),
		}
		writer.AddCommit(commitInfo, false)
		if writer.ShouldFlush() {
			_ = writer.Flush()
		}
	}
	_ = writer.Flush()
}

func BenchmarkBatchWriter_AddChange(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	writer := database.NewBatchWriter(db)

	_ = writer.CreateBranch("main")

	sha := "0000000000000000000000000000000000000000"
	commitInfo := database.CommitInfo{
		SHA:         sha,
		Message:     "Test commit",
		AuthorName:  "Test User",
		AuthorEmail: "test@example.com",
		CommittedAt: time.Now(),
	}
	writer.AddCommit(commitInfo, true)

	manifest := database.ManifestInfo{
		Path:      "package.json",
		Ecosystem: "npm",
		Kind:      "manifest",
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		change := database.ChangeInfo{
			ManifestPath: "package.json",
			Name:         fmt.Sprintf("package-%d", i),
			Ecosystem:    "npm",
			PURL:         fmt.Sprintf("pkg:npm/package-%d", i),
			Requirement:  "^1.0.0",
			ChangeType:   "added",
		}
		writer.AddChange(sha, manifest, change)
	}
	_ = writer.Flush()
}

func BenchmarkGetLatestDependencies_Small(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 10, 20)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetLatestDependencies(branchID)
	}
}

func BenchmarkGetLatestDependencies_Medium(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 100, 50)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetLatestDependencies(branchID)
	}
}

func BenchmarkGetLatestDependencies_Large(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 500, 100)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetLatestDependencies(branchID)
	}
}

func BenchmarkGetCommitsWithChanges_Small(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 50, 10)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetCommitsWithChanges(database.LogOptions{
			BranchID: branchID,
			Limit:    20,
		})
	}
}

func BenchmarkGetCommitsWithChanges_Large(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 500, 20)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetCommitsWithChanges(database.LogOptions{
			BranchID: branchID,
			Limit:    100,
		})
	}
}

func BenchmarkGetBlame(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 100, 50)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetBlame(branchID, "")
	}
}

func BenchmarkGetStats(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	branchID := populateBenchDB(b, db, 200, 30)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetStats(database.StatsOptions{
			BranchID: branchID,
			Limit:    10,
		})
	}
}

func BenchmarkGetChangesForCommit(b *testing.B) {
	db := setupBenchDB(b)
	defer func() { _ = db.Close() }()

	_ = populateBenchDB(b, db, 100, 30)

	sha := fmt.Sprintf("%040d", 50)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = db.GetChangesForCommit(sha)
	}
}
