package database_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func newTestBatchWriter(t *testing.T) (*database.BatchWriter, *database.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	writer := database.NewBatchWriter(db)
	if err := writer.CreateBranch("main"); err != nil {
		t.Fatalf("failed to create branch: %v", err)
	}
	return writer, db
}

func addTestCommitWithChange(writer *database.BatchWriter, sha string) {
	writer.AddCommit(database.CommitInfo{
		SHA:         sha,
		Message:     "commit " + sha,
		AuthorName:  "test",
		AuthorEmail: "test@example.com",
		CommittedAt: time.Now(),
	}, true)
	writer.AddChange(sha, database.ManifestInfo{
		Path:      "go.mod",
		Ecosystem: "go",
		Kind:      "manifest",
	}, database.ChangeInfo{
		Name:       "example.com/pkg-" + sha,
		Ecosystem:  "go",
		ChangeType: "added",
	})
}

func TestFlushAsync(t *testing.T) {
	writer, db := newTestBatchWriter(t)

	addTestCommitWithChange(writer, "aaa111")
	addTestCommitWithChange(writer, "bbb222")

	writer.FlushAsync()

	if err := writer.WaitForFlush(); err != nil {
		t.Fatalf("WaitForFlush returned error: %v", err)
	}

	var commitCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM commits").Scan(&commitCount); err != nil {
		t.Fatalf("failed to count commits: %v", err)
	}
	if commitCount != 2 {
		t.Errorf("expected 2 commits, got %d", commitCount)
	}

	var changeCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dependency_changes").Scan(&changeCount); err != nil {
		t.Fatalf("failed to count changes: %v", err)
	}
	if changeCount != 2 {
		t.Errorf("expected 2 changes, got %d", changeCount)
	}
}

func TestFlushAsyncErrorPropagation(t *testing.T) {
	writer, db := newTestBatchWriter(t)

	addTestCommitWithChange(writer, "err111")

	writer.FlushAsync()

	if err := writer.WaitForFlush(); err != nil {
		t.Fatalf("first flush should succeed: %v", err)
	}

	// Insert the same commit again -- OR IGNORE means the duplicate is
	// silently skipped rather than causing an error.
	addTestCommitWithChange(writer, "err111")

	writer.FlushAsync()

	err := writer.WaitForFlush()
	if err != nil {
		t.Fatalf("second flush should succeed (OR IGNORE): %v", err)
	}

	// Verify the commit exists exactly once
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM commits WHERE sha = 'err111'").Scan(&count); err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 commit, got %d", count)
	}
}

func TestFlushAsyncDoubleBuffer(t *testing.T) {
	writer, db := newTestBatchWriter(t)

	// First batch
	for i := 0; i < 5; i++ {
		addTestCommitWithChange(writer, fmt.Sprintf("batch1-%03d", i))
	}

	writer.FlushAsync()

	// While first batch flushes, add second batch
	for i := 0; i < 3; i++ {
		addTestCommitWithChange(writer, fmt.Sprintf("batch2-%03d", i))
	}

	// Wait for first batch
	if err := writer.WaitForFlush(); err != nil {
		t.Fatalf("first flush failed: %v", err)
	}

	// Flush second batch synchronously
	if err := writer.Flush(); err != nil {
		t.Fatalf("second flush failed: %v", err)
	}

	var commitCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM commits").Scan(&commitCount); err != nil {
		t.Fatalf("failed to count commits: %v", err)
	}
	if commitCount != 8 {
		t.Errorf("expected 8 commits (5 + 3), got %d", commitCount)
	}

	var changeCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM dependency_changes").Scan(&changeCount); err != nil {
		t.Fatalf("failed to count changes: %v", err)
	}
	if changeCount != 8 {
		t.Errorf("expected 8 changes (5 + 3), got %d", changeCount)
	}
}

func TestWaitForFlushNoOp(t *testing.T) {
	writer, _ := newTestBatchWriter(t)

	// WaitForFlush with no prior FlushAsync should return nil
	if err := writer.WaitForFlush(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestManifestLicensesAtRef(t *testing.T) {
	writer, db := newTestBatchWriter(t)
	manifest := database.ManifestInfo{Path: "package.json", Ecosystem: "npm", Kind: "manifest"}
	committedAt := time.Now()

	writer.AddCommit(database.CommitInfo{SHA: "license-1", CommittedAt: committedAt}, false)
	writer.AddManifestLicense("license-1", manifest, database.ManifestLicenseInfo{
		Licenses: []string{"MIT", "ISC"},
	})
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush(first): %v", err)
	}
	branch, err := db.GetBranch("main")
	if err != nil {
		t.Fatalf("GetBranch: %v", err)
	}

	// Use a fresh writer to reproduce incremental indexing, where the same
	// logical path may be associated with a different manifests row.
	writer = database.NewBatchWriter(db)
	if err := writer.UseBranch(branch.ID); err != nil {
		t.Fatalf("UseBranch: %v", err)
	}
	writer.AddCommit(database.CommitInfo{SHA: "license-2", CommittedAt: committedAt.Add(time.Second)}, false)
	writer.AddManifestLicense("license-2", manifest, database.ManifestLicenseInfo{
		Licenses:    []string{"Apache-2.0"},
		LicenseFile: "LICENSE",
	})
	writer.AddCommit(database.CommitInfo{SHA: "license-3", CommittedAt: committedAt.Add(2 * time.Second)}, false)
	writer.AddManifestLicense("license-3", manifest, database.ManifestLicenseInfo{
		Licenses: []string{"Apache-2.0"},
		Removed:  true,
	})
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush(incremental): %v", err)
	}
	first, err := db.GetManifestLicensesAtRef("license-1", branch.ID)
	if err != nil {
		t.Fatalf("GetManifestLicensesAtRef(first): %v", err)
	}
	if len(first) != 1 || !slices.Equal(first[0].Licenses, []string{"MIT", "ISC"}) {
		t.Fatalf("first licenses = %+v", first)
	}

	second, err := db.GetManifestLicensesAtRef("license-2", branch.ID)
	if err != nil {
		t.Fatalf("GetManifestLicensesAtRef(second): %v", err)
	}
	if len(second) != 1 || !slices.Equal(second[0].Licenses, []string{"Apache-2.0"}) ||
		second[0].LicenseFile != "LICENSE" {
		t.Fatalf("second licenses = %+v", second)
	}

	third, err := db.GetManifestLicensesAtRef("license-3", branch.ID)
	if err != nil {
		t.Fatalf("GetManifestLicensesAtRef(third): %v", err)
	}
	if len(third) != 0 {
		t.Fatalf("third licenses = %+v, want none after removal", third)
	}
}
