package database_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/database"
	idb "github.com/git-pkgs/git-pkgs/internal/database"
)

// populatedDB creates a database with sample data for query testing.
// Returns the path and the branch ID.
func populatedDB(t *testing.T) (string, int64) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := idb.Create(dbPath)
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}

	w, err := idb.NewWriter(db)
	if err != nil {
		t.Fatalf("creating writer: %v", err)
	}

	err = w.CreateBranch("main")
	if err != nil {
		t.Fatalf("creating branch: %v", err)
	}

	branch, err := db.GetBranch("main")
	if err != nil {
		t.Fatalf("getting branch: %v", err)
	}
	branchID := branch.ID
	if err := w.UseBranch(branchID); err != nil {
		t.Fatalf("using branch: %v", err)
	}

	// Commit 1: adds two dependencies
	commit1 := idb.CommitInfo{
		SHA:         "aaa111",
		Message:     "Initial deps",
		AuthorName:  "Alice",
		AuthorEmail: "alice@example.com",
		CommittedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	commitID1, _, err := w.InsertCommit(commit1, true)
	if err != nil {
		t.Fatalf("inserting commit 1: %v", err)
	}

	manifest := idb.ManifestInfo{Path: "go.mod", Ecosystem: "golang", Kind: "manifest"}

	err = w.InsertChange(commitID1, manifest, idb.ChangeInfo{
		Name: "github.com/foo/bar", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/foo/bar", ChangeType: "added",
		Requirement: "v1.0.0", DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting change: %v", err)
	}
	err = w.InsertChange(commitID1, manifest, idb.ChangeInfo{
		Name: "github.com/baz/qux", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/baz/qux", ChangeType: "added",
		Requirement: "v2.0.0", DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting change: %v", err)
	}

	err = w.InsertSnapshot(commitID1, manifest, idb.SnapshotInfo{
		Name: "github.com/foo/bar", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/foo/bar", Requirement: "v1.0.0",
		DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting snapshot: %v", err)
	}
	err = w.InsertSnapshot(commitID1, manifest, idb.SnapshotInfo{
		Name: "github.com/baz/qux", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/baz/qux", Requirement: "v2.0.0",
		DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting snapshot: %v", err)
	}

	// Commit 2: modifies one dependency
	commit2 := idb.CommitInfo{
		SHA:         "bbb222",
		Message:     "Bump foo/bar",
		AuthorName:  "Bob",
		AuthorEmail: "bob@example.com",
		CommittedAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	commitID2, _, err := w.InsertCommit(commit2, true)
	if err != nil {
		t.Fatalf("inserting commit 2: %v", err)
	}

	err = w.InsertChange(commitID2, manifest, idb.ChangeInfo{
		Name: "github.com/foo/bar", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/foo/bar", ChangeType: "modified",
		Requirement: "v1.1.0", PreviousRequirement: "v1.0.0",
		DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting change: %v", err)
	}

	err = w.InsertSnapshot(commitID2, manifest, idb.SnapshotInfo{
		Name: "github.com/foo/bar", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/foo/bar", Requirement: "v1.1.0",
		DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting snapshot: %v", err)
	}
	err = w.InsertSnapshot(commitID2, manifest, idb.SnapshotInfo{
		Name: "github.com/baz/qux", Ecosystem: "golang",
		PURL: "pkg:golang/github.com/baz/qux", Requirement: "v2.0.0",
		DependencyType: "runtime",
	})
	if err != nil {
		t.Fatalf("inserting snapshot: %v", err)
	}

	err = w.UpdateBranchLastSHA("bbb222")
	if err != nil {
		t.Fatalf("updating branch: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("closing writer: %v", err)
	}

	// Add a note
	err = db.InsertNote(idb.Note{
		PURL:      "pkg:golang/github.com/foo/bar",
		Namespace: "license",
		Origin:    "test",
		Message:   "MIT license",
		Metadata:  map[string]string{"source": "manual"},
	})
	if err != nil {
		t.Fatalf("inserting note: %v", err)
	}

	// Add a vulnerability
	err = db.InsertVulnerability(idb.Vulnerability{
		ID:          "GHSA-1234",
		Severity:    "high",
		CVSSScore:   8.5,
		Summary:     "Test vulnerability",
		PublishedAt: "2025-01-15",
		ModifiedAt:  "2025-01-15",
		FetchedAt:   "2025-01-20",
	})
	if err != nil {
		t.Fatalf("inserting vulnerability: %v", err)
	}

	err = db.InsertVulnerabilityPackage(idb.VulnerabilityPackage{
		VulnerabilityID:  "GHSA-1234",
		Ecosystem:        "golang",
		PackageName:      "github.com/foo/bar",
		AffectedVersions: "vers:golang/<1.2.0",
		FixedVersions:    "1.2.0",
	})
	if err != nil {
		t.Fatalf("inserting vuln package: %v", err)
	}

	_ = db.Close()
	return dbPath, branchID
}

func TestUpsertAndGetPackage(t *testing.T) {
	dbPath := createTestDB(t)
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	pkg := &database.Package{
		PURL:      "pkg:npm/lodash",
		Ecosystem: "npm",
		Name:      "lodash",
	}
	pkg.LatestVersion.String = "4.17.21"
	pkg.LatestVersion.Valid = true
	pkg.License.String = "MIT"
	pkg.License.Valid = true

	err = db.UpsertPackage(pkg)
	if err != nil {
		t.Fatalf("upserting package: %v", err)
	}

	// Get by PURL
	got, err := db.GetPackageByPURL("pkg:npm/lodash")
	if err != nil {
		t.Fatalf("getting package by purl: %v", err)
	}
	if got == nil {
		t.Fatal("expected package, got nil")
	}
	if got.Name != "lodash" {
		t.Errorf("name = %q, want %q", got.Name, "lodash")
	}
	if got.LatestVersion.String != "4.17.21" {
		t.Errorf("latest_version = %q, want %q", got.LatestVersion.String, "4.17.21")
	}

	// Get by ecosystem/name
	got, err = db.GetPackageByEcosystemName("npm", "lodash")
	if err != nil {
		t.Fatalf("getting package by ecosystem/name: %v", err)
	}
	if got == nil {
		t.Fatal("expected package, got nil")
	}
	if got.PURL != "pkg:npm/lodash" {
		t.Errorf("purl = %q, want %q", got.PURL, "pkg:npm/lodash")
	}

	// Upsert updates existing
	pkg.LatestVersion.String = "4.18.0"
	err = db.UpsertPackage(pkg)
	if err != nil {
		t.Fatalf("upserting package: %v", err)
	}

	got, err = db.GetPackageByPURL("pkg:npm/lodash")
	if err != nil {
		t.Fatalf("getting package: %v", err)
	}
	if got.LatestVersion.String != "4.18.0" {
		t.Errorf("latest_version after upsert = %q, want %q", got.LatestVersion.String, "4.18.0")
	}

	// Non-existent returns nil
	got, err = db.GetPackageByPURL("pkg:npm/nonexistent")
	if err != nil {
		t.Fatalf("getting nonexistent: %v", err)
	}
	if got != nil {
		t.Error("expected nil for nonexistent package")
	}
}

func TestUpsertAndGetVersion(t *testing.T) {
	dbPath := createTestDB(t)
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Insert parent package first
	pkg := &database.Package{
		PURL:      "pkg:npm/lodash",
		Ecosystem: "npm",
		Name:      "lodash",
	}
	if err := db.UpsertPackage(pkg); err != nil {
		t.Fatalf("upserting package: %v", err)
	}

	v := &database.Version{
		PURL:        "pkg:npm/lodash@4.17.21",
		PackagePURL: "pkg:npm/lodash",
	}
	v.License.String = "MIT"
	v.License.Valid = true

	err = db.UpsertVersion(v)
	if err != nil {
		t.Fatalf("upserting version: %v", err)
	}

	// Get by PURL
	got, err := db.GetVersionByPURL("pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("getting version: %v", err)
	}
	if got == nil {
		t.Fatal("expected version, got nil")
	}
	if got.PackagePURL != "pkg:npm/lodash" {
		t.Errorf("package_purl = %q, want %q", got.PackagePURL, "pkg:npm/lodash")
	}
	if got.VersionString() != "4.17.21" {
		t.Errorf("VersionString() = %q, want %q", got.VersionString(), "4.17.21")
	}

	// Add another version
	v2 := &database.Version{
		PURL:        "pkg:npm/lodash@4.18.0",
		PackagePURL: "pkg:npm/lodash",
	}
	if err := db.UpsertVersion(v2); err != nil {
		t.Fatalf("upserting version: %v", err)
	}

	// Get all versions for package
	versions, err := db.GetVersionsByPackagePURL("pkg:npm/lodash")
	if err != nil {
		t.Fatalf("getting versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("got %d versions, want 2", len(versions))
	}
}

func TestGetBranch(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	branch, err := db.GetBranch("main")
	if err != nil {
		t.Fatalf("getting branch: %v", err)
	}
	if branch.Name != "main" {
		t.Errorf("got branch name %q, want %q", branch.Name, "main")
	}
	if branch.LastAnalyzedSHA != "bbb222" {
		t.Errorf("got last SHA %q, want %q", branch.LastAnalyzedSHA, "bbb222")
	}
}

func TestGetDefaultBranch(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("getting default branch: %v", err)
	}
	if branch.Name != "main" {
		t.Errorf("got branch name %q, want %q", branch.Name, "main")
	}
}

func TestGetBranches(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	branches, err := db.GetBranches()
	if err != nil {
		t.Fatalf("getting branches: %v", err)
	}
	if len(branches) != 1 {
		t.Fatalf("got %d branches, want 1", len(branches))
	}
	if branches[0].CommitCount != 2 {
		t.Errorf("got commit count %d, want 2", branches[0].CommitCount)
	}
}

func TestGetLatestDependencies(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	deps, err := db.GetLatestDependencies(branchID)
	if err != nil {
		t.Fatalf("getting dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d dependencies, want 2", len(deps))
	}

	// foo/bar should have been bumped to v1.1.0
	for _, d := range deps {
		if d.Name == "github.com/foo/bar" && d.Requirement != "v1.1.0" {
			t.Errorf("foo/bar requirement = %q, want %q", d.Requirement, "v1.1.0")
		}
		if d.Name == "github.com/baz/qux" && d.Requirement != "v2.0.0" {
			t.Errorf("baz/qux requirement = %q, want %q", d.Requirement, "v2.0.0")
		}
	}
}

func TestGetDependenciesAtCommit(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	deps, err := db.GetDependenciesAtCommit("aaa111")
	if err != nil {
		t.Fatalf("getting dependencies: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("got %d dependencies, want 2", len(deps))
	}

	for _, d := range deps {
		if d.Name == "github.com/foo/bar" && d.Requirement != "v1.0.0" {
			t.Errorf("foo/bar at commit 1 requirement = %q, want %q", d.Requirement, "v1.0.0")
		}
	}
}

func TestHasSnapshotForCommit(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	has, err := db.HasSnapshotForCommit("aaa111")
	if err != nil {
		t.Fatalf("checking snapshot: %v", err)
	}
	if !has {
		t.Error("expected snapshot to exist for aaa111")
	}

	has, err = db.HasSnapshotForCommit("nonexistent")
	if err != nil {
		t.Fatalf("checking snapshot: %v", err)
	}
	if has {
		t.Error("expected no snapshot for nonexistent commit")
	}
}

func TestGetCommitsWithChanges(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	commits, err := db.GetCommitsWithChanges(database.LogOptions{BranchID: branchID})
	if err != nil {
		t.Fatalf("getting commits: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("got %d commits, want 2", len(commits))
	}
	// Most recent first
	if commits[0].SHA != "bbb222" {
		t.Errorf("first commit SHA = %q, want %q", commits[0].SHA, "bbb222")
	}
	if len(commits[0].Changes) != 1 {
		t.Errorf("first commit has %d changes, want 1", len(commits[0].Changes))
	}
	if len(commits[1].Changes) != 2 {
		t.Errorf("second commit has %d changes, want 2", len(commits[1].Changes))
	}
}

func TestGetChangesForCommit(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	changes, err := db.GetChangesForCommit("bbb222")
	if err != nil {
		t.Fatalf("getting changes: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(changes))
	}
	if changes[0].ChangeType != "modified" {
		t.Errorf("change type = %q, want %q", changes[0].ChangeType, "modified")
	}
	if changes[0].PreviousRequirement != "v1.0.0" {
		t.Errorf("previous requirement = %q, want %q", changes[0].PreviousRequirement, "v1.0.0")
	}
}

func TestGetPackageHistory(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	entries, err := db.GetPackageHistory(database.HistoryOptions{
		BranchID:    branchID,
		PackageName: "foo/bar",
	})
	if err != nil {
		t.Fatalf("getting history: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	// Oldest first
	if entries[0].ChangeType != "added" {
		t.Errorf("first entry change type = %q, want %q", entries[0].ChangeType, "added")
	}
	if entries[1].ChangeType != "modified" {
		t.Errorf("second entry change type = %q, want %q", entries[1].ChangeType, "modified")
	}
}

func TestGetStats(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	stats, err := db.GetStats(database.StatsOptions{BranchID: branchID})
	if err != nil {
		t.Fatalf("getting stats: %v", err)
	}
	if stats.Branch != "main" {
		t.Errorf("branch = %q, want %q", stats.Branch, "main")
	}
	if stats.CommitsAnalyzed != 2 {
		t.Errorf("commits analyzed = %d, want 2", stats.CommitsAnalyzed)
	}
	if stats.CommitsWithChanges != 2 {
		t.Errorf("commits with changes = %d, want 2", stats.CommitsWithChanges)
	}
	if stats.TotalChanges != 3 {
		t.Errorf("total changes = %d, want 3", stats.TotalChanges)
	}
}

func TestGetAuthorStats(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	stats, err := db.GetAuthorStats(database.StatsOptions{BranchID: branchID})
	if err != nil {
		t.Fatalf("getting author stats: %v", err)
	}
	if len(stats) != 2 {
		t.Fatalf("got %d authors, want 2", len(stats))
	}
}

func TestSearchDependencies(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	results, err := db.SearchDependencies(branchID, "foo", "", false)
	if err != nil {
		t.Fatalf("searching dependencies: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Name != "github.com/foo/bar" {
		t.Errorf("result name = %q, want %q", results[0].Name, "github.com/foo/bar")
	}
}

func TestGetWhy(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	result, err := db.GetWhy(branchID, "github.com/foo/bar", "golang")
	if err != nil {
		t.Fatalf("getting why: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.SHA != "aaa111" {
		t.Errorf("SHA = %q, want %q", result.SHA, "aaa111")
	}
	if result.AuthorName != "Alice" {
		t.Errorf("author = %q, want %q", result.AuthorName, "Alice")
	}
}

func TestGetBlame(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	entries, err := db.GetBlame(branchID, "")
	if err != nil {
		t.Fatalf("getting blame: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
}

func TestGetDatabaseInfo(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	info, err := db.GetDatabaseInfo()
	if err != nil {
		t.Fatalf("getting database info: %v", err)
	}
	if info.SchemaVersion != database.SchemaVersion {
		t.Errorf("schema version = %d, want %d", info.SchemaVersion, database.SchemaVersion)
	}
	if info.BranchName != "main" {
		t.Errorf("branch = %q, want %q", info.BranchName, "main")
	}
	if info.RowCounts["commits"] != 2 {
		t.Errorf("commits row count = %d, want 2", info.RowCounts["commits"])
	}
}

func TestGetNote(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	note, err := db.GetNote("pkg:golang/github.com/foo/bar", "license")
	if err != nil {
		t.Fatalf("getting note: %v", err)
	}
	if note == nil {
		t.Fatal("expected note, got nil")
	}
	if note.Message != "MIT license" {
		t.Errorf("message = %q, want %q", note.Message, "MIT license")
	}
	if note.Metadata["source"] != "manual" {
		t.Errorf("metadata source = %q, want %q", note.Metadata["source"], "manual")
	}
}

func TestListNotes(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	notes, err := db.ListNotes("license", "")
	if err != nil {
		t.Fatalf("listing notes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes, want 1", len(notes))
	}
}

func TestListNoteNamespaces(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	namespaces, err := db.ListNoteNamespaces("")
	if err != nil {
		t.Fatalf("listing namespaces: %v", err)
	}
	if len(namespaces) != 1 {
		t.Fatalf("got %d namespaces, want 1", len(namespaces))
	}
	if namespaces[0].Namespace != "license" {
		t.Errorf("namespace = %q, want %q", namespaces[0].Namespace, "license")
	}
}

func TestGetVulnerabilitiesForPackage(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	vulns, err := db.GetVulnerabilitiesForPackage("golang", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("getting vulnerabilities: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}
	if vulns[0].ID != "GHSA-1234" {
		t.Errorf("vuln ID = %q, want %q", vulns[0].ID, "GHSA-1234")
	}
	if vulns[0].Severity != "high" {
		t.Errorf("severity = %q, want %q", vulns[0].Severity, "high")
	}
}

func TestGetVulnerabilityPackageInfo(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	vp, err := db.GetVulnerabilityPackageInfo("GHSA-1234", "golang", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("getting vuln package info: %v", err)
	}
	if vp == nil {
		t.Fatal("expected result, got nil")
	}
	if vp.AffectedVersions != "vers:golang/<1.2.0" {
		t.Errorf("affected versions = %q, want %q", vp.AffectedVersions, "vers:golang/<1.2.0")
	}
}

func TestGetStoredVulnCount(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	count, err := db.GetStoredVulnCount("golang", "github.com/foo/bar")
	if err != nil {
		t.Fatalf("getting vuln count: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}

func TestGetVulnerabilityStats(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	stats, err := db.GetVulnerabilityStats(branchID)
	if err != nil {
		t.Fatalf("getting vuln stats: %v", err)
	}
	if stats["high"] != 1 {
		t.Errorf("high severity count = %d, want 1", stats["high"])
	}
}

func TestGetMaxPosition(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	pos, err := db.GetMaxPosition(branchID)
	if err != nil {
		t.Fatalf("getting max position: %v", err)
	}
	if pos != 2 {
		t.Errorf("max position = %d, want 2", pos)
	}
}

func TestGetCommitID(t *testing.T) {
	dbPath, _ := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	id, err := db.GetCommitID("aaa111")
	if err != nil {
		t.Fatalf("getting commit ID: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero commit ID")
	}
}

func TestGetCommitPosition(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	pos, err := db.GetCommitPosition("aaa111", branchID)
	if err != nil {
		t.Fatalf("getting position: %v", err)
	}
	if pos != 1 {
		t.Errorf("position = %d, want 1", pos)
	}
}

func TestGetCommitAtPosition(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	sha, err := db.GetCommitAtPosition(2, branchID)
	if err != nil {
		t.Fatalf("getting commit at position: %v", err)
	}
	if sha != "bbb222" {
		t.Errorf("SHA = %q, want %q", sha, "bbb222")
	}
}

func TestGetBisectCandidates(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	candidates, err := db.GetBisectCandidates(database.BisectOptions{
		BranchID: branchID,
		StartSHA: "aaa111",
		EndSHA:   "bbb222",
	})
	if err != nil {
		t.Fatalf("getting bisect candidates: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(candidates))
	}
	if candidates[0].SHA != "bbb222" {
		t.Errorf("candidate SHA = %q, want %q", candidates[0].SHA, "bbb222")
	}
}

func TestGetLastSnapshot(t *testing.T) {
	dbPath, branchID := populatedDB(t)
	db, err := database.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	snapshot, err := db.GetLastSnapshot(branchID)
	if err != nil {
		t.Fatalf("getting last snapshot: %v", err)
	}
	if len(snapshot) != 2 {
		t.Fatalf("got %d snapshot entries, want 2", len(snapshot))
	}
}
