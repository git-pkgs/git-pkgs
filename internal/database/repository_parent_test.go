package database_test

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func createRepositoryParentTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Create(filepath.Join(t.TempDir(), "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRepositoryParentCacheRoundTrip(t *testing.T) {
	db := createRepositoryParentTestDB(t)
	parent := &database.RepositoryParent{
		FullName: "d3/d3", Evidence: "declared_fork",
		HostName: "GitHub", HostKind: "github", HostURL: "https://github.com",
	}
	if err := db.SavePackageEnrichment("pkg:npm/%40plotly/d3", "npm", "@plotly/d3", "3.8.2", "BSD-3-Clause", "", "ecosystems"); err != nil {
		t.Fatalf("SavePackageEnrichment: %v", err)
	}
	if err := db.SavePackageRepositoryParentBatch([]database.PackageRepositoryParentData{
		{PURL: "pkg:npm/%40plotly/d3", Ecosystem: "npm", Name: "@plotly/d3", Parent: parent},
		{PURL: "pkg:npm/lodash", Ecosystem: "npm", Name: "lodash"},
	}); err != nil {
		t.Fatalf("SavePackageRepositoryParentBatch: %v", err)
	}

	cached, err := db.GetCachedRepositoryParents(
		[]string{"pkg:npm/%40plotly/d3", "pkg:npm/lodash", "pkg:npm/uncached"}, time.Hour,
	)
	if err != nil {
		t.Fatalf("GetCachedRepositoryParents: %v", err)
	}
	if len(cached) != 2 {
		t.Fatalf("cached = %+v, want 2 entries", cached)
	}
	if got := cached["pkg:npm/%40plotly/d3"].Parent; !reflect.DeepEqual(got, parent) {
		t.Errorf("@plotly/d3 parent = %+v, want %+v", got, parent)
	}
	if lodash := cached["pkg:npm/lodash"]; lodash == nil || lodash.Parent != nil {
		t.Errorf("lodash = %+v, want a cached lookup with no parent", lodash)
	}

	// Saving the parent must keep the license cached by SavePackageEnrichment.
	packages, err := db.GetCachedPackages([]string{"pkg:npm/%40plotly/d3"}, time.Hour)
	if err != nil {
		t.Fatalf("GetCachedPackages: %v", err)
	}
	if got := packages["pkg:npm/%40plotly/d3"]; got == nil || got.License != "BSD-3-Clause" {
		t.Errorf("cached package = %+v, want BSD-3-Clause license", got)
	}
	// A package row cached without a parent lookup is not a parent cache hit.
	if err := db.SavePackageEnrichment("pkg:npm/is-odd", "npm", "is-odd", "3.0.1", "MIT", "", "ecosystems"); err != nil {
		t.Fatalf("SavePackageEnrichment: %v", err)
	}
	cached, err = db.GetCachedRepositoryParents([]string{"pkg:npm/is-odd"}, time.Hour)
	if err != nil || len(cached) != 0 {
		t.Errorf("is-odd cached = %+v, error = %v, want no entry", cached, err)
	}
}

func TestRepositoryParentCacheExcludesStaleEntries(t *testing.T) {
	db := createRepositoryParentTestDB(t)
	if err := db.SavePackageRepositoryParentBatch([]database.PackageRepositoryParentData{
		{PURL: "pkg:npm/lodash", Ecosystem: "npm", Name: "lodash"},
	}); err != nil {
		t.Fatalf("SavePackageRepositoryParentBatch: %v", err)
	}
	stale := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec("UPDATE packages SET repository_parent_synced_at = ?", stale); err != nil {
		t.Fatal(err)
	}
	cached, err := db.GetCachedRepositoryParents([]string{"pkg:npm/lodash"}, 24*time.Hour)
	if err != nil || len(cached) != 0 {
		t.Errorf("cached = %+v, error = %v, want no fresh entries", cached, err)
	}
}

func TestRepositoryParentCacheSkipsUndecodableEntries(t *testing.T) {
	db := createRepositoryParentTestDB(t)
	if err := db.SavePackageRepositoryParentBatch([]database.PackageRepositoryParentData{
		{PURL: "pkg:npm/lodash", Ecosystem: "npm", Name: "lodash"},
	}); err != nil {
		t.Fatalf("SavePackageRepositoryParentBatch: %v", err)
	}
	if _, err := db.Exec("UPDATE packages SET repository_parent = 'not json'"); err != nil {
		t.Fatal(err)
	}
	cached, err := db.GetCachedRepositoryParents([]string{"pkg:npm/lodash"}, time.Hour)
	if err != nil || len(cached) != 0 {
		t.Errorf("cached = %+v, error = %v, want the entry treated as uncached", cached, err)
	}
}

func TestHasRepositoryParentCache(t *testing.T) {
	db := createRepositoryParentTestDB(t)
	if ok, err := db.HasRepositoryParentCache(); err != nil || !ok {
		t.Fatalf("current schema: HasRepositoryParentCache() = %v, %v, want true", ok, err)
	}
	for _, statement := range []string{
		"ALTER TABLE packages DROP COLUMN repository_parent",
		"ALTER TABLE packages DROP COLUMN repository_parent_synced_at",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if ok, err := db.HasRepositoryParentCache(); err != nil || ok {
		t.Fatalf("schema 16: HasRepositoryParentCache() = %v, %v, want false", ok, err)
	}
}
