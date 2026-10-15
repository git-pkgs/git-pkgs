package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	gitpkg "github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	gitgo "github.com/go-git/go-git/v5"
)

func indexProjectLicenseRepo(t *testing.T, repoDir string) (*gitpkg.Repository, *database.DB) {
	t.Helper()
	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Create(repo.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := indexer.New(repo, db, indexer.Options{Quiet: true}).Run(); err != nil {
		t.Fatal(err)
	}
	return repo, db
}

func TestProjectLicensesUseIndexedData(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT"}`, "Add manifest")
	commitSBOMFile(t, repository, repoDir, "nested/package.json", `{"name":"nested","license":"GPL-3.0-only"}`, "Add nested manifest")
	repo, db := indexProjectLicenseRepo(t, repoDir)
	// Use distinct indexed metadata to prove that the production command reads the table.
	if _, err := db.Exec(`UPDATE manifest_licenses SET licenses = '["BSD-3-Clause"]'
		WHERE manifest_id IN (SELECT id FROM manifests WHERE path = 'package.json')`); err != nil {
		t.Fatal(err)
	}
	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatal(err)
	}
	for _, branchName := range []string{"", branch.Name} {
		got, warnings, err := projectLicensesAtRevision(repo, db, "HEAD", branchName)
		if err != nil || len(warnings) != 0 || got.Expression != "BSD-3-Clause" {
			t.Fatalf("branch %q: licenses = %+v, warnings = %v, error = %v", branchName, got, warnings, err)
		}
	}
	if _, err := db.GetOrCreateBranch("unindexed"); err != nil {
		t.Fatal(err)
	}
	got, _, err := projectLicensesAtRevision(repo, db, "HEAD", "unindexed")
	if err != nil || got.Expression != "MIT" {
		t.Fatalf("unindexed branch: licenses = %+v, error = %v", got, err)
	}

	t.Chdir(repoDir)
	var output bytes.Buffer
	command := NewRootCmd()
	command.SetArgs([]string{"sbom", "--skip-enrichment", "--branch", branch.Name})
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Licenses []struct {
					Expression string `json:"expression"`
				} `json:"licenses"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(output.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	licenses := doc.Metadata.Component.Licenses
	if len(licenses) != 1 || licenses[0].Expression != "BSD-3-Clause" {
		t.Fatalf("SBOM root licenses = %+v", licenses)
	}
}

func TestProjectLicensesIndexedHistoryMatchesTree(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	first := commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT OR Apache-2.0"}`, "Add license")
	second := commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"Acme Terms"}`, "Change license")
	third := commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo"}`, "Remove license declaration")
	commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "original terms\n", "Add license text")
	fileRevision := commitSBOMFile(t, repository, repoDir, "Cargo.toml", "[package]\nname = 'demo'\nversion = '1.0.0'\nlicense-file = 'LICENSE.custom'\n", "Declare license file")
	updated := commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "updated terms\n", "Update license text only")
	empty := commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "\n", "Empty license text")
	missing := commitSBOMFile(t, repository, repoDir, "Cargo.toml", "[package]\nname = 'demo'\nversion = '1.0.0'\nlicense-file = 'LICENSE.missing'\n", "Declare missing file")
	repo, db := indexProjectLicenseRepo(t, repoDir)
	for _, revision := range []string{first.String(), second.String(), third.String(), fileRevision.String(), updated.String(), empty.String(), missing.String()} {
		t.Run(revision[:7], func(t *testing.T) {
			assertProjectLicenseCacheMatchesTree(t, repo, db, revision)
		})
	}
	// Databases indexed without license events must match tree parsing.
	if _, err := db.Exec("DELETE FROM manifest_licenses"); err != nil {
		t.Fatal(err)
	}
	assertProjectLicenseCacheMatchesTree(t, repo, db, first.String())
	assertProjectLicenseCacheMatchesTree(t, repo, db, fileRevision.String())
}

func TestProjectLicensesPartialIndex(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT"}`, "Add npm license")
	commitSBOMFile(t, repository, repoDir, "Cargo.toml", "[package]\nname = 'demo'\nversion = '1.0.0'\nlicense = 'Apache-2.0'\n", "Add Cargo license")
	repo, db := indexProjectLicenseRepo(t, repoDir)
	if _, err := db.Exec(`DELETE FROM manifest_licenses
		WHERE manifest_id IN (SELECT id FROM manifests WHERE path = 'Cargo.toml')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE manifest_licenses SET licenses = '["BSD-3-Clause"]'`); err != nil {
		t.Fatal(err)
	}
	got, warnings, err := projectLicensesAtRevision(repo, db, "HEAD", "")
	if err != nil || len(warnings) != 0 || got.Expression != "Apache-2.0 AND BSD-3-Clause" {
		t.Fatalf("partial index: licenses = %+v, warnings = %v, error = %v", got, warnings, err)
	}
}

func TestProjectLicensesChangedAfterIndexing(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT"}`, "Add license")
	repo, db := indexProjectLicenseRepo(t, repoDir)
	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatal(err)
	}
	changed := commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"Apache-2.0"}`, "Change license")
	if err := repo.IndexCommitSnapshot(db, branch.ID, changed.String()); err != nil {
		t.Fatal(err)
	}
	assertProjectLicenseCacheMatchesTree(t, repo, db, changed.String())
	removed := commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo"}`, "Remove license")
	if err := repo.IndexCommitSnapshot(db, branch.ID, removed.String()); err != nil {
		t.Fatal(err)
	}
	assertProjectLicenseCacheMatchesTree(t, repo, db, removed.String())
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Remove("package.json"); err != nil {
		t.Fatal(err)
	}
	deleted := commitSBOMFile(t, repository, repoDir, "README.md", "# Demo\n", "Delete manifest")
	if err := repo.IndexCommitSnapshot(db, branch.ID, deleted.String()); err != nil {
		t.Fatal(err)
	}
	assertProjectLicenseCacheMatchesTree(t, repo, db, deleted.String())
}

func TestIndexedProjectLicensesFiltersAndErrors(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT"}`, "Add manifest")
	commitSBOMFile(t, repository, repoDir, "nested/package.json", `{"name":"nested","license":"ISC"}`, "Add nested manifest")
	last := commitSBOMFile(t, repository, repoDir, "Cargo.toml", "[package]\nname = 'demo'\nversion = '1.0.0'\nlicense = 'Apache-2.0'\n", "Add Cargo manifest")
	repo, db := indexProjectLicenseRepo(t, repoDir)
	if _, err := db.Exec("UPDATE manifests SET kind = 'lockfile' WHERE path = 'Cargo.toml'"); err != nil {
		t.Fatal(err)
	}
	indexed, err := indexedProjectLicenses(db, last.String(), "")
	if err != nil || len(indexed) != 1 || indexed["package.json"].ManifestPath != "package.json" {
		t.Fatalf("indexed = %+v, error = %v", indexed, err)
	}
	if _, err := db.Exec("UPDATE manifest_licenses SET licenses = 'invalid JSON'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := projectLicensesAtRevision(repo, db, "HEAD", ""); err == nil || !strings.Contains(err.Error(), "querying indexed project licenses") {
		t.Fatalf("expected query error, got %v", err)
	}
}

func TestProjectLicensesOnDemandOnly(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{"name":"demo","license":"MIT"}`, "Add manifest")
	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	_, db, err := repo.GetDependenciesWithDB("HEAD", "")
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	assertProjectLicenseCacheMatchesTree(t, repo, db, "HEAD")
	// Uncommitted manifest changes must not override either source of committed metadata.
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(`{"license":"ISC"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _, err := projectLicensesAtRevision(repo, db, "HEAD", "")
	if err != nil || got.Expression != "MIT" {
		t.Fatalf("licenses = %+v, error = %v", got, err)
	}
}

func assertProjectLicenseCacheMatchesTree(t *testing.T, repo *gitpkg.Repository, db *database.DB, revision string) {
	t.Helper()
	want, wantWarnings, err := projectLicensesAtRevision(repo, nil, revision, "")
	if err != nil {
		t.Fatal(err)
	}
	got, warnings, err := projectLicensesAtRevision(repo, db, revision, "")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(warnings, wantWarnings) {
		t.Fatalf("licenses = %+v, warnings = %v; want %+v, %v", got, warnings, want, wantWarnings)
	}
}
