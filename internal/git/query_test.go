package git_test

import (
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
)

const gemfileLockFixture = `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake

BUNDLED WITH
   2.5.0
`

const gemfileFixture = `source "https://rubygems.org"

gem "rake"
`

func TestIndexCommitSnapshotManifestKind(t *testing.T) {
	// IndexCommitSnapshot is the on-demand indexing path used by
	// `list --commit` when no snapshot exists for the requested commit.
	// It must record the manifest kind returned by the parser, not guess
	// from whether entries carry integrity hashes: Gemfile.lock has no
	// per-entry hashes without a CHECKSUMS section but is still a lockfile.
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "Gemfile", gemfileFixture)
	addFile(t, repoDir, "Gemfile.lock", gemfileLockFixture)
	sha := commit(t, repoDir, "add gems")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	defer func() { _ = db.Close() }()

	branch, err := db.GetOrCreateBranch("main")
	if err != nil {
		t.Fatalf("GetOrCreateBranch: %v", err)
	}

	if err := repo.IndexCommitSnapshot(db, branch.ID, sha); err != nil {
		t.Fatalf("IndexCommitSnapshot: %v", err)
	}

	want := map[string]string{
		"Gemfile":      "manifest",
		"Gemfile.lock": "lockfile",
	}

	rows, err := db.Query("SELECT path, kind FROM manifests")
	if err != nil {
		t.Fatalf("query manifests: %v", err)
	}
	defer func() { _ = rows.Close() }()

	got := map[string]string{}
	for rows.Next() {
		var path, kind string
		if err := rows.Scan(&path, &kind); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[path] = kind
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	for path, wantKind := range want {
		if got[path] != wantKind {
			t.Errorf("manifests.kind for %s = %q, want %q", path, got[path], wantKind)
		}
	}
}

// On an unindexed repo GetDependenciesWithDB indexes the commit itself, and
// the manifest row must carry the file's ecosystem, not the dependency's.
func TestGetDependenciesWithDBStoresManifestEcosystem(t *testing.T) {
	repoDir := createTestRepo(t)
	gitRun(t, repoDir, "config", "pkgs.ecosystems", "deno")
	addFile(t, repoDir, "deno.json", `{"imports": {"chalk": "npm:chalk@5.3.0"}}`)
	commit(t, repoDir, "Add deno.json")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}
	deps, db, err := repo.GetDependenciesWithDB("HEAD", "")
	if err != nil {
		t.Fatalf("GetDependenciesWithDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	if len(deps) != 1 || deps[0].Name != "chalk" || deps[0].Ecosystem != "npm" || deps[0].ManifestEcosystem != "deno" {
		t.Fatalf("deps = %+v, want chalk (npm) from a deno manifest", deps)
	}
	var ecosystem string
	if err := db.QueryRow("SELECT ecosystem FROM manifests WHERE path = 'deno.json'").Scan(&ecosystem); err != nil {
		t.Fatal(err)
	}
	if ecosystem != "deno" {
		t.Fatalf("manifests row for deno.json: ecosystem %q, want deno", ecosystem)
	}
}
