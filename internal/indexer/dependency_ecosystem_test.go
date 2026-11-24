package indexer_test

import (
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/config"
	"github.com/git-pkgs/git-pkgs/internal/database"
	gitpkg "github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
)

// An incremental run filters the restored snapshot by the ecosystem of the
// file each entry came from, as the analyzer does: the npm import in deno.json
// stays when only deno is enabled, and package.json's entries go.
func TestIncrementalRestoreFiltersByManifestEcosystem(t *testing.T) {
	deno := config.NewEcosystemFilter([]string{"deno"}, nil)
	for _, tc := range []struct {
		name string
		full config.EcosystemFilter
	}{
		{"deno on both runs", deno},
		{"deno enabled after the full run", config.EcosystemFilter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, "deno.json",
				`{"imports": {"chalk": "npm:chalk@5.3.0", "path": "jsr:@std/path@^1.0.0"}}`, "Add deno.json")
			addFileAndCommit(t, repoDir, "package.json",
				`{"dependencies": {"lodash": "^4.17.21"}}`, "Add package.json")
			addFileAndCommit(t, repoDir, "app/deno.json",
				`{"imports": {"fs": "jsr:@std/fs@^1.0.0"}}`, "Add app/deno.json")

			db, err := database.Create(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			run := func(incremental bool, filter config.EcosystemFilter) {
				t.Helper()
				repo, err := gitpkg.OpenRepository(repoDir)
				if err != nil {
					t.Fatal(err)
				}
				idx := indexer.New(repo, db, indexer.Options{
					Quiet: true, Incremental: incremental, SnapshotInterval: 1, EcosystemFilter: filter,
				})
				if _, err := idx.Run(); err != nil {
					t.Fatalf("index (incremental %v): %v", incremental, err)
				}
			}

			run(false, tc.full)
			var manifestEcosystem string
			if err := db.QueryRow("SELECT ecosystem FROM manifests WHERE path = 'deno.json'").Scan(&manifestEcosystem); err != nil {
				t.Fatal(err)
			}
			if manifestEcosystem != "deno" {
				t.Fatalf("manifests row for deno.json: ecosystem %q, want deno", manifestEcosystem)
			}

			addFileAndCommit(t, repoDir, "app/deno.json",
				`{"imports": {"fs": "jsr:@std/fs@^1.1.0"}}`, "Bump @std/fs")
			run(true, deno)

			branch, err := db.GetBranch("main")
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := db.GetLastSnapshot(branch.ID)
			if err != nil {
				t.Fatal(err)
			}
			got := make(map[string]string)
			for _, info := range snapshot {
				got[info.ManifestPath+" "+info.Name] = info.Ecosystem
			}
			want := map[string]string{
				"deno.json chalk":       "npm",
				"deno.json @std/path":   "deno",
				"app/deno.json @std/fs": "deno",
			}
			if len(got) != len(want) {
				t.Fatalf("snapshot after the incremental run = %v, want %v", got, want)
			}
			for key, eco := range want {
				if got[key] != eco {
					t.Fatalf("snapshot after the incremental run = %v, want %v", got, want)
				}
			}
		})
	}
}
