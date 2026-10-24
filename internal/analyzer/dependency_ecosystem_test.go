package analyzer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestMixedEcosystemWorkflowHistory(t *testing.T) {
	repoDir := createTestRepo(t)
	a := analyzer.New()
	var snapshot analyzer.Snapshot
	const path = ".github/workflows/fixture.yml"
	const workflow = `jobs:
  test:
    container: ghcr.io/example/job:1
    services:
      database:
        image: postgres:16
    steps:
      - uses: actions/checkout@v4
      - uses: docker://ghcr.io/example/step:2
`
	for _, stage := range []struct {
		name, content                 string
		wantChanges, wantDependencies int
	}{
		{"added", workflow, 4, 4},
		{"modified", strings.ReplaceAll(workflow, "example/job:1", "example/job:2"), 1, 4},
		{"removed", "", 4, 0},
	} {
		t.Run(stage.name, func(t *testing.T) {
			if stage.content == "" {
				if err := os.Remove(filepath.Join(repoDir, path)); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command("git", "add", "-u", "--", path)
				cmd.Dir = repoDir
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("stage deletion: %v\n%s", err, output)
				}
			} else {
				addFile(t, repoDir, path, stage.content)
			}
			sha := commit(t, repoDir, stage.name)
			repo := openRepo(t, repoDir)
			c, err := repo.CommitObject(*getCommit(t, sha))
			if err != nil {
				t.Fatal(err)
			}
			result, err := a.AnalyzeCommit(c, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || len(result.Changes) != stage.wantChanges {
				t.Fatalf("result=%+v, want %d changes", result, stage.wantChanges)
			}
			checkDependencyEcosystems(t, result.Changes)
			snapshot = result.Snapshot
			checkWorkflowDependencies(t, a, c, repoDir, snapshot, stage.wantDependencies)
		})
	}
}

func checkWorkflowDependencies(t *testing.T, a *analyzer.Analyzer, c *object.Commit, dir string, snapshot analyzer.Snapshot, want int) {
	t.Helper()
	for _, entry := range snapshot {
		if strings.HasPrefix(entry.PURL, "pkg:docker/") && entry.Ecosystem != "docker" {
			t.Errorf("snapshot entry=%+v, want docker", entry)
		}
	}
	atCommit, err := a.DependenciesAtCommit(c)
	if err != nil {
		t.Fatal(err)
	}
	checkDependencyEcosystems(t, atCommit)
	working, err := a.DependenciesInWorkingDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	checkDependencyEcosystems(t, working)
	if len(atCommit) != want || len(working) != want || len(snapshot) != want {
		t.Errorf("dependency counts: commit=%d working=%d snapshot=%d, want %d", len(atCommit), len(working), len(snapshot), want)
	}
}

func checkDependencyEcosystems(t *testing.T, deps []analyzer.Change) {
	t.Helper()
	for _, dep := range deps {
		want := "github-actions"
		if strings.HasPrefix(dep.PURL, "pkg:docker/") {
			want = "docker"
		}
		if dep.Ecosystem != want {
			t.Errorf("%s ecosystem=%q, want %q", dep.Name, dep.Ecosystem, want)
		}
	}
}
