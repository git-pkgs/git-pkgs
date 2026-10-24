package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

const mixedWorkflow = `name: fixture
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container: ghcr.io/example/job:1
    services:
      database:
        image: postgres:16
    steps:
      - uses: actions/checkout@v4
      - uses: docker://ghcr.io/example/step:2
`

func TestInitPreservesDependencyEcosystems(t *testing.T) {
	for _, test := range []struct {
		name, key, value string
		wantTotal        int
	}{
		{name: "all ecosystems", wantTotal: 4},
		{name: "allow Docker", key: "pkgs.ecosystems", value: "docker", wantTotal: 3},
		{name: "ignore actions", key: "pkgs.ignoredEcosystems", value: "github-actions", wantTotal: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, ".github/workflows/fixture.yml", mixedWorkflow, "Add workflow")
			if test.key != "" {
				setGitConfig(t, repoDir, test.key, test.value)
			}
			defer chdir(t, repoDir)()
			if out, stderr, err := runCmd(t, "init", "--no-hooks"); err != nil {
				t.Fatalf("init: %v\n%s\n%s", err, out, stderr)
			}
			checkListedEcosystems(t, test.wantTotal)
			checkListedEcosystems(t, 3, "--ecosystem", "docker")
		})
	}
}

func checkListedEcosystems(t *testing.T, want int, flags ...string) {
	t.Helper()
	args := append([]string{"list", "--format", "json"}, flags...)
	out, stderr, err := runCmd(t, args...)
	if err != nil {
		t.Fatalf("list: %v\n%s", err, stderr)
	}
	var deps []database.Dependency
	if err := json.Unmarshal([]byte(out), &deps); err != nil {
		t.Fatal(err)
	}
	if len(deps) != want {
		t.Errorf("list %v: got %d dependencies, want %d: %s", flags, len(deps), want, out)
	}
	for _, dep := range deps {
		wantEcosystem := "github-actions"
		if strings.HasPrefix(dep.PURL, "pkg:docker/") {
			wantEcosystem = "docker"
		}
		if dep.Ecosystem != wantEcosystem {
			t.Errorf("%s ecosystem=%q, want %q", dep.Name, dep.Ecosystem, wantEcosystem)
		}
	}
}

func TestDiffFilePreservesDependencyEcosystems(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "before.yml")
	to := filepath.Join(dir, "after.yml")
	if err := os.WriteFile(from, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, []byte(mixedWorkflow), 0600); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := runCmd(t, "diff-file", from, to, "--filename", ".github/workflows/fixture.yml", "--format", "json")
	if err != nil {
		t.Fatalf("diff-file: %v\n%s", err, stderr)
	}
	var result struct {
		Added []struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"added"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 4 {
		t.Fatalf("got %d additions, want 4: %s", len(result.Added), out)
	}
	for _, dep := range result.Added {
		want := "github-actions"
		if strings.HasPrefix(dep.Name, "docker://") {
			want = "docker"
		}
		if dep.Ecosystem != want {
			t.Errorf("%s ecosystem=%q, want %q", dep.Name, dep.Ecosystem, want)
		}
	}
}
