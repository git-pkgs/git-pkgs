package cmd_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// With only deno enabled, the npm imports in deno.json and deno.lock are
// indexed, so every command that reads the index has to show them, while
// package.json stays out.
func TestEcosystemConfigKeepsManifestDependencies(t *testing.T) {
	repoDir := createTestRepo(t)
	setGitConfig(t, repoDir, "pkgs.ecosystems", "deno")
	denoJSON := func(chalk string) string {
		return `{"imports": {"chalk": "npm:chalk@` + chalk + `", "path": "jsr:@std/path@^1.0.0"}}`
	}
	denoLock := func(chalk string) string {
		return `{"version": "4", "jsr": {"@std/path@1.0.0": {"integrity": "sha256-b"}}, "npm": {"chalk@` + chalk + `": {"integrity": "sha512-` + chalk + `"}}}`
	}
	addFileAndCommit(t, repoDir, "deno.json", denoJSON("5.3.0"), "Add deno.json")
	addFileAndCommit(t, repoDir, "deno.lock", denoLock("5.3.0"), "Add deno.lock")
	addFileAndCommit(t, repoDir, "package.json", `{"dependencies": {"lodash": "^4.17.21"}}`, "Add package.json")
	// These two commits change only npm dependencies, inside deno files.
	addFileAndCommit(t, repoDir, "deno.json", denoJSON("5.4.0"), "Bump chalk")
	addFileAndCommit(t, repoDir, "deno.lock", denoLock("5.4.0"), "Bump chalk in deno.lock")

	cleanup := chdir(t, repoDir)
	defer cleanup()
	if _, stderr, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}

	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"list"}, []string{"deno.json (deno):", "deno.lock (deno):", "chalk 5.4.0", "@std/path"}},
		{[]string{"tree"}, []string{"chalk 5.4.0"}},
		{[]string{"history"}, []string{"Package: chalk (npm)"}},
		{[]string{"history", "chalk"}, []string{"Updated 5.3.0 -> 5.4.0"}},
		{[]string{"log"}, []string{"Bump chalk in deno.lock", "Changes: ~1", "Changes: +2"}},
		{[]string{"blame"}, []string{"chalk"}},
		{[]string{"why", "chalk"}, []string{"Ecosystem: npm"}},
		{[]string{"stale"}, []string{"chalk"}},
		{[]string{"stats"}, []string{
			"Commits with changes: 4", "Total: 4", "npm: 2", "Total changes: 6", "modified: 2",
			"chalk: 4 changes", "Test User: 6 changes",
		}},
		{[]string{"stats", "--by-author"}, []string{"Commits: 4", "Changes: 6 total"}},
		{[]string{"show", "HEAD~4"}, []string{"+ chalk 5.3.0"}},
		{[]string{"info", "--ecosystems"}, []string{"deno: 3 dependencies", "npm: 3 dependencies"}},
		{[]string{"search", "chalk"}, []string{"chalk  5.4.0  (npm)"}},
		{[]string{"urls", "chalk"}, []string{"pkg:npm/chalk@5.4.0"}},
		// Last, since it checks out a commit.
		{[]string{"bisect", "start", "HEAD", "HEAD~4"}, []string{"2 dependency changes left"}},
	} {
		out, stderr, err := runCmd(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", tc.args, err, stderr)
		}
		for _, want := range tc.want {
			if !strings.Contains(out, want) {
				t.Errorf("%v: missing %q in:\n%s", tc.args, want, out)
			}
		}
		if strings.Contains(out, "lodash") || strings.Contains(out, "package.json") {
			t.Errorf("%v: package.json passed the filter:\n%s", tc.args, out)
		}
	}

	// --ecosystem still matches the dependency's own ecosystem.
	out, _, err := runCmd(t, "list", "--ecosystem", "npm")
	if err != nil || !strings.Contains(out, "chalk") || strings.Contains(out, "@std/path") {
		t.Errorf("list --ecosystem npm: %v\n%s", err, out)
	}
}

// Without init, show analyzes the commit itself and list indexes it on
// demand. The header names the file's ecosystem even when every dependency
// in it is npm.
func TestListUnindexedNPMOnlyDenoManifest(t *testing.T) {
	repoDir := createTestRepo(t)
	setGitConfig(t, repoDir, "pkgs.ecosystems", "deno")
	addFileAndCommit(t, repoDir, "deno.json", `{"imports": {"chalk": "npm:chalk@5.3.0"}}`, "Add deno.json")

	cleanup := chdir(t, repoDir)
	defer cleanup()
	out, stderr, err := runCmd(t, "show", "HEAD")
	if err != nil || !strings.Contains(out, "+ chalk 5.3.0") {
		t.Errorf("show: %v\n%s%s", err, out, stderr)
	}
	out, stderr, err = runCmd(t, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, stderr)
	}
	if !strings.Contains(out, "deno.json (deno):") || !strings.Contains(out, "chalk 5.3.0") {
		t.Errorf("list:\n%s", out)
	}
}

// One commit adds deno.json and package.json. log and show list that
// commit's changes, and with only deno enabled just deno.json's may pass:
// when show analyzes the commit itself, and when the index was built before
// the filter was set.
func TestEcosystemConfigFiltersMixedCommit(t *testing.T) {
	repoDir := createTestRepo(t)
	for path, content := range map[string]string{
		"deno.json":    `{"imports": {"chalk": "npm:chalk@5.3.0"}}`,
		"package.json": `{"dependencies": {"lodash": "^4.17.21"}}`,
	} {
		if err := os.WriteFile(filepath.Join(repoDir, path), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "."}, {"commit", "-m", "Add deno.json and package.json"}} {
		gitCmd := exec.Command("git", args...)
		gitCmd.Dir = repoDir
		if out, err := gitCmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	cleanup := chdir(t, repoDir)
	defer cleanup()
	check := func(args []string, want string) {
		t.Helper()
		out, stderr, err := runCmd(t, args...)
		if err != nil || !strings.Contains(out, want) || strings.Contains(out, "lodash") {
			t.Errorf("%v: want %q and no lodash: %v\n%s%s", args, want, err, out, stderr)
		}
	}
	setGitConfig(t, repoDir, "pkgs.ecosystems", "deno")
	check([]string{"show", "HEAD"}, "+ chalk 5.3.0")

	gitCmd := exec.Command("git", "config", "--unset", "pkgs.ecosystems")
	gitCmd.Dir = repoDir
	if err := gitCmd.Run(); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init: %v\n%s", err, stderr)
	}
	setGitConfig(t, repoDir, "pkgs.ecosystems", "deno")
	check([]string{"show", "HEAD"}, "+ chalk 5.3.0")
	check([]string{"log"}, "Changes: +1")
	check([]string{"search", "chalk"}, "chalk  5.3.0  (npm)")
	out, _, err := runCmd(t, "search", "lodash")
	if err != nil || !strings.Contains(out, `No dependencies matching "lodash" found.`) {
		t.Errorf("search lodash: %v\n%s", err, out)
	}
	if _, _, err := runCmd(t, "urls", "lodash"); err == nil || !strings.Contains(err.Error(), `no dependency matching "lodash"`) {
		t.Errorf("urls lodash: want no match, got %v", err)
	}
}
