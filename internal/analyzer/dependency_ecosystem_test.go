package analyzer_test

import (
	"os/exec"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/config"
)

func denoJSON(chalk string) string {
	imports := `"path": "jsr:@std/path@^1.0.0"`
	if chalk != "" {
		imports = `"chalk": "npm:chalk@` + chalk + `", ` + imports
	}
	return `{"imports": {` + imports + `}}`
}

// ecosystemsByName maps each change's name to "<change type> <ecosystem>".
func ecosystemsByName(changes []analyzer.Change) map[string]string {
	got := make(map[string]string)
	for _, ch := range changes {
		got[ch.Name] = ch.ChangeType + " " + ch.Ecosystem
	}
	return got
}

func TestAnalyzeCommitUsesDependencyEcosystem(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "deno.json", denoJSON("5.3.0"))
	addSHA := commit(t, repoDir, "Add deno.json")
	addFile(t, repoDir, "deno.json", denoJSON("5.4.0"))
	modifySHA := commit(t, repoDir, "Bump chalk")
	addFile(t, repoDir, "deno.json", denoJSON(""))
	removeSHA := commit(t, repoDir, "Drop chalk")

	repo := openRepo(t, repoDir)
	commitObject := func(sha string) *analyzer.Result {
		t.Helper()
		c, err := repo.CommitObject(*getCommit(t, sha))
		if err != nil {
			t.Fatal(err)
		}
		// Only deno is enabled: the filter still goes by the file's ecosystem,
		// so the npm import in deno.json is analyzed.
		a := analyzer.New()
		a.SetEcosystemFilter(config.NewEcosystemFilter([]string{"deno"}, nil))
		result, err := a.AnalyzeCommit(c, nil)
		if err != nil {
			t.Fatalf("AnalyzeCommit: %v", err)
		}
		return result
	}

	added := commitObject(addSHA)
	assertManifestEcosystem(t, "added", added.Changes, added.Snapshot, "deno")
	assertEcosystems(t, "added", ecosystemsByName(added.Changes), map[string]string{
		"chalk":     "added npm",
		"@std/path": "added deno",
	})
	for key, entry := range added.Snapshot {
		want := map[string]string{"chalk": "npm", "@std/path": "deno"}[key.Name]
		if entry.Ecosystem != want {
			t.Errorf("snapshot %s ecosystem = %q, want %q", key.Name, entry.Ecosystem, want)
		}
	}
	if len(added.ManifestLicenses) != 1 || added.ManifestLicenses[0].Ecosystem != "deno" {
		t.Errorf("manifest licenses = %+v, want one with the file's ecosystem, deno", added.ManifestLicenses)
	}

	modified := commitObject(modifySHA)
	assertEcosystems(t, "modified", ecosystemsByName(modified.Changes), map[string]string{
		"chalk": "modified npm",
	})
	assertManifestEcosystem(t, "modified", modified.Changes, modified.Snapshot, "deno")
	removed := commitObject(removeSHA)
	assertEcosystems(t, "removed", ecosystemsByName(removed.Changes), map[string]string{
		"chalk": "removed npm",
	})
	assertManifestEcosystem(t, "removed", removed.Changes, removed.Snapshot, "deno")

	c, err := repo.CommitObject(*getCommit(t, addSHA))
	if err != nil {
		t.Fatal(err)
	}
	deps, err := analyzer.New().DependenciesAtCommit(c)
	if err != nil {
		t.Fatalf("DependenciesAtCommit: %v", err)
	}
	assertEcosystems(t, "DependenciesAtCommit", ecosystemsByName(deps), map[string]string{
		"chalk":     " npm",
		"@std/path": " deno",
	})
	assertManifestEcosystem(t, "DependenciesAtCommit", deps, nil, "deno")
}

func denoLock(npm ...string) string {
	entries := `"@std/path@1.0.0": {"integrity": "sha256-b"}`
	lock := `{"version": "4", "jsr": {` + entries + `}, "npm": {`
	for i, pkg := range npm {
		if i > 0 {
			lock += ", "
		}
		lock += `"` + pkg + `": {"integrity": "sha512-a"}`
	}
	return lock + `}}`
}

// The lockfile paths: another version next to an old one, a new package in a
// changed file, and a deleted file.
func TestAnalyzeCommitUsesDependencyEcosystemInDenoLock(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "deno.lock", denoLock("chalk@4.1.2"))
	commit(t, repoDir, "Add deno.lock")
	addFile(t, repoDir, "deno.lock", denoLock("chalk@4.1.2", "chalk@5.3.0"))
	secondVersionSHA := commit(t, repoDir, "Add chalk 5")
	addFile(t, repoDir, "deno.lock", denoLock("chalk@4.1.2", "chalk@5.3.0", "ms@2.1.3"))
	newPackageSHA := commit(t, repoDir, "Add ms")
	if out, err := exec.Command("git", "-C", repoDir, "rm", "-q", "deno.lock").CombinedOutput(); err != nil {
		t.Fatalf("git rm: %v: %s", err, out)
	}
	deleteSHA := commit(t, repoDir, "Remove deno.lock")

	repo := openRepo(t, repoDir)
	analyze := func(sha string) *analyzer.Result {
		t.Helper()
		c, err := repo.CommitObject(*getCommit(t, sha))
		if err != nil {
			t.Fatal(err)
		}
		result, err := analyzer.New().AnalyzeCommit(c, nil)
		if err != nil {
			t.Fatalf("AnalyzeCommit: %v", err)
		}
		return result
	}

	secondVersion := analyze(secondVersionSHA)
	assertEcosystems(t, "second version", ecosystemsByName(secondVersion.Changes), map[string]string{
		"chalk": "added npm",
	})
	assertManifestEcosystem(t, "second version", secondVersion.Changes, secondVersion.Snapshot, "deno")

	newPackage := analyze(newPackageSHA)
	assertEcosystems(t, "new package", ecosystemsByName(newPackage.Changes), map[string]string{
		"ms": "added npm",
	})
	assertManifestEcosystem(t, "new package", newPackage.Changes, newPackage.Snapshot, "deno")
	if len(newPackage.Snapshot) != 4 {
		t.Errorf("snapshot has %d entries, want 4", len(newPackage.Snapshot))
	}
	for key, entry := range newPackage.Snapshot {
		want := "npm"
		if key.Name == "@std/path" {
			want = "deno"
		}
		if entry.Ecosystem != want {
			t.Errorf("snapshot %s@%s ecosystem = %q, want %q", key.Name, key.Requirement, entry.Ecosystem, want)
		}
	}

	deleted := analyze(deleteSHA)
	assertEcosystems(t, "deleted", ecosystemsByName(deleted.Changes), map[string]string{
		"chalk":     "removed npm",
		"ms":        "removed npm",
		"@std/path": "removed deno",
	})
	assertManifestEcosystem(t, "deleted", deleted.Changes, deleted.Snapshot, "deno")
}

// apm.yml gives Git dependencies the git ecosystem. Moving one to
// devDependencies changes only its scope.
func TestAnalyzeCommitUsesDependencyEcosystemOnScopeChange(t *testing.T) {
	apmYML := func(group string) string {
		return "name: x\nversion: 1.0.0\n" + group + ":\n  apm:\n    - https://github.com/acme/toolkit.git#v2.0.0\n"
	}
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "apm.yml", apmYML("dependencies"))
	commit(t, repoDir, "Add apm.yml")
	addFile(t, repoDir, "apm.yml", apmYML("devDependencies"))
	sha := commit(t, repoDir, "Make toolkit a dev dependency")

	repo := openRepo(t, repoDir)
	c, err := repo.CommitObject(*getCommit(t, sha))
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyzer.New().AnalyzeCommit(c, nil)
	if err != nil {
		t.Fatalf("AnalyzeCommit: %v", err)
	}
	assertEcosystems(t, "scope change", ecosystemsByName(result.Changes), map[string]string{
		"github.com/acme/toolkit": "modified git",
	})
	assertManifestEcosystem(t, "scope change", result.Changes, result.Snapshot, "apm")
	if len(result.Changes) == 1 && result.Changes[0].PreviousDependencyType != "runtime" {
		t.Errorf("previous dependency type = %q, want runtime", result.Changes[0].PreviousDependencyType)
	}
}

func TestDependenciesInWorkingDirUsesDependencyEcosystem(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "deno.json", denoJSON("5.3.0"))

	deps, err := analyzer.New().DependenciesInWorkingDir(repoDir, false)
	if err != nil {
		t.Fatalf("DependenciesInWorkingDir: %v", err)
	}
	assertEcosystems(t, "DependenciesInWorkingDir", ecosystemsByName(deps), map[string]string{
		"chalk":     " npm",
		"@std/path": " deno",
	})
	assertManifestEcosystem(t, "DependenciesInWorkingDir", deps, nil, "deno")
}

func assertEcosystems(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v, want %v", what, got, want)
		return
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: %s = %q, want %q", what, name, got[name], w)
		}
	}
}

// assertManifestEcosystem checks that every change and snapshot entry names
// the ecosystem of the file it came from.
func assertManifestEcosystem(t *testing.T, what string, changes []analyzer.Change, snapshot analyzer.Snapshot, want string) {
	t.Helper()
	for _, ch := range changes {
		if ch.ManifestEcosystem != want {
			t.Errorf("%s: change %s manifest ecosystem = %q, want %q", what, ch.Name, ch.ManifestEcosystem, want)
		}
	}
	for key, entry := range snapshot {
		if entry.ManifestEcosystem != want {
			t.Errorf("%s: snapshot %s manifest ecosystem = %q, want %q", what, key.Name, entry.ManifestEcosystem, want)
		}
	}
}
