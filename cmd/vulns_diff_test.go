package cmd_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
)

func TestVulnsDiffUsesSelectedBranchTip(t *testing.T) {
	for _, checkout := range []string{"ancestor", "divergent"} {
		t.Run(checkout, func(t *testing.T) {
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, "README.md", "# Test\n", "Initial commit")
			addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add manifest")
			runVulnsDiffGit(t, repoDir, "checkout", "-b", "feature")
			addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add vulnerable dependency")
			cleanup := chdir(t, repoDir)
			defer cleanup()
			if _, _, err := runCmd(t, "init", "--branch", "feature", "--no-hooks"); err != nil {
				t.Fatal(err)
			}
			vuln := insertTestNPMVulnerability(t, repoDir, "GHSA-issue-356")
			// Move the live branch without indexing: defaults must still use the indexed tip.
			addFileAndCommit(t, repoDir, "README.md", "# Unindexed commit\n", "Advance feature")
			runVulnsDiffGit(t, repoDir, "checkout", "main")
			if checkout == "divergent" {
				addFileAndCommit(t, repoDir, "README.md", "# Main\n", "Diverge main")
				addFileAndCommit(t, repoDir, "README.md", "# Main again\n", "Advance main")
			}
			if _, _, err := runCmd(t, "branch", "add", "main"); err != nil {
				t.Fatal(err)
			}
			for _, tt := range []struct {
				name         string
				args         []string
				added, fixed int
			}{
				{name: "explicit branch", args: []string{"--branch", "feature"}, added: 1},
				{name: "default database branch", added: 1},
				{name: "explicit refs", args: []string{"--branch", "feature", "feature~2", "feature~1"}, added: 1},
				{name: "reversed refs", args: []string{"--branch", "feature", "feature~1", "feature~2"}, fixed: 1},
				{name: "one ref retains HEAD endpoint", args: []string{"--branch", "feature", "feature~1"}, fixed: 1},
				{name: "explicit HEAD refs", args: []string{"--branch", "feature", "HEAD~1", "HEAD"}},
				{name: "main branch", args: []string{"--branch", "main"}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					assertVulnsDiff(t, vuln.ID, tt.added, tt.fixed, tt.args...)
				})
			}
		})
	}
}

func TestVulnsDiffUsesFirstParentOfMerge(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add manifest")
	runVulnsDiffGit(t, repoDir, "checkout", "-b", "feature")
	addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add vulnerable dependency")
	runVulnsDiffGit(t, repoDir, "checkout", "main")
	addFileAndCommit(t, repoDir, "Gemfile", "source 'https://rubygems.org'\ngem 'rails', '7.0.0'\n", "Add unrelated dependency on main")
	runVulnsDiffGit(t, repoDir, "merge", "--no-ff", "feature", "-m", "Merge vulnerable dependency")
	cleanup := chdir(t, repoDir)
	defer cleanup()
	if _, _, err := runCmd(t, "init", "--no-hooks", "--snapshot-interval", "1"); err != nil {
		t.Fatal(err)
	}
	vuln := insertTestNPMVulnerability(t, repoDir, "GHSA-issue-356-merge")
	// Populate exact tree snapshots to isolate parent selection from incremental merge indexing.
	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	branch, err := db.GetBranch("main")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"HEAD", "HEAD^1", "HEAD^2"} {
		sha := getGitSHA(t, repoDir, ref)
		if _, err := db.Exec("DELETE FROM dependency_snapshots WHERE commit_id = (SELECT id FROM commits WHERE sha = ?)", sha); err != nil {
			t.Fatal(err)
		}
		if err := repo.IndexCommitSnapshot(db, branch.ID, sha); err != nil {
			t.Fatal(err)
		}
	}
	assertVulnsDiff(t, vuln.ID, 1, 0)
	assertVulnsDiff(t, vuln.ID, 0, 0, "HEAD^2", "HEAD")
}

func TestVulnsDiffFixedAtIndexedTip(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add manifest")
	addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add vulnerable dependency")
	addFileAndCommit(t, repoDir, "package-lock.json", strings.ReplaceAll(packageLockJSON, "4.18.2", "4.19.0"), "Fix vulnerability")
	cleanup := chdir(t, repoDir)
	defer cleanup()
	if _, _, err := runCmd(t, "init", "--no-hooks", "--snapshot-interval", "1"); err != nil {
		t.Fatal(err)
	}
	vuln := insertTestNPMVulnerability(t, repoDir, "GHSA-issue-356-fixed")
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	err = db.InsertVulnerabilityPackage(database.VulnerabilityPackage{
		VulnerabilityID:  vuln.ID,
		Ecosystem:        "npm",
		PackageName:      "express",
		AffectedVersions: "vers:npm/>=0.0.0|<4.19.0",
		FixedVersions:    "4.19.0",
	})
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	runVulnsDiffGit(t, repoDir, "checkout", "--detach", "HEAD~1")
	assertVulnsDiff(t, vuln.ID, 0, 1)
}

func TestVulnsDiffRequiresIndexedParent(t *testing.T) {
	for _, missing := range []string{"root commit", "unindexed parent"} {
		t.Run(missing, func(t *testing.T) {
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, "package.json", packageJSON, "Initial commit")
			if missing == "unindexed parent" {
				addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add dependency")
			}
			cleanup := chdir(t, repoDir)
			defer cleanup()
			if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
				t.Fatal(err)
			}
			if missing == "unindexed parent" {
				db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec("DELETE FROM branch_commits WHERE commit_id = (SELECT id FROM commits WHERE sha = ?)", getGitSHA(t, repoDir, "HEAD~1"))
				_ = db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			_, _, err := runCmd(t, "vulns", "diff")
			if err == nil || !strings.Contains(err.Error(), "parent") {
				t.Fatalf("expected parent error, got %v", err)
			}
		})
	}
}

func runVulnsDiffGit(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = repoDir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func assertVulnsDiff(t *testing.T, id string, added, fixed int, args ...string) {
	t.Helper()
	stdout, _, err := runCmd(t, append([]string{"vulns", "diff", "--format", "json"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	var result cmd.VulnsDiffResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parsing diff JSON: %v", err)
	}
	if len(result.Added) != added || len(result.Fixed) != fixed {
		t.Fatalf("diff = %+v, want %d added and %d fixed", result, added, fixed)
	}
	for _, entries := range [][]cmd.VulnResult{result.Added, result.Fixed} {
		for _, entry := range entries {
			if entry.ID != id || entry.Package != "express" {
				t.Fatalf("unexpected vulnerability: %+v", entry)
			}
		}
	}
}
