package cmd_test

import (
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestInitMailmap(t *testing.T) {
	t.Setenv("GIT_PKGS_DB", "")
	repoDir := createTestRepo(t)
	setGitUser(t, repoDir, "jane", "Jane@Laptop.(none)")
	t.Setenv("GIT_AUTHOR_NAME", "jane")
	t.Setenv("GIT_AUTHOR_EMAIL", "Jane@Laptop.(none)")
	mailmapContent := `# Normalize a contributor's old address.
Generic Contributor <generic@example.com> <jane@laptop.(none)>
Jane Doe <jane@example.com> JANE <jane@laptop.(none)>
Later Identity <later@example.com> jane <jane@laptop.(none)>
`
	addFileAndCommit(t, repoDir, ".mailmap", mailmapContent, "Map contributor identities")
	addFileAndCommit(t, repoDir, "Gemfile", "source \"https://rubygems.org\"\ngem \"rails\", \"~> 7.0\"\n", "Add Gemfile")
	sha := getGitSHA(t, repoDir, "HEAD")
	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, stderr, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v\n%s", err, stderr)
	}
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	var name, email string
	if err := db.QueryRow("SELECT author_name, author_email FROM commits WHERE sha = ?", sha).Scan(&name, &email); err != nil {
		t.Fatal(err)
	}
	if name != "Later Identity" || email != "later@example.com" {
		t.Fatalf("indexed author = (%q, %q), want (%q, %q)", name, email, "Later Identity", "later@example.com")
	}
}
