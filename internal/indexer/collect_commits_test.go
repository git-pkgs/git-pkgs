package indexer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	gitpkg "github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/go-git/go-git/v6/plumbing"
)

func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func setupTestIndexer(t *testing.T, repoDir string) *Indexer {
	t.Helper()
	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(repo, db, Options{})
}

func TestCollectCommits(t *testing.T) {
	tmpDir := t.TempDir()
	testGit(t, tmpDir, "init", "--initial-branch=main")
	testGit(t, tmpDir, "config", "user.email", "test@example.com")
	testGit(t, tmpDir, "config", "user.name", "Test User")
	testGit(t, tmpDir, "config", "commit.gpgsign", "false")

	var expected []plumbing.Hash
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
		testGit(t, tmpDir, "add", name)
		testGit(t, tmpDir, "commit", "-m", fmt.Sprintf("commit %d", i))
		sha := testGit(t, tmpDir, "rev-parse", "HEAD")
		expected = append(expected, plumbing.NewHash(sha))
	}

	idx := setupTestIndexer(t, tmpDir)
	hashes, err := idx.collectCommits("main", "")
	if err != nil {
		t.Fatal(err)
	}

	if len(hashes) != 3 {
		t.Fatalf("expected 3 hashes, got %d", len(hashes))
	}

	for i, h := range hashes {
		if h != expected[i] {
			t.Errorf("hash[%d] = %s, want %s", i, h, expected[i])
		}
	}
}

func TestCollectCommitsSince(t *testing.T) {
	tmpDir := t.TempDir()
	testGit(t, tmpDir, "init", "--initial-branch=main")
	testGit(t, tmpDir, "config", "user.email", "test@example.com")
	testGit(t, tmpDir, "config", "user.name", "Test User")
	testGit(t, tmpDir, "config", "commit.gpgsign", "false")

	var shas []string
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("file%d.txt", i)
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
		testGit(t, tmpDir, "add", name)
		testGit(t, tmpDir, "commit", "-m", fmt.Sprintf("commit %d", i))
		shas = append(shas, testGit(t, tmpDir, "rev-parse", "HEAD"))
	}

	idx := setupTestIndexer(t, tmpDir)

	// sinceSHA = first commit, so we should get only commits 2 and 3
	hashes, err := idx.collectCommits("main", shas[0])
	if err != nil {
		t.Fatal(err)
	}

	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}

	if hashes[0].String() != shas[1] {
		t.Errorf("hash[0] = %s, want %s", hashes[0], shas[1])
	}
	if hashes[1].String() != shas[2] {
		t.Errorf("hash[1] = %s, want %s", hashes[1], shas[2])
	}
}

func TestCollectCommitsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	testGit(t, tmpDir, "init", "--initial-branch=main")
	testGit(t, tmpDir, "config", "user.email", "test@example.com")
	testGit(t, tmpDir, "config", "user.name", "Test User")
	testGit(t, tmpDir, "config", "commit.gpgsign", "false")

	if err := os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	testGit(t, tmpDir, "add", "file.txt")
	lastSHA := testGit(t, tmpDir, "commit", "-m", "only commit")
	_ = lastSHA

	idx := setupTestIndexer(t, tmpDir)

	// sinceSHA = HEAD, so range is HEAD..main which is empty
	headSHA := testGit(t, tmpDir, "rev-parse", "HEAD")
	hashes, err := idx.collectCommits("main", headSHA)
	if err != nil {
		t.Fatal(err)
	}

	if len(hashes) != 0 {
		t.Errorf("expected 0 hashes, got %d", len(hashes))
	}
}
