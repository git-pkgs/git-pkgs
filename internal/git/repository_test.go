package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func createTestRepo(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	commands := [][]string{
		{"git", "init", "--initial-branch=main"},
		{"git", "config", "user.email", "test@example.com"},
		{"git", "config", "user.name", "Test User"},
		{"git", "config", "commit.gpgsign", "false"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		if err := cmd.Run(); err != nil {
			t.Fatalf("failed to run %v: %v", args, err)
		}
	}

	return tmpDir
}

func addFile(t *testing.T, repoDir, path, content string) {
	t.Helper()
	fullPath := filepath.Join(repoDir, path)

	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	cmd := exec.Command("git", "add", path)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to git add: %v", err)
	}
}

func commit(t *testing.T, repoDir, message string) string {
	t.Helper()
	cmd := exec.Command("git", "commit", "-m", message)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to commit: %v", err)
	}

	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to get commit sha: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestOpenRepository(t *testing.T) {
	t.Run("opens existing repository", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFile(t, repoDir, "README.md", "# Test")
		commit(t, repoDir, "Initial commit")

		repo, err := git.OpenRepository(repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if repo.WorkDir() != repoDir {
			t.Errorf("expected work dir %s, got %s", repoDir, repo.WorkDir())
		}

		expectedGitDir := filepath.Join(repoDir, ".git")
		if repo.GitDir() != expectedGitDir {
			t.Errorf("expected git dir %s, got %s", expectedGitDir, repo.GitDir())
		}
	})

	t.Run("returns error for non-repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := git.OpenRepository(tmpDir)
		if err == nil {
			t.Error("expected error for non-repository")
		}
	})
}

func TestDatabasePath(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	if repo.DatabasePath() != expected {
		t.Errorf("expected database path %s, got %s", expected, repo.DatabasePath())
	}
}

func TestCurrentBranch(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "Initial commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	branch, err := repo.CurrentBranch()
	if err != nil {
		t.Fatalf("failed to get current branch: %v", err)
	}

	if branch != "main" {
		t.Errorf("expected branch main, got %s", branch)
	}
}

func TestResolveRevision(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	sha := commit(t, repoDir, "Initial commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("resolves HEAD", func(t *testing.T) {
		hash, err := repo.ResolveRevision("HEAD")
		if err != nil {
			t.Fatalf("failed to resolve HEAD: %v", err)
		}
		if hash.String() != sha {
			t.Errorf("expected %s, got %s", sha, hash.String())
		}
	})

	t.Run("resolves branch name", func(t *testing.T) {
		hash, err := repo.ResolveRevision("main")
		if err != nil {
			t.Fatalf("failed to resolve main: %v", err)
		}
		if hash.String() != sha {
			t.Errorf("expected %s, got %s", sha, hash.String())
		}
	})
}

func TestCommitObject(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test")
	sha := commit(t, repoDir, "Initial commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hash, err := repo.ResolveRevision(sha)
	if err != nil {
		t.Fatalf("failed to resolve sha: %v", err)
	}

	c, err := repo.CommitObject(*hash)
	if err != nil {
		t.Fatalf("failed to get commit object: %v", err)
	}

	if c.Author.Name != "Test User" {
		t.Errorf("expected author Test User, got %s", c.Author.Name)
	}
	if c.Author.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", c.Author.Email)
	}
	if !strings.Contains(c.Message, "Initial commit") {
		t.Errorf("expected message to contain 'Initial commit', got %s", c.Message)
	}
}

func TestFileAtCommit(t *testing.T) {
	repoDir := createTestRepo(t)
	addFile(t, repoDir, "README.md", "# Test Project")
	sha := commit(t, repoDir, "Initial commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hash, _ := repo.ResolveRevision(sha)
	c, _ := repo.CommitObject(*hash)

	content, err := repo.FileAtCommit(c, "README.md")
	if err != nil {
		t.Fatalf("failed to get file: %v", err)
	}

	if content != "# Test Project" {
		t.Errorf("expected '# Test Project', got %s", content)
	}
}

func TestLog(t *testing.T) {
	repoDir := createTestRepo(t)

	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "First commit")

	addFile(t, repoDir, "file.txt", "content")
	commit(t, repoDir, "Second commit")

	addFile(t, repoDir, "file.txt", "updated content")
	commit(t, repoDir, "Third commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hash, _ := repo.ResolveRevision("HEAD")
	iter, err := repo.Log(*hash)
	if err != nil {
		t.Fatalf("failed to get log: %v", err)
	}

	var count int
	err = iter.ForEach(func(c *object.Commit) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("failed to iterate: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 commits, got %d", count)
	}
}
