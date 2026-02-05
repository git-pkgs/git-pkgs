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

func gitRun(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repoDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}

func TestTags(t *testing.T) {
	repoDir := createTestRepo(t)

	addFile(t, repoDir, "README.md", "# Test")
	sha1 := commit(t, repoDir, "First commit")
	gitRun(t, repoDir, "tag", "v1.0.0")

	addFile(t, repoDir, "file.txt", "content")
	sha2 := commit(t, repoDir, "Second commit")
	gitRun(t, repoDir, "tag", "v1.1.0")
	gitRun(t, repoDir, "tag", "release-1.1") // second tag on same commit

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tags, err := repo.Tags()
	if err != nil {
		t.Fatalf("failed to get tags: %v", err)
	}

	// Check v1.0.0
	if _, ok := tags[sha1]; !ok {
		t.Errorf("expected tag at sha %s", sha1)
	}
	found := false
	for _, name := range tags[sha1] {
		if name == "v1.0.0" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected v1.0.0 in tags at sha1, got %v", tags[sha1])
	}

	// Check v1.1.0 and release-1.1 are both at sha2
	if _, ok := tags[sha2]; !ok {
		t.Errorf("expected tags at sha %s", sha2)
	}
	if len(tags[sha2]) != 2 {
		t.Errorf("expected 2 tags at sha2, got %d: %v", len(tags[sha2]), tags[sha2])
	}
}

func TestLocalBranches(t *testing.T) {
	repoDir := createTestRepo(t)

	addFile(t, repoDir, "README.md", "# Test")
	commit(t, repoDir, "First commit")

	// Create feature branch
	gitRun(t, repoDir, "checkout", "-b", "feature")
	addFile(t, repoDir, "feature.txt", "feature")
	featureSHA := commit(t, repoDir, "Feature commit")

	// Go back to main and add another commit
	gitRun(t, repoDir, "checkout", "main")
	addFile(t, repoDir, "main.txt", "main")
	mainSHA := commit(t, repoDir, "Main commit")

	repo, err := git.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	branches, err := repo.LocalBranches()
	if err != nil {
		t.Fatalf("failed to get branches: %v", err)
	}

	// Check main branch
	if _, ok := branches[mainSHA]; !ok {
		t.Errorf("expected branch at sha %s", mainSHA)
	}
	found := false
	for _, name := range branches[mainSHA] {
		if name == "main" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected main in branches at mainSHA, got %v", branches[mainSHA])
	}

	// Check feature branch
	if _, ok := branches[featureSHA]; !ok {
		t.Errorf("expected branch at sha %s", featureSHA)
	}
	found = false
	for _, name := range branches[featureSHA] {
		if name == "feature" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected feature in branches at featureSHA, got %v", branches[featureSHA])
	}
}

func TestGetSubmodulePaths(t *testing.T) {
	t.Run("returns empty list when no submodules", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFile(t, repoDir, "README.md", "# Test")
		commit(t, repoDir, "Initial commit")

		repo, err := git.OpenRepository(repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		paths, err := repo.GetSubmodulePaths()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(paths) != 0 {
			t.Errorf("expected empty list, got %d submodules: %v", len(paths), paths)
		}
	})

	t.Run("returns submodule paths when present", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFile(t, repoDir, "README.md", "# Test")
		commit(t, repoDir, "Initial commit")

		// Manually create .gitmodules file
		gitmodulesContent := `[submodule "vendor/lib"]
	path = vendor/lib
	url = https://github.com/example/lib.git
[submodule "external/tool"]
	path = external/tool
	url = https://github.com/example/tool.git
`
		addFile(t, repoDir, ".gitmodules", gitmodulesContent)
		commit(t, repoDir, "Add submodules config")

		repo, err := git.OpenRepository(repoDir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		paths, err := repo.GetSubmodulePaths()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(paths) != 2 {
			t.Fatalf("expected 2 submodules, got %d: %v", len(paths), paths)
		}

		// Check that both paths are present
		pathMap := make(map[string]bool)
		for _, p := range paths {
			pathMap[p] = true
		}

		if !pathMap["vendor/lib"] {
			t.Errorf("expected submodule path 'vendor/lib', got %v", paths)
		}
		if !pathMap["external/tool"] {
			t.Errorf("expected submodule path 'external/tool', got %v", paths)
		}
	})
}
