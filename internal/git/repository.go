package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/mailmap"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const DatabaseFile = "pkgs.sqlite3"

type Repository struct {
	repo    *git.Repository
	gitDir  string
	workDir string
	mailmap *mailmap.Mailmap
}

func OpenRepository(path string) (*Repository, error) {
	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening repository: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	workDir := wt.Filesystem.Root()
	gitDir := filepath.Join(workDir, ".git")

	return &Repository{
		repo:    repo,
		gitDir:  gitDir,
		workDir: workDir,
	}, nil
}

func (r *Repository) DatabasePath() string {
	return filepath.Join(r.gitDir, DatabaseFile)
}

func (r *Repository) GitDir() string {
	return r.gitDir
}

func (r *Repository) WorkDir() string {
	return r.workDir
}

func (r *Repository) Head() (*plumbing.Reference, error) {
	return r.repo.Head()
}

func (r *Repository) CurrentBranch() (string, error) {
	head, err := r.repo.Head()
	if err != nil {
		return "", err
	}
	if !head.Name().IsBranch() {
		return "", fmt.Errorf("HEAD is not a branch")
	}
	return head.Name().Short(), nil
}

func (r *Repository) ResolveRevision(rev string) (*plumbing.Hash, error) {
	return r.repo.ResolveRevision(plumbing.Revision(rev))
}

func (r *Repository) CommitObject(hash plumbing.Hash) (*object.Commit, error) {
	return r.repo.CommitObject(hash)
}

func (r *Repository) Log(from plumbing.Hash) (object.CommitIter, error) {
	return r.repo.Log(&git.LogOptions{
		From:  from,
		Order: git.LogOrderCommitterTime,
	})
}

func (r *Repository) TreeAtCommit(commit *object.Commit) (*object.Tree, error) {
	return commit.Tree()
}

func (r *Repository) FileAtCommit(commit *object.Commit, path string) (string, error) {
	tree, err := commit.Tree()
	if err != nil {
		return "", err
	}

	file, err := tree.File(path)
	if err != nil {
		return "", err
	}

	return file.Contents()
}

// Tags returns a map of commit SHA to tag names for all tags in the repository.
func (r *Repository) Tags() (map[string][]string, error) {
	result := make(map[string][]string)

	iter, err := r.repo.Tags()
	if err != nil {
		return nil, fmt.Errorf("getting tags: %w", err)
	}

	err = iter.ForEach(func(ref *plumbing.Reference) error {
		// Resolve the tag to get the commit SHA (handles both lightweight and annotated tags)
		hash, err := r.repo.ResolveRevision(plumbing.Revision(ref.Name()))
		if err != nil {
			// Skip tags that can't be resolved
			return nil
		}
		sha := hash.String()
		tagName := ref.Name().Short()
		result[sha] = append(result[sha], tagName)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// LocalBranches returns a map of commit SHA to branch names for all local branch heads.
func (r *Repository) LocalBranches() (map[string][]string, error) {
	result := make(map[string][]string)

	iter, err := r.repo.Branches()
	if err != nil {
		return nil, fmt.Errorf("getting branches: %w", err)
	}

	err = iter.ForEach(func(ref *plumbing.Reference) error {
		sha := ref.Hash().String()
		branchName := ref.Name().Short()
		result[sha] = append(result[sha], branchName)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetExcludeDirs returns directories to skip during walking, read from
// git config git-pkgs.exclude-dirs. Defaults to "node_modules,vendor" if unset.
func (r *Repository) GetExcludeDirs() []string {
	cmd := exec.Command("git", "config", "git-pkgs.exclude-dirs")
	cmd.Dir = r.workDir
	out, err := cmd.Output()
	if err != nil {
		return []string{"node_modules", "vendor"}
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return []string{"node_modules", "vendor"}
	}
	parts := strings.Split(val, ",")
	dirs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			dirs = append(dirs, p)
		}
	}
	return dirs
}

// GetSubmodulePaths returns a list of submodule paths using go-git's submodule support.
func (r *Repository) GetSubmodulePaths() ([]string, error) {
	wt, err := r.repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	submodules, err := wt.Submodules()
	if err != nil {
		return nil, nil // No submodules or can't read them, return empty list
	}

	paths := make([]string, 0, len(submodules))
	for _, submodule := range submodules {
		config := submodule.Config()
		// Normalize to forward slashes for cross-platform consistency
		path := filepath.ToSlash(config.Path)
		paths = append(paths, path)
	}

	return paths, nil
}

// LoadMailmap loads the .mailmap file from the repository root if it exists.
// This enables author identity remapping via ResolveAuthor.
func (r *Repository) LoadMailmap() error {
	mailmapPath := filepath.Join(r.workDir, ".mailmap")
	f, err := os.Open(mailmapPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No .mailmap file - this is fine, just use empty mailmap
			r.mailmap = mailmap.New()
			return nil
		}
		return fmt.Errorf("opening .mailmap: %w", err)
	}
	defer func() { _ = f.Close() }()

	mm, err := mailmap.Parse(f)
	if err != nil {
		return fmt.Errorf("parsing .mailmap: %w", err)
	}
	r.mailmap = mm
	return nil
}

// ResolveAuthor maps an author's name and email to their canonical identity
// using the loaded .mailmap file. If no .mailmap was loaded or no mapping
// exists, the original values are returned unchanged.
func (r *Repository) ResolveAuthor(name, email string) (string, string) {
	if r.mailmap == nil {
		return name, email
	}
	return r.mailmap.Resolve(name, email)
}
