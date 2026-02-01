package git

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
)

const DatabaseFile = "pkgs.sqlite3"

type Repository struct {
	repo    *git.Repository
	gitDir  string
	workDir string
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

// IgnoreMatcher checks paths against .gitignore patterns.
type IgnoreMatcher struct {
	matcher gitignore.Matcher
}

// LoadIgnoreMatcher loads .gitignore patterns from the repository.
func (r *Repository) LoadIgnoreMatcher() (*IgnoreMatcher, error) {
	wt, err := r.repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	patterns, err := gitignore.ReadPatterns(wt.Filesystem, nil)
	if err != nil {
		return nil, fmt.Errorf("reading gitignore patterns: %w", err)
	}

	return &IgnoreMatcher{
		matcher: gitignore.NewMatcher(patterns),
	}, nil
}

// IsIgnored checks if the given path (relative to repo root) is ignored.
func (m *IgnoreMatcher) IsIgnored(relPath string, isDir bool) bool {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	return m.matcher.Match(parts, isDir)
}
