package git

import (
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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
