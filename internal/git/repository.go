package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/mailmap"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
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

	cmd := exec.Command("git", "rev-parse", "--git-common-dir")
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("resolving git common dir: %w", err)
	}
	gitDir := filepath.FromSlash(strings.TrimSpace(string(out)))
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(workDir, gitDir)
	}

	// PlainOpen roots its billy filesystem at the per-repo .git, so it can't
	// follow alternates that point outside the repo, and in a linked worktree
	// it can't see refs/objects in the common dir. PlainOpenOptions doesn't
	// expose AlternatesFS, and EnableDotGitCommonDir leaks an fd in v5, so
	// rebuild the storage here with both wired up. gitDir above is already
	// the common dir from `git rev-parse --git-common-dir`.
	if fsStorer, ok := repo.Storer.(*filesystem.Storage); ok {
		dotFs := dotgit.NewRepositoryFilesystem(fsStorer.Filesystem(), osfs.New(gitDir))
		root := filepath.VolumeName(gitDir) + string(filepath.Separator)
		s := filesystem.NewStorageWithOptions(
			dotFs,
			cache.NewObjectLRUDefault(),
			filesystem.Options{AlternatesFS: osfs.New(root)},
		)
		if reopened, rerr := git.Open(s, wt.Filesystem); rerr == nil {
			repo = reopened
		}
	}

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
