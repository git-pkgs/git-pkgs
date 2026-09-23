package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/git-pkgs/git-pkgs/internal/config"
	"github.com/git-pkgs/git-pkgs/internal/mailmap"
	"github.com/git-pkgs/history"
	"github.com/go-git/go-git/v6"
	gitconfig "github.com/go-git/go-git/v6/config"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
)

const DatabaseFile = "pkgs.sqlite3"

type Repository struct {
	repo                *git.Repository
	history             *history.Repo
	gitDir              string
	workDir             string
	mailmap             *mailmap.Mailmap
	ecosystemFilter     config.EcosystemFilter
	ecosystemFilterErr  error
	ecosystemFilterOnce sync.Once
}

func OpenRepository(path string) (*Repository, error) {
	historyRepo, err := history.OpenWithOptions(path, history.OpenOptions{
		Tuning:       history.DefaultTuning(),
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening repository: %w", err)
	}
	repo := historyRepo.Repository()

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("getting worktree: %w", err)
	}

	workDir := wt.Filesystem().Root()

	return &Repository{
		repo:    repo,
		history: historyRepo,
		gitDir:  historyRepo.CommonDir(),
		workDir: workDir,
	}, nil
}

func (r *Repository) DatabasePath() string {
	if dbPath := os.Getenv("GIT_PKGS_DB"); dbPath != "" {
		if filepath.IsAbs(dbPath) {
			return filepath.Clean(dbPath)
		}
		return filepath.Join(r.workDir, dbPath)
	}
	return filepath.Join(r.gitDir, DatabaseFile)
}

func (r *Repository) GitDir() string {
	return r.gitDir
}

func (r *Repository) WorkDir() string {
	return r.workDir
}

func (r *Repository) EcosystemFilter() (config.EcosystemFilter, error) {
	r.ecosystemFilterOnce.Do(func() {
		var repoConfig *gitconfig.Config
		repoConfig, r.ecosystemFilterErr = r.repo.Config()
		if r.ecosystemFilterErr == nil {
			r.ecosystemFilter = config.LoadEcosystemFilter(repoConfig)
		}
	})
	if r.ecosystemFilterErr != nil {
		return config.EcosystemFilter{}, r.ecosystemFilterErr
	}
	return r.ecosystemFilter, nil
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

func (r *Repository) CommitHashes(opts history.CommitOptions) ([]plumbing.Hash, error) {
	return r.history.CommitHashes(opts)
}

func (r *Repository) WalkCommits(opts history.CommitOptions, visit func(history.Commit) error) error {
	return r.history.WalkCommits(opts, visit)
}

func (r *Repository) Checkout(ref string) error {
	worktree, err := r.repo.Worktree()
	if err != nil {
		return err
	}
	branch := plumbing.NewBranchReferenceName(ref)
	if _, err := r.repo.Reference(branch, true); err == nil {
		return worktree.Checkout(&git.CheckoutOptions{Branch: branch})
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return err
	}
	hash, err := r.ResolveRevision(ref)
	if err != nil {
		return err
	}
	return worktree.Checkout(&git.CheckoutOptions{Hash: *hash})
}

func (r *Repository) WorkingTreeClean() (bool, error) {
	worktree, err := r.repo.Worktree()
	if err != nil {
		return false, err
	}
	status, err := worktree.Status()
	if err != nil {
		return false, err
	}
	return status.IsClean(), nil
}

func (r *Repository) SetDiffDriver(command string) error {
	cfg, err := r.repo.Config()
	if err != nil {
		return err
	}
	cfg.Raw.SetOption("diff", "git-pkgs", "textconv", command)
	return r.repo.SetConfig(cfg)
}

func (r *Repository) UnsetDiffDriver() error {
	cfg, err := r.repo.Config()
	if err != nil {
		return err
	}
	if !cfg.Raw.HasSection("diff") {
		return nil
	}
	section := cfg.Raw.Section("diff")
	if !section.HasSubsection("git-pkgs") {
		return nil
	}
	subsection := section.Subsection("git-pkgs")
	subsection.RemoveOption("textconv")
	if len(subsection.Options) == 0 {
		section.RemoveSubsection("git-pkgs")
	}
	if len(section.Options) == 0 && len(section.Subsections) == 0 {
		cfg.Raw.RemoveSection("diff")
	}
	return r.repo.SetConfig(cfg)
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
