package cmd

import (
	"fmt"
	"io"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
)

func openDatabaseForRepository(repo *git.Repository) (*database.DB, error) {
	db, _, err := openRepositoryDatabase(repo, io.Discard, true)
	return db, err
}

func prepareRepositoryDatabase(repo *git.Repository) error {
	if !database.Exists(repo.DatabasePath()) {
		return nil
	}
	db, err := openDatabaseForRepository(repo)
	if err != nil {
		return err
	}
	return db.Close()
}

func getDependenciesWithDB(
	repo *git.Repository,
	commitRef, branchName string,
) ([]database.Dependency, *database.DB, error) {
	if err := prepareRepositoryDatabase(repo); err != nil {
		return nil, nil, err
	}
	return repo.GetDependenciesWithDB(commitRef, branchName)
}

func getDependencies(repo *git.Repository, commitRef, branchName string) ([]database.Dependency, error) {
	if err := prepareRepositoryDatabase(repo); err != nil {
		return nil, err
	}
	return repo.GetDependencies(commitRef, branchName)
}

func openRepositoryDatabase(
	repo *git.Repository,
	output io.Writer,
	quiet bool,
) (*database.DB, database.UpgradeResult, error) {
	return database.OpenWithRebuild(repo.DatabasePath(), func(previous, replacement *database.DB) error {
		branches, err := previous.GetBranches()
		if err != nil {
			return fmt.Errorf("reading tracked branches: %w", err)
		}
		if len(branches) == 0 {
			branch, err := repo.CurrentBranch()
			if err != nil {
				return fmt.Errorf("finding a branch to rebuild: %w", err)
			}
			branches = []database.BranchInfo{{Name: branch}}
		}

		ecosystemFilter, err := repo.EcosystemFilter()
		if err != nil {
			return fmt.Errorf("loading ecosystem config: %w", err)
		}

		if !quiet {
			_, _ = fmt.Fprintln(output, "Database index is out of date. Rebuilding it now...")
		}
		for _, branch := range branches {
			revision, err := rebuildRevision(repo, branch)
			if err != nil {
				return err
			}
			idx := indexer.New(repo, replacement, indexer.Options{
				Branch:          branch.Name,
				Revision:        revision,
				Output:          output,
				Quiet:           quiet,
				EcosystemFilter: ecosystemFilter,
			})
			if _, err := idx.Run(); err != nil {
				return fmt.Errorf("reindexing branch %q: %w", branch.Name, err)
			}
		}
		return nil
	})
}

func rebuildRevision(repo *git.Repository, branch database.BranchInfo) (string, error) {
	if _, err := repo.ResolveRevision(branch.Name); err == nil {
		return branch.Name, nil
	}
	if branch.LastAnalyzedSHA != "" {
		if _, err := repo.ResolveRevision(branch.LastAnalyzedSHA); err == nil {
			return branch.LastAnalyzedSHA, nil
		}
	}
	return "", fmt.Errorf("tracked branch %q cannot be resolved", branch.Name)
}
