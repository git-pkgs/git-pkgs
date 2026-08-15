package cmd

import (
	"fmt"
	"io"
	"sort"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
)

func openDatabaseForRepository(repo *git.Repository) (*database.DB, error) {
	db, _, err := openRepositoryDatabase(repo, io.Discard, true)
	return db, err
}

func openDatabaseForBranchRemoval(repo *git.Repository, branchName string) (*database.DB, error) {
	db, _, err := openRepositoryDatabaseExceptBranch(repo, io.Discard, true, branchName)
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
	return openRepositoryDatabaseExceptBranch(repo, output, quiet, "")
}

func openRepositoryDatabaseExceptBranch(
	repo *git.Repository,
	output io.Writer,
	quiet bool,
	excludedBranch string,
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
		sort.Slice(branches, func(i, j int) bool {
			return branches[i].ID < branches[j].ID
		})
		for _, branch := range branches {
			if branch.ID != 0 && branch.Name == excludedBranch {
				if _, err := replacement.GetOrCreateBranch(branch.Name); err != nil {
					return fmt.Errorf("preserving branch %q for removal: %w", branch.Name, err)
				}
				continue
			}
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
