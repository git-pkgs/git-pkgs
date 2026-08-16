package cmd

import (
	"errors"
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

func removeRepositoryDatabaseBranch(repo *git.Repository, branchName string) error {
	removedDuringRebuild := false
	db, _, err := openRepositoryDatabaseWithPreparation(repo, io.Discard, true, func(previous *database.DB) error {
		if err := previous.RemoveBranch(branchName); err != nil {
			return err
		}
		removedDuringRebuild = true
		return nil
	})
	if err != nil {
		var unresolvableBranch *unresolvableTrackedBranchError
		if removedDuringRebuild && errors.As(err, &unresolvableBranch) {
			return nil
		}
		return err
	}
	defer func() { _ = db.Close() }()

	if removedDuringRebuild {
		return nil
	}
	return db.RemoveBranch(branchName)
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
	return openRepositoryDatabaseWithPreparation(repo, output, quiet, nil)
}

func openRepositoryDatabaseWithPreparation(
	repo *git.Repository,
	output io.Writer,
	quiet bool,
	preparePrevious func(*database.DB) error,
) (*database.DB, database.UpgradeResult, error) {
	return database.OpenWithRebuild(repo.DatabasePath(), func(previous, replacement *database.DB) error {
		if preparePrevious != nil {
			if err := preparePrevious(previous); err != nil {
				return err
			}
		}

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
			revision, err := rebuildRevision(repo, branch)
			if err != nil {
				return err
			}
			idx := indexer.New(repo, replacement, indexer.Options{
				Branch:            branch.Name,
				Revision:          revision,
				Output:            output,
				Quiet:             quiet,
				FailOnCommitError: true,
				EcosystemFilter:   ecosystemFilter,
			})
			if _, err := idx.Run(); err != nil {
				return fmt.Errorf("reindexing branch %q: %w", branch.Name, err)
			}
		}
		return nil
	})
}

type unresolvableTrackedBranchError struct {
	name string
}

func (e *unresolvableTrackedBranchError) Error() string {
	return fmt.Sprintf("tracked branch %q cannot be resolved", e.name)
}

func rebuildRevision(repo *git.Repository, branch database.BranchInfo) (string, error) {
	if rebuildCommitExists(repo, branch.Name) {
		return branch.Name, nil
	}
	if branch.LastAnalyzedSHA != "" && rebuildCommitExists(repo, branch.LastAnalyzedSHA) {
		return branch.LastAnalyzedSHA, nil
	}
	return "", &unresolvableTrackedBranchError{name: branch.Name}
}

func rebuildCommitExists(repo *git.Repository, revision string) bool {
	hash, err := repo.ResolveRevision(revision)
	if err != nil {
		return false
	}
	_, err = repo.CommitObject(*hash)
	return err == nil
}
