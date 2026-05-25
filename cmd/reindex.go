package cmd

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	"github.com/spf13/cobra"
)

func addReindexCmd(parent *cobra.Command) {
	reindexCmd := &cobra.Command{
		Use:   "reindex",
		Short: "Update database with new commits",
		Long: `Incrementally update the git-pkgs database with commits since
the last analysis. Use this after pulling new changes.

When no branch is specified, all tracked branches are updated.`,
		RunE: runReindex,
	}

	reindexCmd.Flags().StringP("branch", "b", "", "Branch to reindex (default: all tracked branches)")
	parent.AddCommand(reindexCmd)
}

func runReindex(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")
	branch, _ := cmd.Flags().GetString("branch")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	if branch != "" {
		return reindexBranch(cmd, repo, db, branch, quiet)
	}

	// No branch specified: reindex all tracked branches
	branches, err := db.GetBranches()
	if err != nil {
		return fmt.Errorf("getting tracked branches: %w", err)
	}

	if len(branches) == 0 {
		return fmt.Errorf("no tracked branches found. Run 'git pkgs init' first")
	}

	for _, b := range branches {
		if err := reindexBranch(cmd, repo, db, b.Name, quiet); err != nil {
			return err
		}
	}

	return nil
}

func reindexBranch(cmd *cobra.Command, repo *git.Repository, db *database.DB, branch string, quiet bool) error {
	_, branchErr := db.GetBranch(branch)
	incremental := branchErr == nil

	idx := indexer.New(repo, db, indexer.Options{
		Branch:      branch,
		Output:      cmd.OutOrStdout(),
		Quiet:       quiet,
		Incremental: incremental,
	})

	result, err := idx.Run()
	if err != nil {
		return fmt.Errorf("updating %s: %w", branch, err)
	}

	if !quiet {
		switch {
		case !incremental:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added branch %q: %d commits, %d with dependency changes\n",
				branch, result.CommitsAnalyzed, result.CommitsWithChanges)
		case result.CommitsAnalyzed == 0:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: up to date\n", branch)
		default:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %d new commits, %d with dependency changes\n",
				branch, result.CommitsAnalyzed, result.CommitsWithChanges)
		}
	}

	return nil
}
