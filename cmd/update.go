package cmd

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	"github.com/spf13/cobra"
)

func init() {
	addUpdateCmd(rootCmd)
}

func addUpdateCmd(parent *cobra.Command) {
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update database with new commits",
		Long: `Incrementally update the git-pkgs database with commits since
the last analysis. Use this after pulling new changes.`,
		RunE: runUpdate,
	}

	updateCmd.Flags().StringP("branch", "b", "", "Branch to update (default: tracked branch)")
	parent.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
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

	// If no branch specified, use the default tracked branch
	if branch == "" {
		branchInfo, err := db.GetDefaultBranch()
		if err != nil {
			return fmt.Errorf("no tracked branch found. Run 'git pkgs init' first")
		}
		branch = branchInfo.Name
	}

	idx := indexer.New(repo, db, indexer.Options{
		Branch:      branch,
		Output:      cmd.OutOrStdout(),
		Quiet:       quiet,
		Incremental: true,
	})

	result, err := idx.Run()
	if err != nil {
		return fmt.Errorf("updating: %w", err)
	}

	if !quiet {
		if result.CommitsAnalyzed == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Already up to date.")
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nDone! Analyzed %d new commits, found %d with dependency changes (%d total changes)\n",
				result.CommitsAnalyzed, result.CommitsWithChanges, result.TotalChanges)
		}
	}

	return nil
}
