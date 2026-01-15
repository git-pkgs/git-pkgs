package cmd

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	"github.com/spf13/cobra"
)

func init() {
	addBranchCmd(rootCmd)
}

func addBranchCmd(parent *cobra.Command) {
	branchCmd := &cobra.Command{
		Use:   "branch",
		Short: "Manage tracked branches",
		Long: `Manage which branches are tracked in the git-pkgs database.

By default, git-pkgs tracks the current branch at init time.
Use this command to add additional branches or view tracking status.`,
		RunE: runBranchList,
	}

	addCmd := &cobra.Command{
		Use:   "add <branch>",
		Short: "Track a new branch",
		Long:  `Add a branch to be tracked by git-pkgs. This will index all commits on the branch.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runBranchAdd,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List tracked branches",
		Long:  `Show all branches currently tracked in the database.`,
		RunE:  runBranchList,
	}

	removeCmd := &cobra.Command{
		Use:   "remove <branch>",
		Short: "Stop tracking a branch",
		Long:  `Remove a branch from tracking. This deletes the branch data but keeps shared commits.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runBranchRemove,
	}

	branchCmd.AddCommand(addCmd, listCmd, removeCmd)
	parent.AddCommand(branchCmd)
}

func runBranchList(cmd *cobra.Command, args []string) error {
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

	branches, err := db.GetBranches()
	if err != nil {
		return fmt.Errorf("getting branches: %w", err)
	}

	if len(branches) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No branches tracked.")
		return nil
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Tracked branches:")
	for _, b := range branches {
		shortSHA := b.LastSHA
		if len(shortSHA) > 7 {
			shortSHA = shortSHA[:7]
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s (%s, %d commits)\n",
			b.Name, shortSHA, b.CommitCount)
	}

	return nil
}

func runBranchAdd(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")
	branchName := args[0]

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	// Check if branch exists in git
	if _, err := repo.ResolveRevision(branchName); err != nil {
		return fmt.Errorf("branch %q not found in repository", branchName)
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Check if already tracked
	branches, err := db.GetBranches()
	if err != nil {
		return fmt.Errorf("getting branches: %w", err)
	}
	for _, b := range branches {
		if b.Name == branchName {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Branch %q is already tracked.\n", branchName)
			return nil
		}
	}

	// Index the branch
	idx := indexer.New(repo, db, indexer.Options{
		Branch: branchName,
		Output: cmd.OutOrStdout(),
		Quiet:  quiet,
	})

	result, err := idx.Run()
	if err != nil {
		return fmt.Errorf("indexing branch: %w", err)
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added branch %q: %d commits, %d with dependency changes\n",
			branchName, result.CommitsAnalyzed, result.CommitsWithChanges)
	}

	return nil
}

func runBranchRemove(cmd *cobra.Command, args []string) error {
	branchName := args[0]

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

	err = db.RemoveBranch(branchName)
	if err != nil {
		return fmt.Errorf("removing branch: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed branch %q from tracking.\n", branchName)
	return nil
}
