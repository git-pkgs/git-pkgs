package cmd

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	"github.com/spf13/cobra"
)

func init() {
	addUpgradeCmd(rootCmd)
}

func addUpgradeCmd(parent *cobra.Command) {
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade database to latest schema version",
		Long: `Upgrade the git-pkgs database to the latest schema version.
This rebuilds the database from scratch if the schema has changed.`,
		RunE: runUpgrade,
	}

	parent.AddCommand(upgradeCmd)
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")

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

	currentVersion, err := db.SchemaVersion()
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("reading schema version: %w", err)
	}

	if currentVersion == database.SchemaVersion {
		_ = db.Close()
		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Database is already at schema version %d. No upgrade needed.\n", currentVersion)
		}
		return nil
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Upgrading database from schema v%d to v%d...\n", currentVersion, database.SchemaVersion)
	}

	// Get the branch name before closing
	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("getting branch info: %w", err)
	}
	branch := branchInfo.Name

	if err := db.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	// Recreate the database
	db, err = database.Create(dbPath)
	if err != nil {
		return fmt.Errorf("creating database: %w", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{
		Branch: branch,
		Output: cmd.OutOrStdout(),
		Quiet:  quiet,
	})

	result, err := idx.Run()
	if err != nil {
		return fmt.Errorf("indexing: %w", err)
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nUpgrade complete! Analyzed %d commits, found %d with dependency changes (%d total changes)\n",
			result.CommitsAnalyzed, result.CommitsWithChanges, result.TotalChanges)
	}

	return nil
}

// NeedsUpgrade checks if the database needs to be upgraded
func NeedsUpgrade(dbPath string) (bool, int, error) {
	if !database.Exists(dbPath) {
		return false, 0, nil
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = db.Close() }()

	currentVersion, err := db.SchemaVersion()
	if err != nil {
		return false, 0, err
	}

	return currentVersion != database.SchemaVersion, currentVersion, nil
}
