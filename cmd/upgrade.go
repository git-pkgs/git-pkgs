package cmd

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func addUpgradeCmd(parent *cobra.Command) {
	upgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade the database schema and index",
		Long:  "Upgrade the git-pkgs database schema and rebuild outdated indexed data.",
		RunE:  runUpgrade,
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

	db, result, err := openRepositoryDatabase(repo, cmd.OutOrStdout(), quiet)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	if !quiet {
		switch {
		case result.Rebuilt && result.FromSchemaVersion == result.ToSchemaVersion:
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Rebuilt database index.")
		case result.Upgraded():
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Upgraded database from schema version %d to %d.\n", result.FromSchemaVersion, result.ToSchemaVersion)
		default:
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Database is already at schema version %d. No upgrade needed.\n", result.ToSchemaVersion)
		}
	}

	return nil
}
