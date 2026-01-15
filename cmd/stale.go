package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addStaleCmd(rootCmd)
}

func addStaleCmd(parent *cobra.Command) {
	staleCmd := &cobra.Command{
		Use:   "stale",
		Short: "Find stale dependencies",
		Long: `List dependencies sorted by how long since they were last changed.
Only shows lockfile dependencies (not manifest declarations).`,
		RunE: runStale,
	}

	staleCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	staleCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	staleCmd.Flags().Int("days", 0, "Only show deps unchanged for at least N days")
	staleCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(staleCmd)
}

func runStale(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	days, _ := cmd.Flags().GetInt("days")
	format, _ := cmd.Flags().GetString("format")

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

	var branchInfo *database.BranchInfo
	if branchName != "" {
		branchInfo, err = db.GetBranch(branchName)
		if err != nil {
			return fmt.Errorf("branch %q not found: %w", branchName, err)
		}
	} else {
		branchInfo, err = db.GetDefaultBranch()
		if err != nil {
			return fmt.Errorf("getting branch: %w", err)
		}
	}

	entries, err := db.GetStaleDependencies(branchInfo.ID, ecosystem, days)
	if err != nil {
		return fmt.Errorf("getting stale dependencies: %w", err)
	}

	if len(entries) == 0 {
		if days > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No dependencies unchanged for %d+ days.\n", days)
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found.")
		}
		return nil
	}

	switch format {
	case "json":
		return outputStaleJSON(cmd, entries)
	default:
		return outputStaleText(cmd, entries)
	}
}

func outputStaleJSON(cmd *cobra.Command, entries []database.StaleEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func outputStaleText(cmd *cobra.Command, entries []database.StaleEntry) error {
	// Find max name length for alignment
	maxNameLen := 0
	for _, e := range entries {
		if len(e.Name) > maxNameLen {
			maxNameLen = len(e.Name)
		}
	}

	for _, e := range entries {
		lastChanged := "never"
		if len(e.LastChanged) >= 10 {
			lastChanged = e.LastChanged[:10]
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %s  (%d days)  %s\n",
			maxNameLen, e.Name,
			e.Requirement,
			e.DaysSince,
			lastChanged)
	}

	return nil
}
