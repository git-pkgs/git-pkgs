package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addStatsCmd(rootCmd)
}

func addStatsCmd(parent *cobra.Command) {
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show dependency statistics",
		Long:  `Display aggregate statistics about dependencies and changes.`,
		RunE:  runStats,
	}

	statsCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	statsCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	statsCmd.Flags().String("since", "", "Only changes after this date (YYYY-MM-DD)")
	statsCmd.Flags().String("until", "", "Only changes before this date (YYYY-MM-DD)")
	statsCmd.Flags().IntP("limit", "n", 10, "Number of top items to show")
	statsCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	limit, _ := cmd.Flags().GetInt("limit")
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

	stats, err := db.GetStats(database.StatsOptions{
		BranchID:  branchInfo.ID,
		Ecosystem: ecosystem,
		Since:     since,
		Until:     until,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("getting stats: %w", err)
	}

	switch format {
	case "json":
		return outputStatsJSON(cmd, stats)
	default:
		return outputStatsText(cmd, stats)
	}
}

func outputStatsJSON(cmd *cobra.Command, stats *database.Stats) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(stats)
}

func outputStatsText(cmd *cobra.Command, stats *database.Stats) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Dependency Statistics")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "========================================")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Branch: %s\n", stats.Branch)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Commits analyzed: %d\n", stats.CommitsAnalyzed)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Commits with changes: %d\n", stats.CommitsWithChanges)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Current Dependencies")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--------------------")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total: %d\n", stats.CurrentDeps)

	// Sort ecosystems by count
	type ecoCount struct {
		name  string
		count int
	}
	var ecos []ecoCount
	for name, count := range stats.DepsByEcosystem {
		ecos = append(ecos, ecoCount{name, count})
	}
	sort.Slice(ecos, func(i, j int) bool {
		return ecos[i].count > ecos[j].count
	})
	for _, ec := range ecos {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d\n", ec.name, ec.count)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Dependency Changes")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--------------------")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total changes: %d\n", stats.TotalChanges)
	if added, ok := stats.ChangesByType["added"]; ok {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  added: %d\n", added)
	}
	if modified, ok := stats.ChangesByType["modified"]; ok {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  modified: %d\n", modified)
	}
	if removed, ok := stats.ChangesByType["removed"]; ok {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  removed: %d\n", removed)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if len(stats.TopChanged) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Most Changed Dependencies")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "-------------------------")
		for _, nc := range stats.TopChanged {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d changes\n", nc.Name, nc.Count)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(stats.TopAuthors) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Top Contributors")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "----------------")
		for _, nc := range stats.TopAuthors {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d changes\n", nc.Name, nc.Count)
		}
	}

	return nil
}
