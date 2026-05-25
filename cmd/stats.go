package cmd

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
)

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
	const defaultStatsLimit = 10
	statsCmd.Flags().IntP("limit", "n", defaultStatsLimit, "Number of top items to show")
	statsCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	statsCmd.Flags().Bool("by-author", false, "Show detailed per-author statistics")
	parent.AddCommand(statsCmd)
}

func runStats(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	limit, _ := cmd.Flags().GetInt("limit")
	format, _ := cmd.Flags().GetString("format")
	byAuthor, _ := cmd.Flags().GetBool("by-author")

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	opts := database.StatsOptions{
		BranchID:  branchInfo.ID,
		Ecosystem: ecosystem,
		Since:     since,
		Until:     until,
		Limit:     limit,
	}

	if byAuthor {
		authorStats, err := db.GetAuthorStats(opts)
		if err != nil {
			return fmt.Errorf("getting author stats: %w", err)
		}

		switch format {
		case formatJSON:
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(authorStats)
		default:
			outputAuthorStatsText(cmd, authorStats)
			return nil
		}
	}

	stats, err := db.GetStats(opts)
	if err != nil {
		return fmt.Errorf("getting stats: %w", err)
	}

	switch format {
	case formatJSON:
		return outputStatsJSON(cmd, stats)
	default:
		outputStatsText(cmd, stats)
		return nil
	}
}

func outputStatsJSON(cmd *cobra.Command, stats *database.Stats) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(stats)
}

func outputAuthorStatsText(cmd *cobra.Command, authors []database.AuthorStats) {
	if len(authors) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No author statistics found.")
		return
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), Bold("Author Statistics"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "========================================")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	for _, a := range authors {
		name := a.Name
		if name == "" {
			name = "(unknown)"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", Bold(name))
		if a.Email != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Email: %s\n", Dim(a.Email))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commits: %d\n", a.Commits)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Changes: %d total\n", a.Changes)
		if added := a.ByType[changeTypeAdded]; added > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s %d\n", Green("+added:"), added)
		}
		if modified := a.ByType[changeTypeModified]; modified > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s %d\n", Yellow("~modified:"), modified)
		}
		if removed := a.ByType[changeTypeRemoved]; removed > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s %d\n", Red("-removed:"), removed)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}

func outputStatsText(cmd *cobra.Command, stats *database.Stats) {
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
		if ecos[i].count != ecos[j].count {
			return ecos[i].count > ecos[j].count
		}
		return ecos[i].name < ecos[j].name
	})
	for _, ec := range ecos {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d\n", ec.name, ec.count)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Dependency Changes")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "--------------------")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total changes: %d\n", stats.TotalChanges)
	if added, ok := stats.ChangesByType[changeTypeAdded]; ok {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  added: %d\n", added)
	}
	if modified, ok := stats.ChangesByType[changeTypeModified]; ok {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  modified: %d\n", modified)
	}
	if removed, ok := stats.ChangesByType[changeTypeRemoved]; ok {
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
}
