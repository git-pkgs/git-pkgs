package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addInfoCmd(rootCmd)
}

func addInfoCmd(parent *cobra.Command) {
	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Show database information",
		Long:  `Display information about the git-pkgs database.`,
		RunE:  runInfo,
	}

	infoCmd.Flags().Bool("ecosystems", false, "Show list of tracked ecosystems")
	infoCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(infoCmd)
}

func runInfo(cmd *cobra.Command, args []string) error {
	showEcosystems, _ := cmd.Flags().GetBool("ecosystems")
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

	info, err := db.GetDatabaseInfo()
	if err != nil {
		return fmt.Errorf("getting info: %w", err)
	}

	// Get file size
	if stat, err := os.Stat(dbPath); err == nil {
		info.SizeBytes = stat.Size()
	}

	if showEcosystems {
		switch format {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(info.Ecosystems)
		default:
			if len(info.Ecosystems) == 0 {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No ecosystems found.")
			} else {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Tracked ecosystems:")
				for _, eco := range info.Ecosystems {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", eco)
				}
			}
		}
		return nil
	}

	switch format {
	case "json":
		return outputInfoJSON(cmd, info)
	default:
		return outputInfoText(cmd, info)
	}
}

func outputInfoJSON(cmd *cobra.Command, info *database.DatabaseInfo) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func outputInfoText(cmd *cobra.Command, info *database.DatabaseInfo) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Database Info")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "========================================")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Location: %s\n", info.Path)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Size: %s\n", formatBytes(info.SizeBytes))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Schema version: %d\n", info.SchemaVersion)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if info.BranchName != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Branch: %s\n", info.BranchName)
		if info.LastAnalyzedSHA != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Last analyzed: %s\n", info.LastAnalyzedSHA[:7])
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Row Counts")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "----------------------------------------")

	total := 0
	order := []string{"branches", "commits", "branch_commits", "manifests", "dependency_changes", "dependency_snapshots"}
	names := map[string]string{
		"branches":             "Branches",
		"commits":              "Commits",
		"branch_commits":       "Branch-Commits",
		"manifests":            "Manifests",
		"dependency_changes":   "Dependency Changes",
		"dependency_snapshots": "Dependency Snapshots",
	}

	for _, table := range order {
		count := info.RowCounts[table]
		name := names[table]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-24s %8d\n", name, count)
		total += count
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  ----------------------------------")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-24s %8d\n", "Total", total)
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if len(info.Ecosystems) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Ecosystems: %s\n", strings.Join(info.Ecosystems, ", "))
	}

	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
