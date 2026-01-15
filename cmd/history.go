package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addHistoryCmd(rootCmd)
}

func addHistoryCmd(parent *cobra.Command) {
	historyCmd := &cobra.Command{
		Use:   "history [package]",
		Short: "Show history of dependency changes",
		Long: `Show the history of changes to a specific package, or all packages if none specified.
Changes are shown in chronological order.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runHistory,
	}

	historyCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	historyCmd.Flags().String("author", "", "Filter by author name or email")
	historyCmd.Flags().String("since", "", "Only changes after this date (YYYY-MM-DD)")
	historyCmd.Flags().String("until", "", "Only changes before this date (YYYY-MM-DD)")
	historyCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(historyCmd)
}

func runHistory(cmd *cobra.Command, args []string) error {
	packageName := ""
	if len(args) > 0 {
		packageName = args[0]
	}

	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	author, _ := cmd.Flags().GetString("author")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
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

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return fmt.Errorf("getting branch: %w", err)
	}

	entries, err := db.GetPackageHistory(database.HistoryOptions{
		BranchID:    branchInfo.ID,
		PackageName: packageName,
		Ecosystem:   ecosystem,
		Author:      author,
		Since:       since,
		Until:       until,
	})
	if err != nil {
		return fmt.Errorf("getting history: %w", err)
	}

	if len(entries) == 0 {
		if packageName != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No history found for %q.\n", packageName)
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependency changes found.")
		}
		return nil
	}

	switch format {
	case "json":
		return outputHistoryJSON(cmd, entries)
	default:
		return outputHistoryText(cmd, entries, packageName)
	}
}

func outputHistoryJSON(cmd *cobra.Command, entries []database.HistoryEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func outputHistoryText(cmd *cobra.Command, entries []database.HistoryEntry, packageName string) error {
	if packageName != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "History for %s:\n\n", packageName)
	}

	for _, e := range entries {
		// Date and change type
		date := e.CommittedAt[:10]

		var line string
		switch e.ChangeType {
		case "added":
			line = fmt.Sprintf("%s Added", date)
			if e.Requirement != "" {
				line += fmt.Sprintf(" = %s", e.Requirement)
			}
		case "modified":
			line = fmt.Sprintf("%s Updated", date)
			if e.PreviousRequirement != "" || e.Requirement != "" {
				line += fmt.Sprintf(" = %s -> = %s", e.PreviousRequirement, e.Requirement)
			}
		case "removed":
			line = fmt.Sprintf("%s Removed", date)
			if e.Requirement != "" {
				line += fmt.Sprintf(" = %s", e.Requirement)
			}
		default:
			line = fmt.Sprintf("%s %s", date, capitalize(e.ChangeType))
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)

		// If showing all packages, show the package name
		if packageName == "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Package: %s (%s)\n", e.Name, e.Ecosystem)
		}

		// First line of commit message
		message := e.Message
		if idx := strings.Index(message, "\n"); idx > 0 {
			message = message[:idx]
		}
		message = strings.TrimSpace(message)

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commit: %s %s\n", e.SHA[:7], message)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Author: %s <%s>\n", e.AuthorName, e.AuthorEmail)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Manifest: %s\n", e.ManifestPath)
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
