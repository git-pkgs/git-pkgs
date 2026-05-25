package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

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
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")

	var packageName, ecosystem string
	if len(args) > 0 {
		var err error
		ecosystem, packageName, _, err = ParsePackageArg(args[0], ecosystemFlag)
		if err != nil {
			return err
		}
	} else {
		ecosystem = ecosystemFlag
	}
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
	case formatJSON:
		return outputHistoryJSON(cmd, entries)
	default:
		outputHistoryText(cmd, entries, packageName)
		return nil
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

// groupedEntry combines manifest and lockfile entries for the same change
type groupedEntry struct {
	database.HistoryEntry
	ManifestRequirement string // constraint from manifest file
	LockfileRequirement string // resolved version from lockfile
}

func groupHistoryEntries(entries []database.HistoryEntry) []groupedEntry {
	// Group by (SHA, Name, ChangeType)
	type groupKey struct {
		SHA        string
		Name       string
		ChangeType string
	}
	groups := make(map[groupKey]*groupedEntry)
	var order []groupKey

	for _, e := range entries {
		key := groupKey{SHA: e.SHA, Name: e.Name, ChangeType: e.ChangeType}
		if g, ok := groups[key]; ok {
			// Add to existing group
			if e.ManifestKind == manifestKindLockfile {
				g.LockfileRequirement = e.Requirement
			} else {
				g.ManifestRequirement = e.Requirement
			}
		} else {
			// New group
			g := &groupedEntry{HistoryEntry: e}
			if e.ManifestKind == manifestKindLockfile {
				g.LockfileRequirement = e.Requirement
			} else {
				g.ManifestRequirement = e.Requirement
			}
			groups[key] = g
			order = append(order, key)
		}
	}

	result := make([]groupedEntry, 0, len(order))
	for _, key := range order {
		result = append(result, *groups[key])
	}
	return result
}

func formatRequirement(g groupedEntry) string {
	if g.ManifestRequirement != "" && g.LockfileRequirement != "" {
		// Show both if different: constraint (resolved)
		if g.ManifestRequirement != g.LockfileRequirement {
			return fmt.Sprintf("%s (%s)", g.ManifestRequirement, g.LockfileRequirement)
		}
		return g.LockfileRequirement
	}
	if g.LockfileRequirement != "" {
		return g.LockfileRequirement
	}
	return g.ManifestRequirement
}

func formatPreviousRequirement(g groupedEntry) string {
	// For updates, we only have the previous from whichever manifest reported it
	return g.PreviousRequirement
}

func outputHistoryText(cmd *cobra.Command, entries []database.HistoryEntry, packageName string) {
	if packageName != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "History for %s:\n\n", Bold(packageName))
	}

	grouped := groupHistoryEntries(entries)

	// Check if we have multiple distinct packages
	distinctPackages := make(map[string]bool)
	for _, g := range grouped {
		distinctPackages[g.Name] = true
	}
	showPackageName := packageName == "" || len(distinctPackages) > 1

	for _, g := range grouped {
		// Date and change type
		date := g.CommittedAt[:10]
		req := formatRequirement(g)

		var line string
		switch g.ChangeType {
		case changeTypeAdded:
			line = fmt.Sprintf("%s %s", date, Green("Added"))
			if req != "" {
				line += fmt.Sprintf(" %s", req)
			}
		case changeTypeModified:
			line = fmt.Sprintf("%s %s", date, Yellow("Updated"))
			prev := formatPreviousRequirement(g)
			if prev != "" || req != "" {
				line += fmt.Sprintf(" %s -> %s", Dim(prev), req)
			}
		case changeTypeRemoved:
			line = fmt.Sprintf("%s %s", date, Red("Removed"))
			if req != "" {
				line += fmt.Sprintf(" %s", req)
			}
		default:
			line = fmt.Sprintf("%s %s", date, capitalize(g.ChangeType))
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)

		// Show package name if showing all packages or multiple match
		if showPackageName {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Package: %s %s\n", Bold(g.Name), Dim("("+g.Ecosystem+")"))
		}

		// First line of commit message
		message := g.Message
		if idx := strings.Index(message, "\n"); idx > 0 {
			message = message[:idx]
		}
		message = strings.TrimSpace(message)

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Commit: %s %s\n", Yellow(shortSHA(g.SHA)), Sanitize(message))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Author: %s %s\n", Sanitize(g.AuthorName), Dim("<"+Sanitize(g.AuthorEmail)+">"))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}
