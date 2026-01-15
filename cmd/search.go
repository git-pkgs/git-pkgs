package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addSearchCmd(rootCmd)
}

func addSearchCmd(parent *cobra.Command) {
	searchCmd := &cobra.Command{
		Use:   "search <pattern>",
		Short: "Find dependencies matching a pattern",
		Long:  `Search for dependencies whose names match the given pattern.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runSearch,
	}

	searchCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	searchCmd.Flags().Bool("direct", false, "Only show direct dependencies (exclude lockfile)")
	searchCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	pattern := args[0]
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	directOnly, _ := cmd.Flags().GetBool("direct")
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

	results, err := db.SearchDependencies(branchInfo.ID, pattern, ecosystem, directOnly)
	if err != nil {
		return fmt.Errorf("searching: %w", err)
	}

	if len(results) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No dependencies matching %q found.\n", pattern)
		return nil
	}

	switch format {
	case "json":
		return outputSearchJSON(cmd, results)
	default:
		return outputSearchText(cmd, results)
	}
}

func outputSearchJSON(cmd *cobra.Command, results []database.SearchResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func outputSearchText(cmd *cobra.Command, results []database.SearchResult) error {
	// Find max name length for alignment
	maxNameLen := 0
	for _, r := range results {
		if len(r.Name) > maxNameLen {
			maxNameLen = len(r.Name)
		}
	}

	for _, r := range results {
		firstSeen := ""
		if len(r.FirstSeen) >= 10 {
			firstSeen = r.FirstSeen[:10]
		}
		lastChanged := ""
		if len(r.LastChanged) >= 10 {
			lastChanged = r.LastChanged[:10]
		}

		line := fmt.Sprintf("%-*s", maxNameLen, r.Name)
		if r.Requirement != "" {
			line += fmt.Sprintf("  %s", r.Requirement)
		}
		if r.Ecosystem != "" {
			line += fmt.Sprintf("  (%s)", r.Ecosystem)
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)

		if firstSeen != "" || lastChanged != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  First seen: %s  Last changed: %s\n", firstSeen, lastChanged)
		}
	}

	return nil
}
