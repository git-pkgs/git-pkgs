package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
)

func addSearchCmd(parent *cobra.Command) {
	searchCmd := &cobra.Command{
		Use:     "search <pattern>",
		Aliases: []string{"grep"},
		Short:   "Find dependencies matching a pattern",
		Long:    `Search for dependencies whose names match the given pattern.`,
		Args:    cobra.ExactArgs(1),
		RunE:    runSearch,
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
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
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

	switch format {
	case formatJSON:
		return outputSearchJSON(cmd, results)
	default:
		if len(results) == 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No dependencies matching %q found.\n", pattern)
			return nil
		}
		outputSearchText(cmd, results)
		return nil
	}
}

func outputSearchJSON(cmd *cobra.Command, results []database.SearchResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(results))
}

func outputSearchText(cmd *cobra.Command, results []database.SearchResult) {
	// Find max name length for alignment
	maxNameLen := 0
	for _, r := range results {
		if len(r.Name) > maxNameLen {
			maxNameLen = len(r.Name)
		}
	}

	for _, r := range results {
		firstSeen := ""
		if len(r.FirstSeen) >= datePrefixLen {
			firstSeen = r.FirstSeen[:datePrefixLen]
		}
		lastChanged := ""
		if len(r.LastChanged) >= datePrefixLen {
			lastChanged = r.LastChanged[:datePrefixLen]
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
}
