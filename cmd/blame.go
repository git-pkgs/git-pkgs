package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addBlameCmd(rootCmd)
}

func addBlameCmd(parent *cobra.Command) {
	blameCmd := &cobra.Command{
		Use:   "blame",
		Short: "Show who added each dependency",
		Long:  `Show the commit and author that first added each current dependency.`,
		RunE:  runBlame,
	}

	blameCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	blameCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	blameCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(blameCmd)
}

func runBlame(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
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

	entries, err := db.GetBlame(branchInfo.ID, ecosystem)
	if err != nil {
		return fmt.Errorf("getting blame: %w", err)
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies found.")
		return nil
	}

	switch format {
	case "json":
		return outputBlameJSON(cmd, entries)
	default:
		return outputBlameText(cmd, entries)
	}
}

func outputBlameJSON(cmd *cobra.Command, entries []database.BlameEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func outputBlameText(cmd *cobra.Command, entries []database.BlameEntry) error {
	// Group by manifest
	byManifest := make(map[string][]database.BlameEntry)
	var manifestOrder []string

	for _, e := range entries {
		if _, exists := byManifest[e.ManifestPath]; !exists {
			manifestOrder = append(manifestOrder, e.ManifestPath)
		}
		byManifest[e.ManifestPath] = append(byManifest[e.ManifestPath], e)
	}

	// Find max name length for alignment
	maxNameLen := 0
	for _, e := range entries {
		if len(e.Name) > maxNameLen {
			maxNameLen = len(e.Name)
		}
	}

	// Find max author name length
	maxAuthorLen := 0
	for _, e := range entries {
		if len(e.AuthorName) > maxAuthorLen {
			maxAuthorLen = len(e.AuthorName)
		}
	}

	for _, manifestPath := range manifestOrder {
		manifestEntries := byManifest[manifestPath]
		ecosystem := ""
		if len(manifestEntries) > 0 {
			ecosystem = manifestEntries[0].Ecosystem
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s):\n", manifestPath, ecosystem)

		for _, e := range manifestEntries {
			date := e.CommittedAt[:10]
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-*s  %-*s  %s  %s\n",
				maxNameLen, e.Name,
				maxAuthorLen, e.AuthorName,
				date,
				e.SHA[:7])
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
