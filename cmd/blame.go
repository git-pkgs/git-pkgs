package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
)

func addBlameCmd(parent *cobra.Command) {
	blameCmd := &cobra.Command{
		Use:     "blame",
		Aliases: []string{"praise"},
		Short:   "Show who added each dependency",
		Long:    `Show the commit and author that first added each current dependency.`,
		RunE:    runBlame,
	}

	blameCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	blameCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	blameCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	blameCmd.Flags().Bool("exclude-bots", false, "Exclude dependencies first added by bot authors")
	parent.AddCommand(blameCmd)
}

func runBlame(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	excludeBots, _ := cmd.Flags().GetBool("exclude-bots")

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	entries, err := db.GetBlame(database.BlameOptions{
		BranchID:    branchInfo.ID,
		Ecosystem:   ecosystem,
		ExcludeBots: excludeBots,
	})
	if err != nil {
		return fmt.Errorf("getting blame: %w", err)
	}

	switch format {
	case formatJSON:
		return outputBlameJSON(cmd, entries)
	default:
		if len(entries) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies found.")
			return nil
		}
		outputBlameText(cmd, entries)
		return nil
	}
}

func outputBlameJSON(cmd *cobra.Command, entries []database.BlameEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(entries))
}

func outputBlameText(cmd *cobra.Command, entries []database.BlameEntry) {
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
				shortSHA(e.SHA))
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}
