package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addShowCmd(rootCmd)
}

func addShowCmd(parent *cobra.Command) {
	showCmd := &cobra.Command{
		Use:   "show [commit]",
		Short: "Show dependency changes in a commit",
		Long: `Show all dependency changes introduced in a specific commit.
Defaults to HEAD if no commit is specified.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runShow,
	}

	showCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	showCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	showCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
	parent.AddCommand(showCmd)
}

func runShow(cmd *cobra.Command, args []string) error {
	commitRef := "HEAD"
	if len(args) > 0 {
		commitRef = args[0]
	}

	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	stateless, _ := cmd.Flags().GetBool("stateless")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var changes []database.Change

	if stateless {
		changes, err = showStateless(repo, commitRef)
	} else {
		changes, err = showFromDB(repo, commitRef)
	}
	if err != nil {
		return err
	}

	// Apply ecosystem filter
	if ecosystem != "" {
		var filtered []database.Change
		for _, c := range changes {
			if strings.EqualFold(c.Ecosystem, ecosystem) {
				filtered = append(filtered, c)
			}
		}
		changes = filtered
	}

	if len(changes) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependency changes in this commit.")
		return nil
	}

	// Output
	switch format {
	case "json":
		return outputShowJSON(cmd, changes)
	default:
		return outputShowText(cmd, changes)
	}
}

func showFromDB(repo *git.Repository, commitRef string) ([]database.Change, error) {
	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return nil, fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Resolve the ref to a full SHA
	hash, err := repo.ResolveRevision(commitRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", commitRef, err)
	}

	return db.GetChangesForCommit(hash.String())
}

func showStateless(repo *git.Repository, commitRef string) ([]database.Change, error) {
	hash, err := repo.ResolveRevision(commitRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", commitRef, err)
	}

	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit: %w", err)
	}

	a := analyzer.New()
	result, err := a.AnalyzeCommit(commit, nil)
	if err != nil {
		return nil, fmt.Errorf("analyzing commit: %w", err)
	}

	if result == nil {
		return nil, nil
	}

	var changes []database.Change
	for _, c := range result.Changes {
		changes = append(changes, database.Change{
			Name:                c.Name,
			Ecosystem:           c.Ecosystem,
			PURL:                c.PURL,
			ChangeType:          c.ChangeType,
			Requirement:         c.Requirement,
			PreviousRequirement: c.PreviousRequirement,
			DependencyType:      c.DependencyType,
			ManifestPath:        c.ManifestPath,
		})
	}

	return changes, nil
}

func outputShowJSON(cmd *cobra.Command, changes []database.Change) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(changes)
}

func outputShowText(cmd *cobra.Command, changes []database.Change) error {
	// Group by manifest
	byManifest := make(map[string][]database.Change)
	var manifestOrder []string

	for _, c := range changes {
		if _, exists := byManifest[c.ManifestPath]; !exists {
			manifestOrder = append(manifestOrder, c.ManifestPath)
		}
		byManifest[c.ManifestPath] = append(byManifest[c.ManifestPath], c)
	}

	for _, manifestPath := range manifestOrder {
		manifestChanges := byManifest[manifestPath]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:\n", manifestPath)

		for _, c := range manifestChanges {
			var prefix string
			switch c.ChangeType {
			case "added":
				prefix = "+"
			case "removed":
				prefix = "-"
			case "modified":
				prefix = "~"
			default:
				prefix = " "
			}

			line := fmt.Sprintf("  %s %s", prefix, c.Name)
			if c.ChangeType == "modified" && c.PreviousRequirement != "" {
				line += fmt.Sprintf(" %s -> %s", c.PreviousRequirement, c.Requirement)
			} else if c.Requirement != "" {
				line += fmt.Sprintf(" %s", c.Requirement)
			}

			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
