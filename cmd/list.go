package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func addListCmd(parent *cobra.Command) {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List dependencies at a commit",
		Long: `List all dependencies at a specific commit.
Defaults to HEAD if no commit is specified.`,
		RunE: runList,
	}

	listCmd.Flags().String("commit", "", "Commit SHA to show dependencies at (default: HEAD)")
	listCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	listCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	listCmd.Flags().StringP("manifest", "m", "", "Filter by manifest path")
	listCmd.Flags().StringP("type", "t", "", "Filter by dependency type (runtime, development, etc.)")
	listCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	commitRef, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	manifest, _ := cmd.Flags().GetString("manifest")
	depType, _ := cmd.Flags().GetString("type")
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	deps, db, err := repo.GetDependenciesWithDB(commitRef, branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return err
	}

	// Apply filters
	deps = filterDependencies(deps, ecosystem, manifest, depType)

	// Output
	switch format {
	case "json":
		return outputListJSON(cmd, deps)
	default:
		return outputListText(cmd, deps)
	}
}

func filterDependencies(deps []database.Dependency, ecosystem, manifest, depType string) []database.Dependency {
	if ecosystem == "" && manifest == "" && depType == "" {
		return deps
	}

	var filtered []database.Dependency
	for _, d := range deps {
		if ecosystem != "" && !strings.EqualFold(d.Ecosystem, ecosystem) {
			continue
		}
		if manifest != "" && !strings.Contains(d.ManifestPath, manifest) {
			continue
		}
		if depType != "" && !strings.EqualFold(d.DependencyType, depType) {
			continue
		}
		filtered = append(filtered, d)
	}
	return filtered
}

func outputListJSON(cmd *cobra.Command, deps []database.Dependency) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(deps)
}

func outputListText(cmd *cobra.Command, deps []database.Dependency) error {
	// Group by manifest
	byManifest := make(map[string][]database.Dependency)
	var manifestOrder []string

	for _, d := range deps {
		if _, exists := byManifest[d.ManifestPath]; !exists {
			manifestOrder = append(manifestOrder, d.ManifestPath)
		}
		byManifest[d.ManifestPath] = append(byManifest[d.ManifestPath], d)
	}

	for _, manifestPath := range manifestOrder {
		manifestDeps := byManifest[manifestPath]
		ecosystem := ""
		if len(manifestDeps) > 0 {
			ecosystem = manifestDeps[0].Ecosystem
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s):\n", manifestPath, ecosystem)

		for _, d := range manifestDeps {
			line := fmt.Sprintf("  %s", d.Name)
			if d.Requirement != "" {
				line += fmt.Sprintf(" %s", d.Requirement)
			}
			if d.DependencyType != "" && d.DependencyType != "runtime" {
				line += fmt.Sprintf(" [%s]", d.DependencyType)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
