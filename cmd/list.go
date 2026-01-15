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
	addListCmd(rootCmd)
}

func addListCmd(parent *cobra.Command) {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List dependencies at a commit",
		Long: `List all dependencies at a specific commit.
Defaults to HEAD if no commit is specified.`,
		RunE: runList,
	}

	listCmd.Flags().String("commit", "", "Commit SHA to show dependencies at (default: HEAD)")
	listCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	listCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	listCmd.Flags().StringP("manifest", "m", "", "Filter by manifest path")
	listCmd.Flags().StringP("type", "t", "", "Filter by dependency type (runtime, development, etc.)")
	listCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	listCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
	parent.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	commitRef, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	manifest, _ := cmd.Flags().GetString("manifest")
	depType, _ := cmd.Flags().GetString("type")
	format, _ := cmd.Flags().GetString("format")
	stateless, _ := cmd.Flags().GetBool("stateless")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var deps []database.Dependency

	if stateless {
		deps, err = listStateless(repo, commitRef)
	} else {
		deps, err = listFromDB(repo, commitRef, branchName)
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

func listFromDB(repo *git.Repository, commitRef, branchName string) ([]database.Dependency, error) {
	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return nil, fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	var branchInfo *database.BranchInfo
	if branchName != "" {
		branchInfo, err = db.GetBranch(branchName)
		if err != nil {
			return nil, fmt.Errorf("branch %q not found: %w", branchName, err)
		}
	} else {
		branchInfo, err = db.GetDefaultBranch()
		if err != nil {
			return nil, fmt.Errorf("getting branch: %w", err)
		}
	}

	if commitRef == "" {
		return db.GetLatestDependencies(branchInfo.ID)
	}

	// Resolve the ref to a full SHA
	hash, err := repo.ResolveRevision(commitRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", commitRef, err)
	}

	return db.GetDependenciesAtRef(hash.String(), branchInfo.ID)
}

func listStateless(repo *git.Repository, commitRef string) ([]database.Dependency, error) {
	if commitRef == "" {
		commitRef = "HEAD"
	}

	hash, err := repo.ResolveRevision(commitRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", commitRef, err)
	}

	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit: %w", err)
	}

	a := analyzer.New()
	changes, err := a.DependenciesAtCommit(commit)
	if err != nil {
		return nil, fmt.Errorf("analyzing commit: %w", err)
	}

	var deps []database.Dependency
	for _, c := range changes {
		deps = append(deps, database.Dependency{
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			PURL:           c.PURL,
			Requirement:    c.Requirement,
			DependencyType: c.DependencyType,
			Integrity:      c.Integrity,
			ManifestPath:   c.ManifestPath,
			ManifestKind:   c.Kind,
		})
	}

	return deps, nil
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
