package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func addDiffCmd(parent *cobra.Command) {
	diffCmd := &cobra.Command{
		Use:   "diff [from..to]",
		Short: "Compare dependencies between commits or working tree",
		Long: `Compare dependencies between two commits, refs, or the working tree.
With no arguments, compares HEAD against the working tree (like git diff).
Supports range syntax (main..feature) or explicit --from/--to flags.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDiff,
	}

	diffCmd.Flags().String("from", "", "Starting commit (default: HEAD)")
	diffCmd.Flags().String("to", "", "Ending commit (default: working tree)")
	diffCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	diffCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(diffCmd)
}

type DiffResult struct {
	Added    []DiffEntry `json:"added,omitempty"`
	Modified []DiffEntry `json:"modified,omitempty"`
	Removed  []DiffEntry `json:"removed,omitempty"`
}

type DiffEntry struct {
	Name            string `json:"name"`
	Ecosystem       string `json:"ecosystem,omitempty"`
	ManifestPath    string `json:"manifest_path"`
	FromRequirement string `json:"from_requirement,omitempty"`
	ToRequirement   string `json:"to_requirement,omitempty"`
}

func runDiff(cmd *cobra.Command, args []string) error {
	fromRef, _ := cmd.Flags().GetString("from")
	toRef, _ := cmd.Flags().GetString("to")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")

	// Parse range syntax if provided
	if len(args) > 0 {
		parts := strings.Split(args[0], "..")
		if len(parts) == 2 {
			fromRef = parts[0]
			toRef = parts[1]
		} else {
			fromRef = args[0]
		}
	}

	// Set defaults
	if fromRef == "" {
		fromRef = "HEAD"
	}
	// toRef "" means working tree

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var result *DiffResult

	// When comparing to working tree, use direct parsing since there's
	// no database state for uncommitted changes
	if toRef == "" {
		result, err = diffWithWorkingTree(repo, fromRef)
	} else {
		result, err = diffBetweenCommits(repo, fromRef, toRef)
	}
	if err != nil {
		return err
	}

	// Apply ecosystem filter
	if ecosystem != "" {
		result = filterDiffResult(result, ecosystem)
	}

	if len(result.Added) == 0 && len(result.Modified) == 0 && len(result.Removed) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependency changes.")
		return nil
	}

	// Output
	switch format {
	case "json":
		return outputDiffJSON(cmd, result)
	default:
		return outputDiffText(cmd, result)
	}
}

// diffBetweenCommits compares dependencies between two commits using on-demand indexing.
func diffBetweenCommits(repo *git.Repository, fromRef, toRef string) (*DiffResult, error) {
	fromDeps, err := repo.GetDependencies( fromRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", fromRef, err)
	}

	toDeps, err := repo.GetDependencies( toRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", toRef, err)
	}

	return computeDiff(fromDeps, toDeps), nil
}

// diffWithWorkingTree compares dependencies between a commit and the working tree.
func diffWithWorkingTree(repo *git.Repository, fromRef string) (*DiffResult, error) {
	fromDeps, err := repo.GetDependencies( fromRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", fromRef, err)
	}

	// Parse working tree directly
	a := analyzer.New()
	toChanges, err := a.DependenciesInWorkingDir(repo.WorkDir())
	if err != nil {
		return nil, fmt.Errorf("reading working tree: %w", err)
	}
	toDeps := changesToDeps(toChanges)

	return computeDiff(fromDeps, toDeps), nil
}

func changesToDeps(changes []analyzer.Change) []database.Dependency {
	var deps []database.Dependency
	for _, c := range changes {
		deps = append(deps, database.Dependency{
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			Requirement:    c.Requirement,
			ManifestPath:   c.ManifestPath,
			DependencyType: c.DependencyType,
		})
	}
	return deps
}

func computeDiff(fromDeps, toDeps []database.Dependency) *DiffResult {
	result := &DiffResult{}

	// Build maps keyed by manifest:name:requirement to handle packages that appear
	// multiple times with different versions (e.g., npm nested dependencies)
	fromMap := make(map[string]database.Dependency)
	for _, d := range fromDeps {
		key := d.ManifestPath + ":" + d.Name + ":" + d.Requirement
		fromMap[key] = d
	}

	toMap := make(map[string]database.Dependency)
	for _, d := range toDeps {
		key := d.ManifestPath + ":" + d.Name + ":" + d.Requirement
		toMap[key] = d
	}

	// Find added and modified
	for key, toDep := range toMap {
		if fromDep, exists := fromMap[key]; exists {
			if fromDep.Requirement != toDep.Requirement {
				result.Modified = append(result.Modified, DiffEntry{
					Name:            toDep.Name,
					Ecosystem:       toDep.Ecosystem,
					ManifestPath:    toDep.ManifestPath,
					FromRequirement: fromDep.Requirement,
					ToRequirement:   toDep.Requirement,
				})
			}
		} else {
			result.Added = append(result.Added, DiffEntry{
				Name:          toDep.Name,
				Ecosystem:     toDep.Ecosystem,
				ManifestPath:  toDep.ManifestPath,
				ToRequirement: toDep.Requirement,
			})
		}
	}

	// Find removed
	for key, fromDep := range fromMap {
		if _, exists := toMap[key]; !exists {
			result.Removed = append(result.Removed, DiffEntry{
				Name:            fromDep.Name,
				Ecosystem:       fromDep.Ecosystem,
				ManifestPath:    fromDep.ManifestPath,
				FromRequirement: fromDep.Requirement,
			})
		}
	}

	// Sort results for deterministic output
	sortDiffEntries(result.Added)
	sortDiffEntries(result.Modified)
	sortDiffEntries(result.Removed)

	return result
}

func sortDiffEntries(entries []DiffEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ManifestPath != entries[j].ManifestPath {
			return entries[i].ManifestPath < entries[j].ManifestPath
		}
		return entries[i].Name < entries[j].Name
	})
}

func filterDiffResult(result *DiffResult, ecosystem string) *DiffResult {
	filtered := &DiffResult{}

	for _, e := range result.Added {
		if strings.EqualFold(e.Ecosystem, ecosystem) {
			filtered.Added = append(filtered.Added, e)
		}
	}
	for _, e := range result.Modified {
		if strings.EqualFold(e.Ecosystem, ecosystem) {
			filtered.Modified = append(filtered.Modified, e)
		}
	}
	for _, e := range result.Removed {
		if strings.EqualFold(e.Ecosystem, ecosystem) {
			filtered.Removed = append(filtered.Removed, e)
		}
	}

	return filtered
}

func outputDiffJSON(cmd *cobra.Command, result *DiffResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputDiffText(cmd *cobra.Command, result *DiffResult) error {
	if len(result.Added) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), Bold("Added:"))
		for _, e := range result.Added {
			line := fmt.Sprintf("  %s %s", Green("+"), Green(e.Name))
			if e.ToRequirement != "" {
				line += fmt.Sprintf(" %s", e.ToRequirement)
			}
			line += fmt.Sprintf(" %s", Dim("("+e.ManifestPath+")"))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(result.Modified) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), Bold("Modified:"))
		for _, e := range result.Modified {
			line := fmt.Sprintf("  %s %s %s -> %s", Yellow("~"), Yellow(e.Name), Dim(e.FromRequirement), e.ToRequirement)
			line += fmt.Sprintf(" %s", Dim("("+e.ManifestPath+")"))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(result.Removed) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), Bold("Removed:"))
		for _, e := range result.Removed {
			line := fmt.Sprintf("  %s %s", Red("-"), Red(e.Name))
			if e.FromRequirement != "" {
				line += fmt.Sprintf(" %s", e.FromRequirement)
			}
			line += fmt.Sprintf(" %s", Dim("("+e.ManifestPath+")"))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
