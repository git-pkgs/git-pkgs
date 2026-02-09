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
	diffCmd.Flags().StringP("type", "t", "", "Filter by dependency type (runtime, development, etc.)")
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
	DependencyType  string `json:"dependency_type,omitempty"`
	FromRequirement string `json:"from_requirement,omitempty"`
	ToRequirement   string `json:"to_requirement,omitempty"`
}

func runDiff(cmd *cobra.Command, args []string) error {
	fromRef, _ := cmd.Flags().GetString("from")
	toRef, _ := cmd.Flags().GetString("to")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	depType, _ := cmd.Flags().GetString("type")
	format, _ := cmd.Flags().GetString("format")
	includeSubmodules, _ := cmd.Flags().GetBool("include-submodules")

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
		result, err = diffWithWorkingTree(repo, fromRef, includeSubmodules)
	} else {
		result, err = diffBetweenCommits(repo, fromRef, toRef)
	}
	if err != nil {
		return err
	}

	// Apply filters
	if ecosystem != "" || depType != "" {
		result = filterDiffResult(result, ecosystem, depType)
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
func diffWithWorkingTree(repo *git.Repository, fromRef string, includeSubmodules bool) (*DiffResult, error) {
	fromDeps, err := repo.GetDependencies(fromRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", fromRef, err)
	}

	// Parse working tree directly
	a := analyzer.New()
	toChanges, err := a.DependenciesInWorkingDir(repo.WorkDir(), includeSubmodules)
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

	// Build multi-maps keyed by manifest:name, since lockfiles can contain
	// the same package at multiple versions (e.g. npm dependency hoisting).
	type depKey struct {
		ManifestPath string
		Name         string
	}

	fromMulti := make(map[depKey][]database.Dependency)
	for _, d := range fromDeps {
		key := depKey{d.ManifestPath, d.Name}
		fromMulti[key] = append(fromMulti[key], d)
	}

	toMulti := make(map[depKey][]database.Dependency)
	for _, d := range toDeps {
		key := depKey{d.ManifestPath, d.Name}
		toMulti[key] = append(toMulti[key], d)
	}

	// Find added and modified
	for key, toList := range toMulti {
		fromList, exists := fromMulti[key]
		if !exists {
			// Entirely new package
			for _, d := range toList {
				result.Added = append(result.Added, DiffEntry{
					Name:           d.Name,
					Ecosystem:      d.Ecosystem,
					ManifestPath:   d.ManifestPath,
					DependencyType: d.DependencyType,
					ToRequirement:  d.Requirement,
				})
			}
			continue
		}

		// Single version on each side: compare directly (shows "modified")
		if len(fromList) == 1 && len(toList) == 1 {
			if fromList[0].Requirement != toList[0].Requirement {
				result.Modified = append(result.Modified, DiffEntry{
					Name:            toList[0].Name,
					Ecosystem:       toList[0].Ecosystem,
					ManifestPath:    toList[0].ManifestPath,
					DependencyType:  toList[0].DependencyType,
					FromRequirement: fromList[0].Requirement,
					ToRequirement:   toList[0].Requirement,
				})
			}
			continue
		}

		// Multiple versions on at least one side: compare version sets
		fromVersions := make(map[string]bool, len(fromList))
		for _, d := range fromList {
			fromVersions[d.Requirement] = true
		}
		toVersions := make(map[string]bool, len(toList))
		for _, d := range toList {
			toVersions[d.Requirement] = true
		}

		for _, d := range toList {
			if !fromVersions[d.Requirement] {
				result.Added = append(result.Added, DiffEntry{
					Name:           d.Name,
					Ecosystem:      d.Ecosystem,
					ManifestPath:   d.ManifestPath,
					DependencyType: d.DependencyType,
					ToRequirement:  d.Requirement,
				})
			}
		}
		for _, d := range fromList {
			if !toVersions[d.Requirement] {
				result.Removed = append(result.Removed, DiffEntry{
					Name:            d.Name,
					Ecosystem:       d.Ecosystem,
					ManifestPath:    d.ManifestPath,
					DependencyType:  d.DependencyType,
					FromRequirement: d.Requirement,
				})
			}
		}
	}

	// Find removed (packages not in toMulti at all)
	for key, fromList := range fromMulti {
		if _, exists := toMulti[key]; !exists {
			for _, d := range fromList {
				result.Removed = append(result.Removed, DiffEntry{
					Name:            d.Name,
					Ecosystem:       d.Ecosystem,
					ManifestPath:    d.ManifestPath,
					DependencyType:  d.DependencyType,
					FromRequirement: d.Requirement,
				})
			}
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

func filterDiffResult(result *DiffResult, ecosystem, depType string) *DiffResult {
	filtered := &DiffResult{}

	for _, e := range result.Added {
		if ecosystem != "" && !strings.EqualFold(e.Ecosystem, ecosystem) {
			continue
		}
		if depType != "" && !strings.EqualFold(e.DependencyType, depType) {
			continue
		}
		filtered.Added = append(filtered.Added, e)
	}
	for _, e := range result.Modified {
		if ecosystem != "" && !strings.EqualFold(e.Ecosystem, ecosystem) {
			continue
		}
		if depType != "" && !strings.EqualFold(e.DependencyType, depType) {
			continue
		}
		filtered.Modified = append(filtered.Modified, e)
	}
	for _, e := range result.Removed {
		if ecosystem != "" && !strings.EqualFold(e.Ecosystem, ecosystem) {
			continue
		}
		if depType != "" && !strings.EqualFold(e.DependencyType, depType) {
			continue
		}
		filtered.Removed = append(filtered.Removed, e)
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
			if e.DependencyType != "" && e.DependencyType != "runtime" {
				line += fmt.Sprintf(" [%s]", e.DependencyType)
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
			if e.DependencyType != "" && e.DependencyType != "runtime" {
				line += fmt.Sprintf(" [%s]", e.DependencyType)
			}
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
			if e.DependencyType != "" && e.DependencyType != "runtime" {
				line += fmt.Sprintf(" [%s]", e.DependencyType)
			}
			line += fmt.Sprintf(" %s", Dim("("+e.ManifestPath+")"))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
