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
	diffCmd.Flags().String("by", diffByManifest, "Match dependencies by: manifest, ecosystem")
	diffCmd.Flags().Bool("stat", false, "Show aggregate dependency change counts")
	diffCmd.Flags().Bool("summary", false, "Show aggregate dependency change counts")
	parent.AddCommand(diffCmd)
}

const (
	diffByManifest  = "manifest"
	diffByEcosystem = "ecosystem"
)

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

type DiffStat struct {
	Added        int `json:"added"`
	Removed      int `json:"removed"`
	Updated      int `json:"updated"`
	MajorUpdates int `json:"major_updates"`
	MinorUpdates int `json:"minor_updates"`
	PatchUpdates int `json:"patch_updates"`
	OtherUpdates int `json:"other_updates"`
}

func runDiff(cmd *cobra.Command, args []string) error {
	fromRef, _ := cmd.Flags().GetString("from")
	toRef, _ := cmd.Flags().GetString("to")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	depType, _ := cmd.Flags().GetString("type")
	format, _ := cmd.Flags().GetString("format")
	by, _ := cmd.Flags().GetString("by")
	stat, _ := cmd.Flags().GetBool("stat")
	summary, _ := cmd.Flags().GetBool("summary")
	includeSubmodules, _ := cmd.Flags().GetBool("include-submodules")

	if by != diffByManifest && by != diffByEcosystem {
		return fmt.Errorf("--by must be one of: %s, %s", diffByManifest, diffByEcosystem)
	}

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
		fromRef = refHEAD
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
		result, err = diffWithWorkingTree(repo, fromRef, includeSubmodules, by)
	} else {
		result, err = diffBetweenCommits(repo, fromRef, toRef, by)
	}
	if err != nil {
		return err
	}

	// Apply filters
	if ecosystem != "" || depType != "" {
		result = filterDiffResult(result, ecosystem, depType)
	}

	if stat || summary {
		outputDiffStat(cmd, buildDiffStat(result))
		return nil
	}

	// Output
	switch format {
	case formatJSON:
		return outputDiffJSON(cmd, result)
	default:
		if len(result.Added) == 0 && len(result.Modified) == 0 && len(result.Removed) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependency changes.")
			return nil
		}
		return outputDiffText(cmd, result)
	}
}

// diffBetweenCommits compares dependencies between two commits using on-demand indexing.
func diffBetweenCommits(repo *git.Repository, fromRef, toRef, by string) (*DiffResult, error) {
	fromDeps, err := repo.GetDependencies(fromRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", fromRef, err)
	}

	toDeps, err := repo.GetDependencies(toRef, "")
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", toRef, err)
	}

	return computeDiffBy(fromDeps, toDeps, by), nil
}

// diffWithWorkingTree compares dependencies between a commit and the working tree.
func diffWithWorkingTree(repo *git.Repository, fromRef string, includeSubmodules bool, by string) (*DiffResult, error) {
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

	return computeDiffBy(fromDeps, toDeps, by), nil
}

func changesToDeps(changes []analyzer.Change) []database.Dependency {
	var deps []database.Dependency
	for _, c := range changes {
		deps = append(deps, database.Dependency{
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			PURL:           c.PURL,
			Requirement:    c.Requirement,
			ManifestPath:   c.ManifestPath,
			ManifestKind:   c.Kind,
			DependencyType: c.DependencyType,
		})
	}
	return deps
}

func computeDiff(fromDeps, toDeps []database.Dependency) *DiffResult {
	return computeDiffBy(fromDeps, toDeps, diffByManifest)
}

func computeDiffBy(fromDeps, toDeps []database.Dependency, by string) *DiffResult {
	result := &DiffResult{}

	// Build multi-maps keyed by the selected matching mode, since lockfiles
	// can contain the same package at multiple versions (e.g. npm hoisting).
	fromMulti := make(map[diffDepKey][]database.Dependency)
	for _, d := range fromDeps {
		key := diffDepKeyFor(d, by)
		fromMulti[key] = append(fromMulti[key], d)
	}

	toMulti := make(map[diffDepKey][]database.Dependency)
	for _, d := range toDeps {
		key := diffDepKeyFor(d, by)
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

		// Multiple versions on at least one side: count occurrences of each
		// version and pair net removals with net additions as Modified.
		fromCounts := make(map[string]int, len(fromList))
		for _, d := range fromList {
			fromCounts[d.Requirement]++
		}
		toCounts := make(map[string]int, len(toList))
		for _, d := range toList {
			toCounts[d.Requirement]++
		}

		// Use the first entry as a template for metadata.
		ref := toList[0]

		// Build lists of individual net removals and net additions.
		var removedVersions []string
		var addedVersions []string

		// Versions that decreased in count or disappeared entirely.
		for ver, fc := range fromCounts {
			tc := toCounts[ver]
			if delta := fc - tc; delta > 0 {
				for i := 0; i < delta; i++ {
					removedVersions = append(removedVersions, ver)
				}
			}
		}
		// Versions that increased in count or appeared for the first time.
		for ver, tc := range toCounts {
			fc := fromCounts[ver]
			if delta := tc - fc; delta > 0 {
				for i := 0; i < delta; i++ {
					addedVersions = append(addedVersions, ver)
				}
			}
		}

		// Sort for deterministic pairing.
		sort.Strings(removedVersions)
		sort.Strings(addedVersions)

		// Pair removals with additions as Modified.
		paired := len(removedVersions)
		if len(addedVersions) < paired {
			paired = len(addedVersions)
		}
		for i := 0; i < paired; i++ {
			result.Modified = append(result.Modified, DiffEntry{
				Name:            ref.Name,
				Ecosystem:       ref.Ecosystem,
				ManifestPath:    ref.ManifestPath,
				DependencyType:  ref.DependencyType,
				FromRequirement: removedVersions[i],
				ToRequirement:   addedVersions[i],
			})
		}
		// Surplus additions.
		for i := paired; i < len(addedVersions); i++ {
			result.Added = append(result.Added, DiffEntry{
				Name:           ref.Name,
				Ecosystem:      ref.Ecosystem,
				ManifestPath:   ref.ManifestPath,
				DependencyType: ref.DependencyType,
				ToRequirement:  addedVersions[i],
			})
		}
		// Surplus removals.
		for i := paired; i < len(removedVersions); i++ {
			result.Removed = append(result.Removed, DiffEntry{
				Name:            ref.Name,
				Ecosystem:       ref.Ecosystem,
				ManifestPath:    ref.ManifestPath,
				DependencyType:  ref.DependencyType,
				FromRequirement: removedVersions[i],
			})
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

type diffDepKey struct {
	ManifestPath string
	Ecosystem    string
	Name         string
}

func diffDepKeyFor(d database.Dependency, by string) diffDepKey {
	if by == diffByEcosystem {
		return diffDepKey{Ecosystem: d.Ecosystem, Name: d.Name}
	}
	return diffDepKey{ManifestPath: d.ManifestPath, Name: d.Name}
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

func buildDiffStat(result *DiffResult) DiffStat {
	stat := DiffStat{
		Added:   len(result.Added),
		Removed: len(result.Removed),
		Updated: len(result.Modified),
	}

	for _, entry := range result.Modified {
		switch classifyUpdate(entry.FromRequirement, entry.ToRequirement) {
		case updateMajor:
			stat.MajorUpdates++
		case updateMinor:
			stat.MinorUpdates++
		case updatePatch:
			stat.PatchUpdates++
		default:
			stat.OtherUpdates++
		}
	}

	return stat
}

func outputDiffStat(cmd *cobra.Command, stat DiffStat) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s, %s, %s",
		formatCount(stat.Added, "added"),
		formatCount(stat.Removed, "removed"),
		formatCount(stat.Updated, "updated"))

	parts := diffUpdateStatParts(stat)
	if len(parts) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), " (%s)", strings.Join(parts, ", "))
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
}

func diffUpdateStatParts(stat DiffStat) []string {
	parts := make([]string, 0, 4) //nolint:mnd
	if stat.MajorUpdates > 0 {
		parts = append(parts, formatCount(stat.MajorUpdates, updateMajor))
	}
	if stat.MinorUpdates > 0 {
		parts = append(parts, formatCount(stat.MinorUpdates, updateMinor))
	}
	if stat.PatchUpdates > 0 {
		parts = append(parts, formatCount(stat.PatchUpdates, updatePatch))
	}
	if stat.OtherUpdates > 0 {
		parts = append(parts, formatCount(stat.OtherUpdates, "other"))
	}
	return parts
}

func formatCount(count int, label string) string {
	return fmt.Sprintf("%d %s", count, label)
}

func outputDiffText(cmd *cobra.Command, result *DiffResult) error {
	if len(result.Added) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), Bold("Added:"))
		for _, e := range result.Added {
			line := fmt.Sprintf("  %s %s", Green("+"), Green(e.Name))
			if e.ToRequirement != "" {
				line += fmt.Sprintf(" %s", e.ToRequirement)
			}
			if e.DependencyType != "" && e.DependencyType != depTypeRuntime {
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
			if e.DependencyType != "" && e.DependencyType != depTypeRuntime {
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
			if e.DependencyType != "" && e.DependencyType != depTypeRuntime {
				line += fmt.Sprintf(" [%s]", e.DependencyType)
			}
			line += fmt.Sprintf(" %s", Dim("("+e.ManifestPath+")"))
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
