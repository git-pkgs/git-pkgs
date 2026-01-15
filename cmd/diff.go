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
	addDiffCmd(rootCmd)
}

func addDiffCmd(parent *cobra.Command) {
	diffCmd := &cobra.Command{
		Use:   "diff [from..to]",
		Short: "Compare dependencies between two commits",
		Long: `Compare dependencies between two commits or refs.
Supports range syntax (main..feature) or explicit --from/--to flags.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runDiff,
	}

	diffCmd.Flags().String("from", "", "Starting commit (default: HEAD~1)")
	diffCmd.Flags().String("to", "", "Ending commit (default: HEAD)")
	diffCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	diffCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	diffCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
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
	stateless, _ := cmd.Flags().GetBool("stateless")

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
		fromRef = "HEAD~1"
	}
	if toRef == "" {
		toRef = "HEAD"
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var result *DiffResult

	if stateless {
		result, err = diffStateless(repo, fromRef, toRef)
	} else {
		result, err = diffFromDB(repo, fromRef, toRef)
	}
	if err != nil {
		return err
	}

	// Apply ecosystem filter
	if ecosystem != "" {
		result = filterDiffResult(result, ecosystem)
	}

	if len(result.Added) == 0 && len(result.Modified) == 0 && len(result.Removed) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependency changes between these commits.")
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

func diffFromDB(repo *git.Repository, fromRef, toRef string) (*DiffResult, error) {
	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return nil, fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return nil, fmt.Errorf("getting branch: %w", err)
	}

	// Resolve refs
	fromHash, err := repo.ResolveRevision(fromRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", fromRef, err)
	}
	toHash, err := repo.ResolveRevision(toRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", toRef, err)
	}

	fromDeps, err := db.GetDependenciesAtRef(fromHash.String(), branchInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", fromRef, err)
	}
	toDeps, err := db.GetDependenciesAtRef(toHash.String(), branchInfo.ID)
	if err != nil {
		return nil, fmt.Errorf("getting deps at %s: %w", toRef, err)
	}

	return computeDiff(fromDeps, toDeps), nil
}

func diffStateless(repo *git.Repository, fromRef, toRef string) (*DiffResult, error) {
	fromHash, err := repo.ResolveRevision(fromRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", fromRef, err)
	}
	toHash, err := repo.ResolveRevision(toRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", toRef, err)
	}

	fromCommit, err := repo.CommitObject(*fromHash)
	if err != nil {
		return nil, fmt.Errorf("getting from commit: %w", err)
	}
	toCommit, err := repo.CommitObject(*toHash)
	if err != nil {
		return nil, fmt.Errorf("getting to commit: %w", err)
	}

	a := analyzer.New()

	fromChanges, err := a.DependenciesAtCommit(fromCommit)
	if err != nil {
		return nil, fmt.Errorf("analyzing from commit: %w", err)
	}
	toChanges, err := a.DependenciesAtCommit(toCommit)
	if err != nil {
		return nil, fmt.Errorf("analyzing to commit: %w", err)
	}

	// Convert to database.Dependency
	var fromDeps, toDeps []database.Dependency
	for _, c := range fromChanges {
		fromDeps = append(fromDeps, database.Dependency{
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			Requirement:    c.Requirement,
			ManifestPath:   c.ManifestPath,
			DependencyType: c.DependencyType,
		})
	}
	for _, c := range toChanges {
		toDeps = append(toDeps, database.Dependency{
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			Requirement:    c.Requirement,
			ManifestPath:   c.ManifestPath,
			DependencyType: c.DependencyType,
		})
	}

	return computeDiff(fromDeps, toDeps), nil
}

func computeDiff(fromDeps, toDeps []database.Dependency) *DiffResult {
	result := &DiffResult{}

	// Build maps keyed by manifest:name
	fromMap := make(map[string]database.Dependency)
	for _, d := range fromDeps {
		key := d.ManifestPath + ":" + d.Name
		fromMap[key] = d
	}

	toMap := make(map[string]database.Dependency)
	for _, d := range toDeps {
		key := d.ManifestPath + ":" + d.Name
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

	return result
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
