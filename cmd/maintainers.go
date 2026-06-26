package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/spf13/cobra"
)

const maintainerLookupTimeout = 5 * time.Minute

func addMaintainersCmd(parent *cobra.Command) {
	maintainersCmd := &cobra.Command{
		Use:   "maintainers",
		Short: "Show dependency maintainer information",
		Long:  `Fetch package maintainer metadata and show maintainer counts for dependencies.`,
		RunE:  runMaintainers,
	}

	maintainersCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	maintainersCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	maintainersCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	maintainersCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	maintainersCmd.Flags().Bool("single", false, "Only show dependencies with exactly one maintainer")
	maintainersCmd.Flags().Bool("all", false, "Include transitive dependencies from lockfiles")
	parent.AddCommand(maintainersCmd)
}

type MaintainersSummary struct {
	TotalDependencies   int `json:"total_dependencies"`
	QueriedDependencies int `json:"queried_dependencies"`
	WithMaintainers     int `json:"with_maintainers"`
	WithoutMaintainers  int `json:"without_maintainers"`
	SingleMaintainer    int `json:"single_maintainer"`
	LookupErrors        int `json:"lookup_errors"`
}

type MaintainerInfo struct {
	Login string `json:"login,omitempty"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	URL   string `json:"url,omitempty"`
	Role  string `json:"role,omitempty"`
}

type MaintainersEntry struct {
	Name             string           `json:"name"`
	Ecosystem        string           `json:"ecosystem"`
	Version          string           `json:"version,omitempty"`
	ManifestPath     string           `json:"manifest_path"`
	PURL             string           `json:"purl,omitempty"`
	MaintainerCount  int              `json:"maintainer_count"`
	SingleMaintainer bool             `json:"single_maintainer"`
	Maintainers      []MaintainerInfo `json:"maintainers"`
	Error            string           `json:"error,omitempty"`
}

type MaintainersResult struct {
	Summary      MaintainersSummary `json:"summary"`
	Dependencies []MaintainersEntry `json:"dependencies"`
}

type maintainerLookupResult struct {
	Maintainers []MaintainerInfo
	Error       string
}

func runMaintainers(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	singleOnly, _ := cmd.Flags().GetBool("single")
	includeTransitive, _ := cmd.Flags().GetBool("all")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	deps, db, err := repo.GetDependenciesWithDB(commit, branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, ecosystem)
	deps = selectMaintainerDependencies(deps, includeTransitive)
	if len(deps) == 0 {
		if format == formatJSON {
			return outputMaintainersJSON(cmd, emptyMaintainersResult())
		}
		if includeTransitive {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies found.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No direct dependencies found.")
		}
		return nil
	}

	purls := uniqueMaintainerPURLs(deps)
	ctx, cancel := context.WithTimeout(context.Background(), maintainerLookupTimeout)
	defer cancel()

	data := fetchMaintainerData(ctx, db, deps, purls)
	result := buildMaintainersResult(deps, data, singleOnly)
	if len(result.Dependencies) == 0 {
		if format == formatJSON {
			return outputMaintainersJSON(cmd, result)
		}
		if singleOnly {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No single-maintainer dependencies found.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No maintainer data found.")
		}
		return nil
	}

	switch format {
	case formatJSON:
		return outputMaintainersJSON(cmd, result)
	default:
		outputMaintainersText(cmd, result, singleOnly)
		return nil
	}
}

func selectMaintainerDependencies(deps []database.Dependency, includeTransitive bool) []database.Dependency {
	var selected []database.Dependency
	for _, dep := range deps {
		if includeTransitive {
			if dep.ManifestKind == "manifest" || isResolvedDependency(dep) {
				selected = append(selected, dep)
			}
			continue
		}
		if dep.ManifestKind == "manifest" {
			selected = append(selected, dep)
		}
	}
	return selected
}

func uniqueMaintainerPURLs(deps []database.Dependency) []string {
	seen := make(map[string]bool)
	var purls []string
	for _, dep := range deps {
		purlStr := maintainerPURLForDependency(dep)
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
	}
	sort.Strings(purls)
	return purls
}

func maintainerPURLForDependency(dep database.Dependency) string {
	if dep.PURL != "" {
		parsed, err := purl.Parse(dep.PURL)
		if err == nil {
			parsed.Version = ""
			return parsed.String()
		}
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, "")
}

func fetchMaintainerData(
	ctx context.Context,
	db *database.DB,
	deps []database.Dependency,
	purls []string,
) map[string]maintainerLookupResult {
	results := make(map[string]maintainerLookupResult, len(purls))
	if len(purls) == 0 {
		return results
	}

	for purlStr, result := range cachedMaintainerData(db, purls) {
		results[purlStr] = result
	}

	misses := make([]string, 0)
	for _, purlStr := range purls {
		if _, ok := results[purlStr]; !ok {
			misses = append(misses, purlStr)
		}
	}
	if len(misses) == 0 {
		return results
	}

	fetched := fetchMaintainerDataUncached(ctx, misses)
	for purlStr, result := range fetched {
		results[purlStr] = result
	}
	saveMaintainerData(db, deps, fetched)

	return results
}

func cachedMaintainerData(db *database.DB, purls []string) map[string]maintainerLookupResult {
	results := make(map[string]maintainerLookupResult, len(purls))
	if db == nil {
		return results
	}

	cached, err := db.GetCachedMaintainers(purls, enrichmentCacheTTL)
	if err != nil {
		return results
	}
	for purlStr, cachedMaintainers := range cached {
		var maintainers []MaintainerInfo
		if err := json.Unmarshal([]byte(cachedMaintainers.Data), &maintainers); err != nil {
			continue
		}
		results[purlStr] = maintainerLookupResult{Maintainers: maintainers}
	}
	return results
}

func fetchMaintainerDataUncached(ctx context.Context, purls []string) map[string]maintainerLookupResult {
	results := make(map[string]maintainerLookupResult, len(purls))
	if len(purls) == 0 {
		return results
	}

	client, err := newEnrichmentClient()
	if err != nil {
		for _, purlStr := range purls {
			results[purlStr] = maintainerLookupResult{Error: fmt.Sprintf("creating enrichment client: %v", err)}
		}
		return results
	}

	packages, err := client.BulkLookup(ctx, purls)
	if err != nil {
		wrapped := wrapEcosystemsError(err).Error()
		for _, purlStr := range purls {
			results[purlStr] = maintainerLookupResult{Error: wrapped}
		}
		return results
	}

	for _, purlStr := range purls {
		pkg := packages[purlStr]
		if pkg == nil {
			results[purlStr] = maintainerLookupResult{}
			continue
		}
		results[purlStr] = maintainerLookupResult{
			Maintainers: maintainerInfosFromEnrichment(pkg.Maintainers),
		}
	}
	return results
}

func saveMaintainerData(db *database.DB, deps []database.Dependency, lookup map[string]maintainerLookupResult) {
	if db == nil || len(lookup) == 0 {
		return
	}

	packages := maintainerPackageData(deps)
	toSave := make([]database.PackageMaintainersData, 0, len(lookup))
	for purlStr, result := range lookup {
		if result.Error != "" {
			continue
		}
		pkg, ok := packages[purlStr]
		if !ok {
			continue
		}
		raw, err := json.Marshal(result.Maintainers)
		if err != nil {
			continue
		}
		pkg.Maintainers = string(raw)
		toSave = append(toSave, pkg)
	}

	_ = db.SavePackageMaintainersBatch(toSave)
}

func maintainerPackageData(deps []database.Dependency) map[string]database.PackageMaintainersData {
	packages := make(map[string]database.PackageMaintainersData)
	for _, dep := range deps {
		purlStr := maintainerPURLForDependency(dep)
		if purlStr == "" {
			continue
		}
		if _, ok := packages[purlStr]; ok {
			continue
		}
		packages[purlStr] = database.PackageMaintainersData{
			PURL:      purlStr,
			Ecosystem: dep.Ecosystem,
			Name:      dep.Name,
		}
	}
	return packages
}

func buildMaintainersResult(
	deps []database.Dependency,
	lookup map[string]maintainerLookupResult,
	singleOnly bool,
) *MaintainersResult {
	result := emptyMaintainersResult()
	result.Summary.TotalDependencies = len(deps)

	for _, dep := range deps {
		purlStr := maintainerPURLForDependency(dep)
		if purlStr == "" {
			continue
		}

		data, ok := lookup[purlStr]
		if !ok {
			data.Error = "maintainer lookup was not run"
		}

		entry := MaintainersEntry{
			Name:         dep.Name,
			Ecosystem:    dep.Ecosystem,
			Version:      dep.Requirement,
			ManifestPath: dep.ManifestPath,
			PURL:         purlStr,
			Error:        data.Error,
		}
		entry.Maintainers = normalizeMaintainers(data.Maintainers)
		entry.MaintainerCount = len(entry.Maintainers)
		entry.SingleMaintainer = entry.MaintainerCount == 1

		result.Summary.QueriedDependencies++
		switch {
		case entry.Error != "":
			result.Summary.LookupErrors++
		case entry.MaintainerCount == 0:
			result.Summary.WithoutMaintainers++
		default:
			result.Summary.WithMaintainers++
			if entry.SingleMaintainer {
				result.Summary.SingleMaintainer++
			}
		}

		if singleOnly && !entry.SingleMaintainer {
			continue
		}
		result.Dependencies = append(result.Dependencies, entry)
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].MaintainerCount != result.Dependencies[j].MaintainerCount {
			return result.Dependencies[i].MaintainerCount < result.Dependencies[j].MaintainerCount
		}
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		return result.Dependencies[i].Ecosystem < result.Dependencies[j].Ecosystem
	})

	return result
}

func emptyMaintainersResult() *MaintainersResult {
	return &MaintainersResult{
		Dependencies: []MaintainersEntry{},
	}
}

func maintainerInfosFromEnrichment(maintainers []enrichment.Maintainer) []MaintainerInfo {
	infos := make([]MaintainerInfo, 0, len(maintainers))
	for _, maintainer := range maintainers {
		infos = append(infos, MaintainerInfo{
			Login: maintainer.Login,
			Name:  maintainer.Name,
			Email: maintainer.Email,
			URL:   maintainer.URL,
			Role:  maintainer.Role,
		})
	}
	return infos
}

func normalizeMaintainers(maintainers []MaintainerInfo) []MaintainerInfo {
	seen := make(map[string]bool)
	infos := make([]MaintainerInfo, 0, len(maintainers))
	for _, maintainer := range maintainers {
		info := MaintainerInfo{
			Login: maintainer.Login,
			Name:  maintainer.Name,
			Email: maintainer.Email,
			URL:   maintainer.URL,
			Role:  maintainer.Role,
		}
		key := maintainerDisplay(info)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return maintainerDisplay(infos[i]) < maintainerDisplay(infos[j])
	})
	return infos
}

func maintainerDisplay(maintainer MaintainerInfo) string {
	parts := []string{
		maintainer.Login,
		maintainer.Name,
		maintainer.Email,
		maintainer.URL,
	}
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			return part
		}
	}
	return ""
}

func outputMaintainersJSON(cmd *cobra.Command, result *MaintainersResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputMaintainersText(cmd *cobra.Command, result *MaintainersResult, singleOnly bool) {
	if singleOnly {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d single-maintainer dependencies:\n\n", len(result.Dependencies))
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found maintainer data for %d dependencies:\n\n", len(result.Dependencies))
	}

	maxNameLen := 0
	for _, dep := range result.Dependencies {
		if len(dep.Name) > maxNameLen {
			maxNameLen = len(dep.Name)
		}
	}

	for _, dep := range result.Dependencies {
		maintainers := formatMaintainerNames(dep.Maintainers)
		if dep.Error != "" {
			maintainers = "lookup error: " + dep.Error
		} else if maintainers == "" {
			maintainers = "none reported"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %2d  %s  %s\n",
			maxNameLen,
			dep.Name,
			dep.MaintainerCount,
			maintainers,
			Dim("("+dep.ManifestPath+")"))
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Checked: %d, with maintainers: %d, without maintainers: %d, single maintainer: %d, lookup errors: %d\n",
		result.Summary.QueriedDependencies,
		result.Summary.WithMaintainers,
		result.Summary.WithoutMaintainers,
		result.Summary.SingleMaintainer,
		result.Summary.LookupErrors)
}

func formatMaintainerNames(maintainers []MaintainerInfo) string {
	names := make([]string, 0, len(maintainers))
	for _, maintainer := range maintainers {
		name := maintainerDisplay(maintainer)
		if maintainer.Role != "" && name != "" {
			name += " (" + maintainer.Role + ")"
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}
