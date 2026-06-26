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

func addHealthCmd(parent *cobra.Command) {
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Show dependency maintenance health scores",
		Long:  `Score dependency maintenance health using cached package metadata from ecosyste.ms.`,
		RunE:  runHealth,
	}

	healthCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	healthCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	healthCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	healthCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	healthCmd.Flags().Bool("all", false, "Include transitive dependencies from lockfiles")
	healthCmd.Flags().Int("threshold", 100, "Only show dependencies with health scores at or below this threshold; at-risk count uses the same threshold")
	parent.AddCommand(healthCmd)
}

type HealthSummary struct {
	TotalDependencies     int `json:"total_dependencies"`
	CheckedDependencies   int `json:"checked_dependencies"`
	AtRiskDependencies    int `json:"at_risk_dependencies"`
	UnresolvedPackageData int `json:"unresolved_package_data"`
	AverageScore          int `json:"average_score"`
	DisplayedDependencies int `json:"displayed_dependencies"`
	HealthScoreThreshold  int `json:"health_score_threshold"`
}

type HealthEntry struct {
	Name                   string   `json:"name"`
	Ecosystem              string   `json:"ecosystem"`
	Version                string   `json:"version,omitempty"`
	Score                  int      `json:"score"`
	Risk                   string   `json:"risk"`
	MaintainerCount        int      `json:"maintainer_count"`
	Downloads              int      `json:"downloads"`
	DownloadsPeriod        string   `json:"downloads_period,omitempty"`
	DependentPackagesCount int      `json:"dependent_packages_count"`
	DependentReposCount    int      `json:"dependent_repos_count"`
	Signals                []string `json:"signals"`
	ManifestPath           string   `json:"manifest_path"`
	PURL                   string   `json:"purl,omitempty"`
}

type HealthResult struct {
	Summary      HealthSummary `json:"summary"`
	Dependencies []HealthEntry `json:"dependencies"`
}

type healthPackageData struct {
	MaintainerCount        int
	Maintainers            []MaintainerInfo
	Downloads              int
	DownloadsPeriod        string
	DependentPackagesCount int
	DependentReposCount    int
}

func runHealth(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	includeAll, _ := cmd.Flags().GetBool("all")
	threshold, _ := cmd.Flags().GetInt("threshold")

	if threshold < 0 || threshold > 100 {
		return fmt.Errorf("--threshold must be between 0 and 100")
	}

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

	deps = selectHealthDependencies(filterByEcosystem(deps, ecosystem), includeAll)
	if len(deps) == 0 {
		result := emptyHealthResult(threshold)
		if format == formatJSON {
			return outputHealthJSON(cmd, result)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies found.")
		return nil
	}

	packageData, err := fetchHealthPackageData(db, deps)
	if err != nil {
		return fmt.Errorf("looking up package health data: %w", err)
	}

	result := buildHealthResult(deps, packageData, threshold)
	switch format {
	case formatJSON:
		return outputHealthJSON(cmd, result)
	default:
		outputHealthText(cmd, result)
		return nil
	}
}

func selectHealthDependencies(deps []database.Dependency, includeAll bool) []database.Dependency {
	selected := make([]database.Dependency, 0, len(deps))
	for _, dep := range deps {
		if dep.ManifestKind == "manifest" {
			selected = append(selected, dep)
			continue
		}
		if includeAll && isResolvedDependency(dep) {
			selected = append(selected, dep)
		}
	}
	return selected
}

func fetchHealthPackageData(db *database.DB, deps []database.Dependency) (map[string]*healthPackageData, error) {
	purls := make([]string, 0, len(deps))
	seen := make(map[string]bool)
	purlToDep := make(map[string]database.Dependency)
	for _, dep := range deps {
		purlStr := healthPURLForDependency(dep)
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
		purlToDep[purlStr] = dep
	}
	if len(purls) == 0 {
		return map[string]*healthPackageData{}, nil
	}

	result := make(map[string]*healthPackageData, len(purls))
	var uncached []string
	if db != nil {
		cached, err := db.GetCachedPackageHealth(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, err
		}
		for purlStr, data := range cached {
			result[purlStr] = healthDataFromCached(data)
		}
		for _, purlStr := range purls {
			if _, ok := cached[purlStr]; !ok {
				uncached = append(uncached, purlStr)
			}
		}
	} else {
		uncached = purls
	}

	if len(uncached) == 0 {
		return result, nil
	}

	packages, err := fetchHealthMetadata(uncached)
	if err != nil {
		return nil, err
	}

	fetched := make(map[string]*healthPackageData, len(packages))
	for purlStr, pkg := range packages {
		if pkg == nil {
			continue
		}
		data := healthDataFromPackage(pkg)
		result[purlStr] = data
		fetched[purlStr] = data
	}

	saveHealthPackageData(db, purlToDep, fetched)

	return result, nil
}

func fetchHealthMetadata(purls []string) (map[string]*enrichment.PackageInfo, error) {
	client, err := newEnrichmentClient()
	if err != nil {
		return nil, err
	}

	const healthLookupTimeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), healthLookupTimeout)
	defer cancel()

	packages, err := client.BulkLookup(ctx, purls)
	if err != nil {
		return nil, wrapEcosystemsError(err)
	}
	return packages, nil
}

func saveHealthPackageData(
	db *database.DB,
	purlToDep map[string]database.Dependency,
	healthData map[string]*healthPackageData,
) {
	if db == nil {
		return
	}

	var toSave []database.PackageHealthData
	var maintainersToSave []database.PackageMaintainersData
	for purlStr, data := range healthData {
		dep := purlToDep[purlStr]
		if data == nil {
			continue
		}
		toSave = append(toSave, database.PackageHealthData{
			PURL:                   purlStr,
			Ecosystem:              dep.Ecosystem,
			Name:                   dep.Name,
			Downloads:              data.Downloads,
			DownloadsPeriod:        data.DownloadsPeriod,
			DependentPackagesCount: data.DependentPackagesCount,
			DependentReposCount:    data.DependentReposCount,
		})

		maintainers := data.Maintainers
		if maintainers == nil {
			maintainers = []MaintainerInfo{}
		}
		rawMaintainers, err := json.Marshal(maintainers)
		if err != nil {
			continue
		}
		maintainersToSave = append(maintainersToSave, database.PackageMaintainersData{
			PURL:        purlStr,
			Ecosystem:   dep.Ecosystem,
			Name:        dep.Name,
			Maintainers: string(rawMaintainers),
		})
	}

	_ = db.SavePackageHealthBatch(toSave)
	_ = db.SavePackageMaintainersBatch(maintainersToSave)
}

func healthDataFromCached(data *database.CachedPackageHealth) *healthPackageData {
	if data == nil {
		return nil
	}
	return &healthPackageData{
		MaintainerCount:        data.MaintainerCount,
		Downloads:              data.Downloads,
		DownloadsPeriod:        data.DownloadsPeriod,
		DependentPackagesCount: data.DependentPackagesCount,
		DependentReposCount:    data.DependentReposCount,
	}
}

func healthDataFromPackage(pkg *enrichment.PackageInfo) *healthPackageData {
	if pkg == nil {
		return nil
	}
	return &healthPackageData{
		MaintainerCount:        len(pkg.Maintainers),
		Maintainers:            maintainerInfosFromEnrichment(pkg.Maintainers),
		Downloads:              pkg.Downloads,
		DownloadsPeriod:        pkg.DownloadsPeriod,
		DependentPackagesCount: pkg.DependentPackagesCount,
		DependentReposCount:    pkg.DependentReposCount,
	}
}

func healthPURLForDependency(dep database.Dependency) string {
	if dep.PURL != "" {
		parsed, err := purl.Parse(dep.PURL)
		if err == nil {
			parsed.Version = ""
			return parsed.String()
		}
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, "")
}

func buildHealthResult(
	deps []database.Dependency,
	packageData map[string]*healthPackageData,
	threshold int,
) *HealthResult {
	result := emptyHealthResult(threshold)
	result.Summary.TotalDependencies = len(deps)

	seen := make(map[string]bool)
	scoreTotal := 0
	for _, dep := range deps {
		purlStr := healthPURLForDependency(dep)
		if purlStr == "" {
			result.Summary.UnresolvedPackageData++
			continue
		}

		key := purlStr + "\x00" + dep.ManifestPath + "\x00" + dep.Requirement
		if seen[key] {
			continue
		}
		seen[key] = true

		pkg := packageData[purlStr]
		if pkg == nil {
			result.Summary.UnresolvedPackageData++
			continue
		}

		score, risk, signals := maintenanceHealthScore(pkg)
		result.Summary.CheckedDependencies++
		scoreTotal += score
		if score <= threshold {
			result.Summary.AtRiskDependencies++
		}
		if score > threshold {
			continue
		}

		result.Dependencies = append(result.Dependencies, HealthEntry{
			Name:                   dep.Name,
			Ecosystem:              dep.Ecosystem,
			Version:                dep.Requirement,
			Score:                  score,
			Risk:                   risk,
			MaintainerCount:        pkg.MaintainerCount,
			Downloads:              pkg.Downloads,
			DownloadsPeriod:        pkg.DownloadsPeriod,
			DependentPackagesCount: pkg.DependentPackagesCount,
			DependentReposCount:    pkg.DependentReposCount,
			Signals:                signals,
			ManifestPath:           dep.ManifestPath,
			PURL:                   purlStr,
		})
	}

	if result.Summary.CheckedDependencies > 0 {
		result.Summary.AverageScore = scoreTotal / result.Summary.CheckedDependencies
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].Score != result.Dependencies[j].Score {
			return result.Dependencies[i].Score < result.Dependencies[j].Score
		}
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		return result.Dependencies[i].ManifestPath < result.Dependencies[j].ManifestPath
	})
	result.Summary.DisplayedDependencies = len(result.Dependencies)

	return result
}

func maintenanceHealthScore(data *healthPackageData) (int, string, []string) {
	score := 100
	var signals []string

	switch data.MaintainerCount {
	case 0:
		score -= 30
		signals = append(signals, "no maintainer data")
	case 1:
		score -= 25
		signals = append(signals, "single maintainer")
	case 2:
		score -= 10
		signals = append(signals, "small maintainer team")
	}

	if data.DependentReposCount == 0 && data.DependentPackagesCount == 0 {
		score -= 10
		signals = append(signals, "no dependent usage data")
	} else if data.DependentReposCount < 10 && data.DependentPackagesCount < 10 {
		score -= 5
		signals = append(signals, "limited dependent usage")
	}

	if data.Downloads == 0 {
		score -= 5
		signals = append(signals, "no download data")
	}

	if score < 0 {
		score = 0
	}

	return score, healthRisk(score), signals
}

func healthRisk(score int) string {
	switch {
	case score < 50:
		return "high"
	case score < 75:
		return "medium"
	default:
		return "low"
	}
}

func emptyHealthResult(threshold int) *HealthResult {
	return &HealthResult{
		Summary: HealthSummary{
			HealthScoreThreshold: threshold,
		},
		Dependencies: []HealthEntry{},
	}
}

func outputHealthJSON(cmd *cobra.Command, result *HealthResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputHealthText(cmd *cobra.Command, result *HealthResult) {
	if result.Summary.CheckedDependencies == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No package health metadata resolved.")
		if result.Summary.UnresolvedPackageData > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unresolved dependencies: %d\n", result.Summary.UnresolvedPackageData)
		}
		return
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Maintenance Health Summary")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "==========================")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Checked dependencies: %d/%d\n",
		result.Summary.CheckedDependencies, result.Summary.TotalDependencies)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Average score: %d\n", result.Summary.AverageScore)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "At-risk dependencies: %d\n", result.Summary.AtRiskDependencies)
	if result.Summary.UnresolvedPackageData > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unresolved dependencies: %d\n", result.Summary.UnresolvedPackageData)
	}

	if len(result.Dependencies) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nNo dependencies at or below health threshold %d.\n",
			result.Summary.HealthScoreThreshold)
		return
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nDependencies at or below health threshold %d:\n\n",
		result.Summary.HealthScoreThreshold)
	for _, entry := range result.Dependencies {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s): score %d [%s]\n",
			entry.Name, entry.Ecosystem, entry.Score, entry.Risk)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  maintainers: %d, downloads: %d",
			entry.MaintainerCount, entry.Downloads)
		if entry.DownloadsPeriod != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), " (%s)", entry.DownloadsPeriod)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), ", dependent repos: %d, dependent packages: %d\n",
			entry.DependentReposCount, entry.DependentPackagesCount)
		if len(entry.Signals) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  signals: %s\n", strings.Join(entry.Signals, ", "))
		}
	}
}
