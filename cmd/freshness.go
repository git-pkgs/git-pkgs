package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vers"
	"github.com/spf13/cobra"
)

const defaultFreshnessLimit = 10

func addFreshnessCmd(parent *cobra.Command) {
	freshnessCmd := &cobra.Command{
		Use:   "freshness",
		Short: "Show release freshness metrics",
		Long: `Compare installed dependency versions with the latest published versions.
Reports how many days dependencies lag behind latest releases and lists the
packages with the largest release-date lag.`,
		RunE: runFreshness,
	}

	freshnessCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	freshnessCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	freshnessCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	freshnessCmd.Flags().IntP("limit", "n", defaultFreshnessLimit, "Number of lagging dependencies to show")
	freshnessCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(freshnessCmd)
}

type FreshnessSummary struct {
	TotalDependencies          int `json:"total_dependencies"`
	MeasuredDependencies       int `json:"measured_dependencies"`
	LaggingDependencies        int `json:"lagging_dependencies"`
	AverageDaysBehindLatest    int `json:"average_days_behind_latest"`
	MaximumDaysBehindLatest    int `json:"maximum_days_behind_latest"`
	UnmeasuredDependencies     int `json:"unmeasured_dependencies"`
	UniquePackagesWithMetadata int `json:"unique_packages_with_metadata"`
}

type FreshnessEntry struct {
	Name               string `json:"name"`
	Ecosystem          string `json:"ecosystem"`
	CurrentVersion     string `json:"current_version"`
	LatestVersion      string `json:"latest_version"`
	DaysBehindLatest   int    `json:"days_behind_latest"`
	CurrentPublishedAt string `json:"current_published_at"`
	LatestPublishedAt  string `json:"latest_published_at"`
	ManifestPath       string `json:"manifest_path"`
	PURL               string `json:"purl,omitempty"`
}

type FreshnessResult struct {
	Summary      FreshnessSummary `json:"summary"`
	Dependencies []FreshnessEntry `json:"dependencies"`
}

type freshnessVersion struct {
	Number      string
	PublishedAt time.Time
}

func runFreshness(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	limit, _ := cmd.Flags().GetInt("limit")
	format, _ := cmd.Flags().GetString("format")

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

	var resolved []database.Dependency
	for _, d := range deps {
		if isResolvedDependency(d) {
			resolved = append(resolved, d)
		}
	}

	if len(resolved) == 0 {
		if format == formatJSON {
			return outputFreshnessJSON(cmd, emptyFreshnessResult())
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found.")
		return nil
	}

	result, err := computeFreshness(db, resolved)
	if err != nil {
		return err
	}

	if limit >= 0 && len(result.Dependencies) > limit {
		result.Dependencies = result.Dependencies[:limit]
	}

	if format == formatJSON {
		return outputFreshnessJSON(cmd, result)
	}
	outputFreshnessText(cmd, result)
	return nil
}

func computeFreshness(db *database.DB, deps []database.Dependency) (*FreshnessResult, error) {
	result := emptyFreshnessResult()
	result.Summary.TotalDependencies = len(deps)

	purlVersions, err := loadFreshnessVersions(db, deps)
	if err != nil {
		return nil, err
	}
	result.Summary.UniquePackagesWithMetadata = len(purlVersions)

	for _, dep := range deps {
		purlStr := purl.MakePURLString(dep.Ecosystem, dep.Name, "")
		if purlStr == "" {
			result.Summary.UnmeasuredDependencies++
			continue
		}

		versions := purlVersions[purlStr]
		entry, ok := freshnessEntryForDependency(dep, purlStr, versions)
		if !ok {
			result.Summary.UnmeasuredDependencies++
			continue
		}

		result.Summary.MeasuredDependencies++
		result.Summary.AverageDaysBehindLatest += entry.DaysBehindLatest
		if entry.DaysBehindLatest > result.Summary.MaximumDaysBehindLatest {
			result.Summary.MaximumDaysBehindLatest = entry.DaysBehindLatest
		}
		if entry.DaysBehindLatest > 0 {
			result.Summary.LaggingDependencies++
			result.Dependencies = append(result.Dependencies, entry)
		}
	}

	if result.Summary.MeasuredDependencies > 0 {
		result.Summary.AverageDaysBehindLatest /= result.Summary.MeasuredDependencies
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].DaysBehindLatest != result.Dependencies[j].DaysBehindLatest {
			return result.Dependencies[i].DaysBehindLatest > result.Dependencies[j].DaysBehindLatest
		}
		return result.Dependencies[i].Name < result.Dependencies[j].Name
	})

	return result, nil
}

func loadFreshnessVersions(db *database.DB, deps []database.Dependency) (map[string][]freshnessVersion, error) {
	purls := make([]string, 0, len(deps))
	seen := make(map[string]bool)
	for _, dep := range deps {
		purlStr := purl.MakePURLString(dep.Ecosystem, dep.Name, "")
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
	}

	result := make(map[string][]freshnessVersion, len(purls))
	var missing []string
	for _, purlStr := range purls {
		versions, err := cachedFreshnessVersions(db, purlStr)
		if err != nil {
			return nil, err
		}
		if len(versions) == 0 {
			missing = append(missing, purlStr)
			continue
		}
		result[purlStr] = versions
	}

	if len(missing) == 0 {
		return result, nil
	}

	client, err := NewEnrichmentClient(enrichment.WithUserAgent(userAgent))
	if err != nil {
		return nil, err
	}

	const freshnessLookupTimeout = 60 * time.Second
	var fetchErrors []error
	for _, purlStr := range missing {
		ctx, cancel := context.WithTimeout(context.Background(), freshnessLookupTimeout)
		versions, err := fetchFreshnessVersions(ctx, client, purlStr)
		cancel()
		if err != nil {
			fetchErrors = append(fetchErrors, fmt.Errorf("%s: %w", purlStr, err))
			continue
		}
		if len(versions) == 0 {
			continue
		}
		result[purlStr] = versions
		if db != nil {
			_ = db.SaveVersions(cachedVersionsFromFreshness(purlStr, versions))
		}
	}
	if len(fetchErrors) == len(missing) {
		return nil, fmt.Errorf("fetching freshness metadata failed for all %d uncached packages: %w",
			len(missing), errors.Join(fetchErrors...))
	}

	return result, nil
}

func emptyFreshnessResult() *FreshnessResult {
	return &FreshnessResult{
		Dependencies: []FreshnessEntry{},
	}
}

func cachedFreshnessVersions(db *database.DB, purlStr string) ([]freshnessVersion, error) {
	if db == nil {
		return nil, nil
	}

	cached, err := db.GetCachedVersions(purlStr, enrichmentCacheTTL)
	if err != nil {
		return nil, err
	}

	versions := make([]freshnessVersion, 0, len(cached))
	for _, v := range cached {
		if v.PublishedAt.IsZero() {
			continue
		}
		number := versionFromPURL(v.PURL)
		if number == "" {
			continue
		}
		versions = append(versions, freshnessVersion{
			Number:      number,
			PublishedAt: v.PublishedAt,
		})
	}
	return versions, nil
}

func fetchFreshnessVersions(ctx context.Context, client enrichment.Client, purlStr string) ([]freshnessVersion, error) {
	apiVersions, err := client.GetVersions(ctx, purlStr)
	if err != nil {
		return nil, err
	}

	versions := make([]freshnessVersion, 0, len(apiVersions))
	for _, v := range apiVersions {
		if v.Number == "" || v.PublishedAt.IsZero() {
			continue
		}
		versions = append(versions, freshnessVersion{
			Number:      v.Number,
			PublishedAt: v.PublishedAt,
		})
	}
	return versions, nil
}

func cachedVersionsFromFreshness(packagePURL string, versions []freshnessVersion) []database.CachedVersion {
	cached := make([]database.CachedVersion, 0, len(versions))
	for _, v := range versions {
		cached = append(cached, database.CachedVersion{
			PURL:        packagePURL + "@" + v.Number,
			PackagePURL: packagePURL,
			PublishedAt: v.PublishedAt,
		})
	}
	return cached
}

func freshnessEntryForDependency(dep database.Dependency, purlStr string, versions []freshnessVersion) (FreshnessEntry, bool) {
	current, latest, ok := currentAndLatestVersions(dep.Requirement, versions)
	if !ok {
		return FreshnessEntry{}, false
	}

	daysBehind := int(latest.PublishedAt.Sub(current.PublishedAt).Hours() / 24)
	if daysBehind < 0 {
		daysBehind = 0
	}

	return FreshnessEntry{
		Name:               dep.Name,
		Ecosystem:          dep.Ecosystem,
		CurrentVersion:     current.Number,
		LatestVersion:      latest.Number,
		DaysBehindLatest:   daysBehind,
		CurrentPublishedAt: current.PublishedAt.Format(time.RFC3339),
		LatestPublishedAt:  latest.PublishedAt.Format(time.RFC3339),
		ManifestPath:       dep.ManifestPath,
		PURL:               purlStr,
	}, true
}

func currentAndLatestVersions(currentVersion string, versions []freshnessVersion) (freshnessVersion, freshnessVersion, bool) {
	var current freshnessVersion
	var latest freshnessVersion
	for _, v := range versions {
		if v.Number == currentVersion {
			current = v
		}
		if latest.Number == "" || isVersionNewer(v, latest) {
			latest = v
		}
	}
	if current.Number == "" || latest.Number == "" {
		return freshnessVersion{}, freshnessVersion{}, false
	}
	return current, latest, true
}

func isVersionNewer(candidate, current freshnessVersion) bool {
	if cmp := vers.Compare(candidate.Number, current.Number); cmp != 0 {
		return cmp > 0
	}
	return candidate.PublishedAt.After(current.PublishedAt)
}

func versionFromPURL(purlStr string) string {
	parsed, err := purl.Parse(purlStr)
	if err != nil {
		return ""
	}
	return parsed.Version
}

func outputFreshnessJSON(cmd *cobra.Command, result *FreshnessResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputFreshnessText(cmd *cobra.Command, result *FreshnessResult) {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Freshness Summary")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "=================")
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Measured dependencies: %d/%d\n",
		result.Summary.MeasuredDependencies, result.Summary.TotalDependencies)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Lagging dependencies: %d\n", result.Summary.LaggingDependencies)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Average days behind latest: %d\n", result.Summary.AverageDaysBehindLatest)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Maximum days behind latest: %d\n", result.Summary.MaximumDaysBehindLatest)
	if result.Summary.UnmeasuredDependencies > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unmeasured dependencies: %d\n", result.Summary.UnmeasuredDependencies)
	}

	if len(result.Dependencies) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nAll measured dependencies are fresh.")
		return
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nMost Lagging Dependencies")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "-------------------------")
	maxNameLen := 0
	for _, e := range result.Dependencies {
		if len(e.Name) > maxNameLen {
			maxNameLen = len(e.Name)
		}
	}
	for _, e := range result.Dependencies {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %s -> %s  (%d days)  %s\n",
			maxNameLen,
			e.Name,
			e.CurrentVersion,
			e.LatestVersion,
			e.DaysBehindLatest,
			e.ManifestPath)
	}
}
