package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/spf13/cobra"
)

func addFundingCmd(parent *cobra.Command) {
	fundingCmd := &cobra.Command{
		Use:   "funding",
		Short: "Show dependency funding information",
		Long:  `Check package metadata for funding links and show dependencies that have or need funding information.`,
		RunE:  runFunding,
	}

	fundingCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	fundingCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	fundingCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	fundingCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	fundingCmd.Flags().Bool("missing", false, "Show dependencies without funding links")
	parent.AddCommand(fundingCmd)
}

type FundingSummary struct {
	TotalDependencies     int `json:"total_dependencies"`
	CheckedDependencies   int `json:"checked_dependencies"`
	WithFunding           int `json:"with_funding"`
	WithoutFunding        int `json:"without_funding"`
	UnresolvedPackageData int `json:"unresolved_package_data"`
}

type FundingEntry struct {
	Name         string   `json:"name"`
	Ecosystem    string   `json:"ecosystem"`
	Version      string   `json:"version,omitempty"`
	FundingLinks []string `json:"funding_links,omitempty"`
	ManifestPath string   `json:"manifest_path"`
	PURL         string   `json:"purl,omitempty"`
}

type FundingResult struct {
	Summary      FundingSummary `json:"summary"`
	Dependencies []FundingEntry `json:"dependencies"`
}

type fundingPackageData struct {
	FundingLinks []string
}

func runFunding(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	showMissing, _ := cmd.Flags().GetBool("missing")

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
			return outputFundingJSON(cmd, emptyFundingResult())
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found.")
		return nil
	}

	packageData, err := fetchFundingPackageData(db, resolved)
	if err != nil {
		return fmt.Errorf("looking up funding data: %w", err)
	}

	result := buildFundingResult(resolved, packageData, showMissing)
	if len(result.Dependencies) == 0 {
		if format == formatJSON {
			return outputFundingJSON(cmd, result)
		}
		outputFundingEmpty(cmd, result, showMissing)
		return nil
	}

	switch format {
	case formatJSON:
		return outputFundingJSON(cmd, result)
	default:
		outputFundingText(cmd, result, showMissing)
		return nil
	}
}

func fetchFundingPackageData(db *database.DB, deps []database.Dependency) (map[string]*fundingPackageData, error) {
	purls := make([]string, 0, len(deps))
	seen := make(map[string]bool)
	purlToDep := make(map[string]database.Dependency)
	for _, dep := range deps {
		purlStr := fundingPURLForDependency(dep)
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
		purlToDep[purlStr] = dep
	}
	if len(purls) == 0 {
		return map[string]*fundingPackageData{}, nil
	}

	result := make(map[string]*fundingPackageData, len(purls))
	var uncached []string
	if db != nil {
		cached, err := db.GetCachedPackageFunding(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, err
		}
		for purlStr, data := range cached {
			result[purlStr] = &fundingPackageData{FundingLinks: data.FundingLinks}
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

	packages, err := fetchFundingMetadata(uncached)
	if err != nil {
		return nil, err
	}

	fetchedFunding := make(map[string]*fundingPackageData, len(packages))
	for purlStr, pkg := range packages {
		if pkg == nil {
			continue
		}
		data := &fundingPackageData{FundingLinks: uniqueStrings(pkg.FundingLinks)}
		result[purlStr] = data
		fetchedFunding[purlStr] = data
	}

	saveFundingPackageData(db, purlToDep, fetchedFunding)

	return result, nil
}

func fetchFundingMetadata(purls []string) (map[string]*enrichment.PackageInfo, error) {
	client, err := newEnrichmentClient()
	if err != nil {
		return nil, err
	}

	const fundingLookupTimeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), fundingLookupTimeout)
	defer cancel()

	packages, err := client.BulkLookup(ctx, purls)
	if err != nil {
		return nil, wrapEcosystemsError(err)
	}
	return packages, nil
}

func saveFundingPackageData(
	db *database.DB,
	purlToDep map[string]database.Dependency,
	fundingData map[string]*fundingPackageData,
) {
	if db == nil {
		return
	}

	var fundingToSave []database.PackageFundingData
	for purlStr, data := range fundingData {
		dep := purlToDep[purlStr]
		if data == nil {
			continue
		}
		fundingToSave = append(fundingToSave, database.PackageFundingData{
			PURL:         purlStr,
			Ecosystem:    dep.Ecosystem,
			Name:         dep.Name,
			FundingLinks: data.FundingLinks,
		})
	}

	_ = db.SavePackageFundingBatch(fundingToSave)
}

func fundingPURLForDependency(dep database.Dependency) string {
	if dep.PURL != "" {
		parsed, err := purl.Parse(dep.PURL)
		if err == nil {
			parsed.Version = ""
			return parsed.String()
		}
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, "")
}

func buildFundingResult(
	deps []database.Dependency,
	packageData map[string]*fundingPackageData,
	showMissing bool,
) *FundingResult {
	result := emptyFundingResult()
	result.Summary.TotalDependencies = len(deps)

	seen := make(map[string]bool)
	for _, dep := range deps {
		purlStr := fundingPURLForDependency(dep)
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

		result.Summary.CheckedDependencies++
		links := uniqueStrings(pkg.FundingLinks)
		if len(links) > 0 {
			result.Summary.WithFunding++
		} else {
			result.Summary.WithoutFunding++
		}

		if (showMissing && len(links) == 0) || (!showMissing && len(links) > 0) {
			result.Dependencies = append(result.Dependencies, FundingEntry{
				Name:         dep.Name,
				Ecosystem:    dep.Ecosystem,
				Version:      dep.Requirement,
				FundingLinks: links,
				ManifestPath: dep.ManifestPath,
				PURL:         purlStr,
			})
		}
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		if result.Dependencies[i].ManifestPath != result.Dependencies[j].ManifestPath {
			return result.Dependencies[i].ManifestPath < result.Dependencies[j].ManifestPath
		}
		return result.Dependencies[i].Version < result.Dependencies[j].Version
	})

	return result
}

func emptyFundingResult() *FundingResult {
	return &FundingResult{
		Dependencies: []FundingEntry{},
	}
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}

func outputFundingJSON(cmd *cobra.Command, result *FundingResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputFundingEmpty(cmd *cobra.Command, result *FundingResult, showMissing bool) {
	if result.Summary.CheckedDependencies == 0 && result.Summary.UnresolvedPackageData > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"No package metadata resolved for %d dependencies; funding status could not be determined.\n",
			result.Summary.UnresolvedPackageData)
		return
	}

	if showMissing {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All checked dependencies have funding links.")
	} else {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No funding links found.")
	}
	if result.Summary.UnresolvedPackageData > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Funding status could not be determined for %d dependencies.\n",
			result.Summary.UnresolvedPackageData)
	}
}

func outputFundingText(cmd *cobra.Command, result *FundingResult, showMissing bool) {
	if showMissing {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d dependencies without funding links:\n\n", len(result.Dependencies))
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d dependencies with funding links:\n\n", len(result.Dependencies))
	}

	maxNameLen := 0
	for _, dep := range result.Dependencies {
		if len(dep.Name) > maxNameLen {
			maxNameLen = len(dep.Name)
		}
	}

	for _, dep := range result.Dependencies {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %s  %s\n",
			maxNameLen,
			dep.Name,
			dep.Version,
			Dim("("+dep.ManifestPath+")"))
		for _, link := range dep.FundingLinks {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", link)
		}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Checked: %d, with funding: %d, without funding: %d, unresolved: %d\n",
		result.Summary.CheckedDependencies,
		result.Summary.WithFunding,
		result.Summary.WithoutFunding,
		result.Summary.UnresolvedPackageData)
}
