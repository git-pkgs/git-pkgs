package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/spf13/cobra"
)

func addDeprecatedCmd(parent *cobra.Command) {
	deprecatedCmd := &cobra.Command{
		Use:     "deprecated",
		Aliases: []string{"deprecations"},
		Short:   "Find deprecated dependency versions",
		Long:    `Check installed dependency versions against registries and report deprecated versions.`,
		RunE:    runDeprecated,
	}

	deprecatedCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	deprecatedCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	deprecatedCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	deprecatedCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(deprecatedCmd)
}

type DeprecatedPackage struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Version      string `json:"version"`
	Message      string `json:"message,omitempty"`
	ManifestPath string `json:"manifest_path"`
	PURL         string `json:"purl,omitempty"`
}

func runDeprecated(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
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
			return outputDeprecatedJSON(cmd, []DeprecatedPackage{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No resolved dependencies found.")
		return nil
	}

	versionedPURLs := make([]string, 0, len(resolved))
	purlToDeps := make(map[string][]database.Dependency)
	for _, dep := range resolved {
		purlStr := versionedPURLForDependency(dep)
		if purlStr == "" {
			continue
		}
		if len(purlToDeps[purlStr]) == 0 {
			versionedPURLs = append(versionedPURLs, purlStr)
		}
		purlToDeps[purlStr] = append(purlToDeps[purlStr], dep)
	}

	versionData := fetchDeprecatedVersionData(db, versionedPURLs)
	deprecated := deprecatedPackages(purlToDeps, versionData)
	if len(deprecated) == 0 {
		if format == formatJSON {
			return outputDeprecatedJSON(cmd, []DeprecatedPackage{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No deprecated dependencies found.")
		return nil
	}

	switch format {
	case formatJSON:
		return outputDeprecatedJSON(cmd, deprecated)
	default:
		outputDeprecatedText(cmd, deprecated)
		return nil
	}
}

func versionedPURLForDependency(dep database.Dependency) string {
	if dep.Requirement == "" {
		return ""
	}
	if dep.PURL != "" {
		parsed, err := purl.Parse(dep.PURL)
		if err == nil && parsed.Version != "" {
			return dep.PURL
		}
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, dep.Requirement)
}

func fetchDeprecatedVersionData(db *database.DB, versionedPURLs []string) map[string]*registries.Version {
	if len(versionedPURLs) == 0 {
		return map[string]*registries.Version{}
	}

	versionData := cachedDeprecatedVersionData(db, versionedPURLs)
	misses := missingVersionedPURLs(versionedPURLs, versionData)
	if len(misses) == 0 {
		return versionData
	}

	const deprecatedLookupTimeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), deprecatedLookupTimeout)
	defer cancel()

	fetched := registries.BulkFetchVersions(ctx, misses, registries.NewClient().WithUserAgent("git-pkgs/"+version))
	for purlStr, version := range fetched {
		versionData[purlStr] = version
	}
	saveDeprecatedVersionData(db, fetched)

	return versionData
}

func cachedDeprecatedVersionData(db *database.DB, versionedPURLs []string) map[string]*registries.Version {
	result := make(map[string]*registries.Version)
	if db == nil {
		return result
	}

	staleThreshold := time.Now().Add(-enrichmentCacheTTL)
	for _, packagePURL := range uniquePackagePURLs(versionedPURLs) {
		cachedVersions, err := db.GetCachedVersions(packagePURL, enrichmentCacheTTL)
		if err != nil {
			continue
		}
		for _, cached := range cachedVersions {
			if cached.StatusCheckedAt.IsZero() || cached.StatusCheckedAt.Before(staleThreshold) {
				continue
			}
			result[cached.PURL] = &registries.Version{
				Number:      versionFromPURL(cached.PURL),
				PublishedAt: cached.PublishedAt,
				Licenses:    cached.License,
				Status:      registries.VersionStatus(cached.Status),
				Metadata:    cached.Metadata,
			}
		}
	}

	return result
}

func missingVersionedPURLs(versionedPURLs []string, versionData map[string]*registries.Version) []string {
	misses := make([]string, 0)
	for _, purlStr := range versionedPURLs {
		if _, ok := versionData[purlStr]; !ok {
			misses = append(misses, purlStr)
		}
	}
	return misses
}

func uniquePackagePURLs(versionedPURLs []string) []string {
	seen := make(map[string]bool)
	var packagePURLs []string
	for _, purlStr := range versionedPURLs {
		packagePURL := packagePURLFromVersioned(purlStr)
		if packagePURL == "" || seen[packagePURL] {
			continue
		}
		seen[packagePURL] = true
		packagePURLs = append(packagePURLs, packagePURL)
	}
	return packagePURLs
}

func packagePURLFromVersioned(purlStr string) string {
	parsed, err := purl.Parse(purlStr)
	if err != nil {
		return ""
	}
	return parsed.WithoutVersion().String()
}

func saveDeprecatedVersionData(db *database.DB, versionData map[string]*registries.Version) {
	if db == nil || len(versionData) == 0 {
		return
	}

	checkedAt := time.Now()
	toCache := make([]database.CachedVersion, 0, len(versionData))
	for purlStr, version := range versionData {
		if version == nil {
			continue
		}
		packagePURL := packagePURLFromVersioned(purlStr)
		if packagePURL == "" {
			continue
		}
		toCache = append(toCache, database.CachedVersion{
			PURL:            purlStr,
			PackagePURL:     packagePURL,
			License:         version.Licenses,
			PublishedAt:     version.PublishedAt,
			Status:          string(version.Status),
			StatusCheckedAt: checkedAt,
			Metadata:        version.Metadata,
		})
	}

	_ = db.SaveVersions(toCache)
}

func deprecatedPackages(
	purlToDeps map[string][]database.Dependency,
	versionData map[string]*registries.Version,
) []DeprecatedPackage {
	var deprecated []DeprecatedPackage

	for purlStr, version := range versionData {
		if version == nil || version.Status != registries.StatusDeprecated {
			continue
		}
		for _, dep := range purlToDeps[purlStr] {
			deprecated = append(deprecated, DeprecatedPackage{
				Name:         dep.Name,
				Ecosystem:    dep.Ecosystem,
				Version:      dep.Requirement,
				Message:      deprecationMessage(version),
				ManifestPath: dep.ManifestPath,
				PURL:         purlStr,
			})
		}
	}

	sort.Slice(deprecated, func(i, j int) bool {
		if deprecated[i].Name != deprecated[j].Name {
			return deprecated[i].Name < deprecated[j].Name
		}
		if deprecated[i].ManifestPath != deprecated[j].ManifestPath {
			return deprecated[i].ManifestPath < deprecated[j].ManifestPath
		}
		return deprecated[i].Version < deprecated[j].Version
	})

	return deprecated
}

func deprecationMessage(version *registries.Version) string {
	if version == nil || version.Metadata == nil {
		return ""
	}
	for _, key := range []string{"deprecated", "deprecation", "message"} {
		if msg, ok := stringMetadata(version.Metadata[key]); ok {
			return msg
		}
	}
	return ""
}

func stringMetadata(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v), strings.TrimSpace(v) != ""
	case fmt.Stringer:
		msg := strings.TrimSpace(v.String())
		return msg, msg != ""
	default:
		return "", false
	}
}

func outputDeprecatedJSON(cmd *cobra.Command, deprecated []DeprecatedPackage) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(deprecated)
}

func outputDeprecatedText(cmd *cobra.Command, deprecated []DeprecatedPackage) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d deprecated dependencies:\n\n", len(deprecated))
	for _, dep := range deprecated {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s\n", dep.Name, dep.Version, Dim("("+dep.ManifestPath+")"))
		if dep.Message != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", dep.Message)
		}
	}
}
