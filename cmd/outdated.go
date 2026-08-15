package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vers"
	"github.com/spf13/cobra"
)

func addOutdatedCmd(parent *cobra.Command) {
	outdatedCmd := &cobra.Command{
		Use:   "outdated",
		Short: "Find packages with newer versions available",
		Long: `Check dependencies against the ecosyste.ms API to find packages
with newer versions available.`,
		RunE: runOutdated,
	}

	outdatedCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	outdatedCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	outdatedCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	outdatedCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	outdatedCmd.Flags().Bool("major", false, "Only show major version updates")
	outdatedCmd.Flags().Bool("minor", false, "Skip patch-only updates")
	outdatedCmd.Flags().String("at", "", "Check what was outdated at this date (YYYY-MM-DD)")
	parent.AddCommand(outdatedCmd)
}

type OutdatedPackage struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	UpdateType     string `json:"update_type"` // major, minor, patch
	ManifestPath   string `json:"manifest_path"`
	PURL           string `json:"purl,omitempty"`
}

// Default cache TTL for enrichment data (24 hours)
const enrichmentCacheTTL = 24 * time.Hour

func runOutdated(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	majorOnly, _ := cmd.Flags().GetBool("major")
	minorUp, _ := cmd.Flags().GetBool("minor")
	atDate, _ := cmd.Flags().GetString("at")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	deps, db, err := getDependenciesWithDB(repo, commit, branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, ecosystem)

	// Filter to resolved dependencies (lockfiles and Go modules)
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if isResolvedDependency(d) {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		if format == formatJSON {
			return outputOutdatedJSON(cmd, nil)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found.")
		return nil
	}

	// Build PURLs for lookup (without version for cache key)
	purls := make([]string, 0, len(lockfileDeps))
	purlToDep := make(map[string]database.Dependency)
	for _, d := range lockfileDeps {
		// Build PURL without version for cache lookup
		purlStr := purl.MakePURLString(d.Ecosystem, d.Name, "")
		if purlStr != "" {
			purls = append(purls, purlStr)
			purlToDep[purlStr] = d
		}
	}

	// Parse --at date if provided
	var atTime time.Time
	if atDate != "" {
		atTime, err = time.Parse("2006-01-02", atDate)
		if err != nil {
			return fmt.Errorf("invalid date format (use YYYY-MM-DD): %w", err)
		}
	}

	// Get package data (from cache or API)
	packageData, err := getPackageData(db, purls, purlToDep)
	if err != nil {
		return fmt.Errorf("looking up packages: %w", err)
	}

	// Compare versions
	var outdated []OutdatedPackage
	for purl, data := range packageData {
		if data.LatestVersion == "" {
			continue
		}

		dep := purlToDep[purl]
		current := dep.Requirement
		latest := data.LatestVersion

		// If --at is specified, find the latest version at that date
		if !atTime.IsZero() {
			latest = findLatestAtDateCached(db, purl, atTime)
			if latest == "" {
				continue
			}
		}

		// Compare versions
		cmp := vers.Compare(current, latest)
		if cmp >= 0 {
			continue // Not outdated
		}

		updateType := classifyUpdate(current, latest)
		if updateType == "" {
			continue // Invalid version format
		}

		// Apply filters
		if majorOnly && updateType != updateMajor {
			continue
		}
		if minorUp && updateType == updatePatch {
			continue
		}

		outdated = append(outdated, OutdatedPackage{
			Name:           dep.Name,
			Ecosystem:      dep.Ecosystem,
			CurrentVersion: current,
			LatestVersion:  latest,
			UpdateType:     updateType,
			ManifestPath:   dep.ManifestPath,
			PURL:           purl,
		})
	}

	if format == formatJSON {
		return outputOutdatedJSON(cmd, outdated)
	}
	if len(outdated) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All dependencies are up to date.")
		return nil
	}
	outputOutdatedText(cmd, outdated)
	return nil
}

type packageInfo struct {
	Ecosystem     string
	Name          string
	LatestVersion string
	License       string
	RegistryURL   string
	Source        string
}

func getPackageData(db *database.DB, purls []string, purlToDep map[string]database.Dependency) (map[string]*packageInfo, error) {
	result := make(map[string]*packageInfo)
	var uncachedPurls []string

	// Check cache if DB is available
	if db != nil {
		cached, err := db.GetCachedPackages(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, err
		}

		for purl, cp := range cached {
			result[purl] = &packageInfo{
				Ecosystem:     cp.Ecosystem,
				Name:          cp.Name,
				LatestVersion: cp.LatestVersion,
				License:       cp.License,
			}
		}
		// Find uncached PURLs
		for _, purl := range purls {
			if _, ok := cached[purl]; !ok {
				uncachedPurls = append(uncachedPurls, purl)
			}
		}
	} else {
		uncachedPurls = purls
	}

	// Fetch uncached from API
	if len(uncachedPurls) > 0 {
		client, err := newEnrichmentClient()
		if err != nil {
			return nil, err
		}

		const outdatedTimeout = 60 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), outdatedTimeout)
		defer cancel()

		packages, err := client.BulkLookup(ctx, uncachedPurls)
		if err != nil {
			return nil, wrapEcosystemsError(err)
		}

		var toSave []database.PackageEnrichmentData
		for purl, pkg := range packages {
			if pkg == nil {
				continue
			}

			info := &packageInfo{
				Ecosystem:     pkg.Ecosystem,
				Name:          pkg.Name,
				LatestVersion: pkg.LatestVersion,
				License:       pkg.License,
				RegistryURL:   pkg.RegistryURL,
				Source:        pkg.Source,
			}
			result[purl] = info

			// Collect for batch save
			if db != nil {
				dep := purlToDep[purl]
				toSave = append(toSave, database.PackageEnrichmentData{
					PURL:          purl,
					Ecosystem:     dep.Ecosystem,
					Name:          dep.Name,
					LatestVersion: info.LatestVersion,
					License:       info.License,
					RegistryURL:   info.RegistryURL,
					Source:        info.Source,
				})
			}
		}

		// Batch save to cache
		if db != nil && len(toSave) > 0 {
			_ = db.SavePackageEnrichmentBatch(toSave)
		}
	}

	return result, nil
}

func findLatestAtDateCached(db *database.DB, purl string, atTime time.Time) string {
	// Check cache first if DB available
	if db != nil {
		versions, err := db.GetCachedVersionList(purl, enrichmentCacheTTL)
		if err == nil && hasCachedVersionStatuses(versions) {
			if latestVersion := latestAvailableVersionAt(versions, atTime); latestVersion != "" {
				return latestVersion
			}
		}
	}

	// Fall back to API
	client, err := newEnrichmentClient()
	if err != nil {
		return ""
	}

	const versionLookupTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), versionLookupTimeout)
	defer cancel()

	apiVersions, err := client.GetVersions(ctx, purl)
	if err != nil {
		return ""
	}

	var toCache []database.CachedVersion
	checkedAt := time.Now()

	for _, v := range apiVersions {
		// Build version PURL
		versionPurl := purl + "@" + v.Number
		cachedVersion := database.CachedVersion{
			PURL:            versionPurl,
			PackagePURL:     purl,
			PublishedAt:     v.PublishedAt,
			Status:          enrichmentVersionStatus(v),
			StatusCheckedAt: checkedAt,
			Metadata:        v.Metadata,
		}
		toCache = append(toCache, cachedVersion)
	}

	// Save to cache if DB available
	if db != nil && len(toCache) > 0 {
		_ = db.SaveVersionList(purl, toCache)
	}

	return latestAvailableVersionAt(toCache, atTime)
}

func latestAvailableVersionAt(versions []database.CachedVersion, atTime time.Time) string {
	var latestVersion string
	var latestTime time.Time
	for _, version := range versions {
		if version.PublishedAt.IsZero() || version.PublishedAt.After(atTime) || isWithdrawnVersionStatus(version.Status) {
			continue
		}
		if latestVersion == "" || version.PublishedAt.After(latestTime) {
			latestVersion = versionFromPURL(version.PURL)
			latestTime = version.PublishedAt
		}
	}
	return latestVersion
}

func classifyUpdate(current, latest string) string {
	currentInfo, err := vers.ParseVersion(current)
	if err != nil {
		return ""
	}
	latestInfo, err := vers.ParseVersion(latest)
	if err != nil {
		return ""
	}

	if latestInfo.Major > currentInfo.Major {
		return updateMajor
	}
	if latestInfo.Minor > currentInfo.Minor {
		return updateMinor
	}
	if latestInfo.Patch > currentInfo.Patch {
		return updatePatch
	}

	// Handle prerelease upgrades
	if currentInfo.Prerelease != "" && latestInfo.Prerelease == "" {
		return updatePatch
	}

	return ""
}

func outputOutdatedJSON(cmd *cobra.Command, outdated []OutdatedPackage) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(outdated))
}

func outputOutdatedText(cmd *cobra.Command, outdated []OutdatedPackage) {
	// Group by update type
	var major, minor, patch []OutdatedPackage
	for _, o := range outdated {
		switch o.UpdateType {
		case updateMajor:
			major = append(major, o)
		case updateMinor:
			minor = append(minor, o)
		case updatePatch:
			patch = append(patch, o)
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d outdated dependencies:\n\n", len(outdated))

	if len(major) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Major updates:")
		for _, o := range major {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s -> %s\n", o.Name, o.CurrentVersion, o.LatestVersion)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(minor) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Minor updates:")
		for _, o := range minor {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s -> %s\n", o.Name, o.CurrentVersion, o.LatestVersion)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(patch) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Patch updates:")
		for _, o := range patch {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s -> %s\n", o.Name, o.CurrentVersion, o.LatestVersion)
		}
	}
}
