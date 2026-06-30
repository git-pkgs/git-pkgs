package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/spdx"
	"github.com/spf13/cobra"
)

func addLicensesCmd(parent *cobra.Command) {
	licensesCmd := &cobra.Command{
		Use:   "licenses",
		Short: "Show license information for dependencies",
		Long: `Retrieve license information for all dependencies in the project.
Licenses are normalized to SPDX identifiers when possible.`,
		RunE: runLicenses,
	}

	licensesCmd.Flags().StringP("commit", "c", "", "Check licenses at specific commit (default: HEAD)")
	licensesCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	licensesCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	licensesCmd.Flags().StringP("format", "f", "text", "Output format: text, json, csv")
	licensesCmd.Flags().StringSlice("allow", nil, "Only allow these licenses (exit 1 on violation)")
	licensesCmd.Flags().StringSlice("deny", nil, "Deny these licenses (exit 1 if found)")
	licensesCmd.Flags().Bool("permissive", false, "Flag non-permissive licenses")
	licensesCmd.Flags().Bool("copyleft", false, "Flag copyleft licenses (GPL, AGPL)")
	licensesCmd.Flags().Bool("unknown", false, "Flag packages with unknown licenses")
	licensesCmd.Flags().Bool("group", false, "Group output by license")
	licensesCmd.Flags().Bool("drift", false, "Detect dependencies whose license changed between installed and latest versions")
	parent.AddCommand(licensesCmd)
}

type LicenseInfo struct {
	Name         string   `json:"name"`
	Ecosystem    string   `json:"ecosystem"`
	Version      string   `json:"version,omitempty"`
	Licenses     []string `json:"licenses"`
	LicenseText  string   `json:"license_text,omitempty"`
	ManifestPath string   `json:"manifest_path"`
	PURL         string   `json:"purl,omitempty"`
	Flagged      bool     `json:"flagged,omitempty"`
	FlagReason   string   `json:"flag_reason,omitempty"`
}

type LicenseDriftSummary struct {
	TotalDependencies      int `json:"total_dependencies"`
	CheckedDependencies    int `json:"checked_dependencies"`
	DriftedDependencies    int `json:"drifted_dependencies"`
	UnresolvedDependencies int `json:"unresolved_dependencies"`
}

type LicenseDriftEntry struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	CurrentLicense string `json:"current_license"`
	LatestLicense  string `json:"latest_license"`
	ManifestPath   string `json:"manifest_path"`
	PURL           string `json:"purl,omitempty"`
}

type LicenseDriftResult struct {
	Summary      LicenseDriftSummary `json:"summary"`
	Dependencies []LicenseDriftEntry `json:"dependencies"`
}

func runLicenses(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	allowList, _ := cmd.Flags().GetStringSlice("allow")
	denyList, _ := cmd.Flags().GetStringSlice("deny")
	flagPermissive, _ := cmd.Flags().GetBool("permissive")
	flagCopyleft, _ := cmd.Flags().GetBool("copyleft")
	flagUnknown, _ := cmd.Flags().GetBool("unknown")
	groupBy, _ := cmd.Flags().GetBool("group")
	driftOnly, _ := cmd.Flags().GetBool("drift")

	if driftOnly {
		if err := validateLicenseDriftFlags(allowList, denyList, flagPermissive, flagCopyleft, flagUnknown, groupBy); err != nil {
			return err
		}
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

	deps = filterByEcosystem(deps, ecosystem)

	if driftOnly {
		return runLicenseDrift(cmd, db, deps, format)
	}

	// Filter to manifest dependencies (direct deps)
	var directDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "manifest" {
			directDeps = append(directDeps, d)
		}
	}

	if len(directDeps) == 0 {
		if format == formatJSON {
			return outputLicensesJSON(cmd, nil)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No direct dependencies found.")
		return nil
	}

	// Build PURLs
	purls := make([]string, 0, len(directDeps))
	purlToDep := make(map[string]database.Dependency)
	for _, d := range directDeps {
		purlStr := d.PURL
		if purlStr == "" {
			purlStr = purl.MakePURLString(d.Ecosystem, d.Name, "")
		}
		if purlStr != "" {
			purls = append(purls, purlStr)
			purlToDep[purlStr] = d
		}
	}

	// Get license data (from cache or API)
	packageData, err := getLicenseData(db, purls, purlToDep)
	if err != nil {
		return fmt.Errorf("looking up packages: %w", err)
	}

	// Normalize allow/deny lists to SPDX identifiers
	allowSet := make(map[string]bool)
	for _, l := range allowList {
		if normalized, err := spdx.Normalize(l); err == nil {
			allowSet[normalized] = true
		} else {
			allowSet[strings.ToLower(l)] = true
		}
	}
	denySet := make(map[string]bool)
	for _, l := range denyList {
		if normalized, err := spdx.Normalize(l); err == nil {
			denySet[normalized] = true
		} else {
			denySet[strings.ToLower(l)] = true
		}
	}

	// Build license info
	var licenseInfos []LicenseInfo
	hasViolations := false

	for purl, data := range packageData {
		dep := purlToDep[purl]

		// Use API data when dep lookup failed (PURL mismatch)
		name := dep.Name
		ecosystem := dep.Ecosystem
		if name == "" && data.Name != "" {
			name = data.Name
			ecosystem = data.Ecosystem
		}

		info := LicenseInfo{
			Name:         name,
			Ecosystem:    ecosystem,
			Version:      dep.Requirement,
			ManifestPath: dep.ManifestPath,
			PURL:         purl,
		}

		if data.License != "" {
			info.Licenses = []string{data.License}
		}

		// Check for violations
		if len(info.Licenses) == 0 {
			info.Licenses = []string{"Unknown"}
			if flagUnknown {
				info.Flagged = true
				info.FlagReason = "unknown license"
				hasViolations = true
			}
		} else {
			for _, lic := range info.Licenses {
				// Check allow list (compare normalized forms)
				if len(allowSet) > 0 {
					inAllowList := allowSet[lic]
					if !inAllowList {
						if normalized, err := spdx.Normalize(lic); err == nil {
							inAllowList = allowSet[normalized]
						}
					}
					if !inAllowList {
						inAllowList = allowSet[strings.ToLower(lic)]
					}
					if !inAllowList {
						info.Flagged = true
						info.FlagReason = fmt.Sprintf("license %q not in allow list", lic)
						hasViolations = true
					}
				}

				// Check deny list (compare normalized forms)
				inDenyList := denySet[lic]
				if !inDenyList {
					if normalized, err := spdx.Normalize(lic); err == nil {
						inDenyList = denySet[normalized]
					}
				}
				if !inDenyList {
					inDenyList = denySet[strings.ToLower(lic)]
				}
				if inDenyList {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q is denied", lic)
					hasViolations = true
				}

				// Check permissive using spdx library
				if flagPermissive && !spdx.IsFullyPermissive(lic) {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q is not permissive", lic)
					hasViolations = true
				}

				// Check copyleft using spdx library
				if flagCopyleft && spdx.HasCopyleft(lic) {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q is copyleft", lic)
					hasViolations = true
				}
			}
		}

		licenseInfos = append(licenseInfos, info)
	}

	// Sort by name
	sort.Slice(licenseInfos, func(i, j int) bool {
		if licenseInfos[i].Name != licenseInfos[j].Name {
			return licenseInfos[i].Name < licenseInfos[j].Name
		}
		return licenseInfos[i].Version < licenseInfos[j].Version
	})

	switch format {
	case formatJSON:
		err = outputLicensesJSON(cmd, licenseInfos)
	case "csv":
		err = outputLicensesCSV(cmd, licenseInfos)
	default:
		if groupBy {
			outputLicensesGrouped(cmd, licenseInfos)
		} else {
			outputLicensesText(cmd, licenseInfos)
		}
	}

	if err != nil {
		return err
	}

	if hasViolations {
		return fmt.Errorf("license violations found")
	}
	return nil
}

func validateLicenseDriftFlags(allowList, denyList []string, flagPermissive, flagCopyleft, flagUnknown, groupBy bool) error {
	var incompatible []string
	if len(allowList) > 0 {
		incompatible = append(incompatible, "--allow")
	}
	if len(denyList) > 0 {
		incompatible = append(incompatible, "--deny")
	}
	if flagPermissive {
		incompatible = append(incompatible, "--permissive")
	}
	if flagCopyleft {
		incompatible = append(incompatible, "--copyleft")
	}
	if flagUnknown {
		incompatible = append(incompatible, "--unknown")
	}
	if groupBy {
		incompatible = append(incompatible, "--group")
	}
	if len(incompatible) == 0 {
		return nil
	}
	return fmt.Errorf("--drift cannot be combined with %s", strings.Join(incompatible, ", "))
}

type licenseData struct {
	License       string
	Name          string
	Ecosystem     string
	LatestVersion string
}

func getLicenseData(db *database.DB, purls []string, purlToDep map[string]database.Dependency) (map[string]*licenseData, error) {
	result := make(map[string]*licenseData)
	var uncachedPurls []string

	// Check cache if DB is available
	if db != nil {
		cached, err := db.GetCachedPackages(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, err
		}
		for purl, cp := range cached {
			result[purl] = &licenseData{
				License:       cp.License,
				Name:          cp.Name,
				Ecosystem:     cp.Ecosystem,
				LatestVersion: cp.LatestVersion,
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

		const licensesTimeout = 60 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), licensesTimeout)
		defer cancel()

		packages, err := client.BulkLookup(ctx, uncachedPurls)
		if err != nil {
			return nil, wrapEcosystemsError(err)
		}

		for purl, pkg := range packages {
			data := &licenseData{}
			if pkg != nil {
				data.Name = pkg.Name
				data.Ecosystem = pkg.Ecosystem
				data.LatestVersion = pkg.LatestVersion
				// Normalize license to SPDX identifier
				if pkg.License != "" {
					if normalized, err := spdx.Normalize(pkg.License); err == nil {
						data.License = normalized
					} else {
						data.License = pkg.License
					}
				}
			}
			result[purl] = data

			// Save to cache if DB available
			if db != nil && pkg != nil {
				// Use API data for ecosystem/name (in case PURL was canonicalized)
				_ = db.SavePackageEnrichment(purl, pkg.Ecosystem, pkg.Name, pkg.LatestVersion, pkg.License, pkg.RegistryURL, pkg.Source)
			}
		}
	}

	return result, nil
}

func runLicenseDrift(cmd *cobra.Command, db *database.DB, deps []database.Dependency, format string) error {
	resolved := make([]database.Dependency, 0, len(deps))
	for _, dep := range deps {
		if isResolvedDependency(dep) {
			resolved = append(resolved, dep)
		}
	}

	if len(resolved) == 0 {
		result := emptyLicenseDriftResult()
		if format == formatJSON {
			return outputLicenseDriftJSON(cmd, result)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No resolved dependencies found.")
		return nil
	}

	result, err := computeLicenseDrift(db, resolved)
	if err != nil {
		return err
	}

	switch format {
	case formatJSON:
		return outputLicenseDriftJSON(cmd, result)
	case "csv":
		return outputLicenseDriftCSV(cmd, result.Dependencies)
	default:
		outputLicenseDriftText(cmd, result)
		return nil
	}
}

func computeLicenseDrift(db *database.DB, deps []database.Dependency) (*LicenseDriftResult, error) {
	result := emptyLicenseDriftResult()
	result.Summary.TotalDependencies = len(deps)

	packagePURLs := make([]string, 0, len(deps))
	purlToDep := make(map[string]database.Dependency)
	seenPURLs := make(map[string]bool)
	for _, dep := range deps {
		packagePURL := licensePackagePURLForDependency(dep)
		if packagePURL == "" {
			continue
		}
		if !seenPURLs[packagePURL] {
			seenPURLs[packagePURL] = true
			packagePURLs = append(packagePURLs, packagePURL)
			purlToDep[packagePURL] = dep
		}
	}

	packageLicenses, err := getLicenseData(db, packagePURLs, purlToDep)
	if err != nil {
		return nil, fmt.Errorf("looking up package licenses: %w", err)
	}

	versionLicenses, err := loadLicenseDriftVersionLicenses(db, deps)
	if err != nil {
		return nil, fmt.Errorf("looking up version licenses: %w", err)
	}

	seenDeps := make(map[string]bool)
	for _, dep := range deps {
		packagePURL := licensePackagePURLForDependency(dep)
		versionedPURL := versionedPURLForDependency(dep)
		key := packagePURL + "\x00" + dep.Requirement + "\x00" + dep.ManifestPath
		if packagePURL == "" || versionedPURL == "" || seenDeps[key] {
			continue
		}
		seenDeps[key] = true

		packageData := packageLicenses[packagePURL]
		currentLicense := normalizeLicenseString(versionLicenses[versionedPURL])
		latestLicense := ""
		latestVersion := ""
		if packageData != nil {
			latestLicense = normalizeLicenseString(packageData.License)
			latestVersion = packageData.LatestVersion
		}

		if currentLicense == "" || latestLicense == "" {
			result.Summary.UnresolvedDependencies++
			continue
		}

		result.Summary.CheckedDependencies++
		if currentLicense == latestLicense {
			continue
		}

		result.Summary.DriftedDependencies++
		result.Dependencies = append(result.Dependencies, LicenseDriftEntry{
			Name:           dep.Name,
			Ecosystem:      dep.Ecosystem,
			CurrentVersion: dep.Requirement,
			LatestVersion:  latestVersion,
			CurrentLicense: currentLicense,
			LatestLicense:  latestLicense,
			ManifestPath:   dep.ManifestPath,
			PURL:           versionedPURL,
		})
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		if result.Dependencies[i].ManifestPath != result.Dependencies[j].ManifestPath {
			return result.Dependencies[i].ManifestPath < result.Dependencies[j].ManifestPath
		}
		return result.Dependencies[i].CurrentVersion < result.Dependencies[j].CurrentVersion
	})

	return result, nil
}

func licensePackagePURLForDependency(dep database.Dependency) string {
	versionedPURL := versionedPURLForDependency(dep)
	if versionedPURL != "" {
		return packagePURLFromVersioned(versionedPURL)
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, "")
}

func loadLicenseDriftVersionLicenses(db *database.DB, deps []database.Dependency) (map[string]string, error) {
	needed := make(map[string]map[string]bool)
	for _, dep := range deps {
		versionedPURL := versionedPURLForDependency(dep)
		packagePURL := licensePackagePURLForDependency(dep)
		if versionedPURL == "" || packagePURL == "" || dep.Requirement == "" {
			continue
		}
		if needed[packagePURL] == nil {
			needed[packagePURL] = make(map[string]bool)
		}
		needed[packagePURL][dep.Requirement] = true
	}

	result := cachedLicenseDriftVersionLicenses(db, needed)
	var missing []licenseDriftVersionLookup
	for packagePURL, versions := range needed {
		for version := range versions {
			versionedPURL := licenseVersionedPURL(packagePURL, version)
			if versionedPURL == "" || result[versionedPURL] != "" {
				continue
			}
			missing = append(missing, licenseDriftVersionLookup{
				PackagePURL:   packagePURL,
				VersionedPURL: versionedPURL,
			})
		}
	}
	if len(missing) == 0 {
		return result, nil
	}

	client, err := newEnrichmentClient()
	if err != nil {
		return nil, err
	}

	const licenseDriftLookupTimeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), licenseDriftLookupTimeout)
	defer cancel()

	fetched, fetchErrors := fetchLicenseDriftVersions(ctx, client, missing)
	for _, fetchedVersion := range fetched {
		saveLicenseDriftVersion(db, fetchedVersion.PackagePURL, fetchedVersion.VersionedPURL, fetchedVersion.Version)
		if fetchedVersion.Version == nil || fetchedVersion.Version.License == "" {
			continue
		}
		result[fetchedVersion.VersionedPURL] = normalizeLicenseString(fetchedVersion.Version.License)
	}
	if len(fetchErrors) == len(missing) {
		return nil, fmt.Errorf("fetching license drift metadata failed for all %d uncached versions: %w",
			len(missing), wrapEcosystemsError(errors.Join(fetchErrors...)))
	}

	return result, nil
}

type licenseDriftVersionLookup struct {
	PackagePURL   string
	VersionedPURL string
}

type fetchedLicenseDriftVersion struct {
	licenseDriftVersionLookup
	Version *enrichment.VersionInfo
}

func fetchLicenseDriftVersions(
	ctx context.Context,
	client enrichment.Client,
	missing []licenseDriftVersionLookup,
) ([]fetchedLicenseDriftVersion, []error) {
	const licenseDriftLookupConcurrency = 8

	workers := licenseDriftLookupConcurrency
	if len(missing) < workers {
		workers = len(missing)
	}
	jobs := make(chan licenseDriftVersionLookup)
	results := make(chan fetchedLicenseDriftVersion, len(missing))
	errorsCh := make(chan error, len(missing))

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for lookup := range jobs {
				versionInfo, err := client.GetVersion(ctx, lookup.VersionedPURL)
				if err != nil {
					errorsCh <- fmt.Errorf("%s: %w", lookup.VersionedPURL, err)
					continue
				}
				results <- fetchedLicenseDriftVersion{
					licenseDriftVersionLookup: lookup,
					Version:                   versionInfo,
				}
			}
		}()
	}

	for _, lookup := range missing {
		jobs <- lookup
	}
	close(jobs)
	wg.Wait()
	close(results)
	close(errorsCh)

	var fetched []fetchedLicenseDriftVersion
	for result := range results {
		fetched = append(fetched, result)
	}
	var fetchErrors []error
	for err := range errorsCh {
		fetchErrors = append(fetchErrors, err)
	}
	return fetched, fetchErrors
}

func cachedLicenseDriftVersionLicenses(db *database.DB, needed map[string]map[string]bool) map[string]string {
	result := make(map[string]string)
	if db == nil {
		return result
	}

	for packagePURL := range needed {
		cached, err := db.GetCachedVersions(packagePURL, enrichmentCacheTTL)
		if err != nil {
			continue
		}
		for _, cachedVersion := range cached {
			if cachedVersion.License == "" {
				continue
			}
			result[cachedVersion.PURL] = normalizeLicenseString(cachedVersion.License)
		}
	}
	return result
}

func saveLicenseDriftVersion(db *database.DB, packagePURL string, versionedPURL string, versionInfo *enrichment.VersionInfo) {
	if db == nil || versionInfo == nil || versionedPURL == "" {
		return
	}

	_ = db.SaveVersions([]database.CachedVersion{{
		PURL:        versionedPURL,
		PackagePURL: packagePURL,
		License:     normalizeLicenseString(versionInfo.License),
		PublishedAt: versionInfo.PublishedAt,
	}})
}

func licenseVersionedPURL(packagePURL string, version string) string {
	if packagePURL == "" || version == "" {
		return ""
	}
	parsed, err := purl.Parse(packagePURL)
	if err != nil {
		return ""
	}
	return parsed.WithVersion(version).String()
}

func normalizeLicenseString(license string) string {
	license = strings.TrimSpace(license)
	if license == "" {
		return ""
	}
	if normalized, err := spdx.Normalize(license); err == nil {
		return normalized
	}
	return license
}

func emptyLicenseDriftResult() *LicenseDriftResult {
	return &LicenseDriftResult{
		Dependencies: []LicenseDriftEntry{},
	}
}

func outputLicenseDriftJSON(cmd *cobra.Command, result *LicenseDriftResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputLicenseDriftCSV(cmd *cobra.Command, entries []LicenseDriftEntry) error {
	w := csv.NewWriter(cmd.OutOrStdout())
	defer w.Flush()

	if err := w.Write([]string{"Name", "Ecosystem", "Current Version", "Latest Version", "Current License", "Latest License", "Manifest", "PURL"}); err != nil {
		return err
	}
	for _, entry := range entries {
		if err := w.Write([]string{
			entry.Name,
			entry.Ecosystem,
			entry.CurrentVersion,
			entry.LatestVersion,
			entry.CurrentLicense,
			entry.LatestLicense,
			entry.ManifestPath,
			entry.PURL,
		}); err != nil {
			return err
		}
	}
	return nil
}

func outputLicenseDriftText(cmd *cobra.Command, result *LicenseDriftResult) {
	if len(result.Dependencies) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No license drift detected.")
		if result.Summary.UnresolvedDependencies > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Unresolved dependencies: %d\n", result.Summary.UnresolvedDependencies)
		}
		return
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d dependencies with license drift:\n\n", len(result.Dependencies))
	for _, entry := range result.Dependencies {
		latestVersion := entry.LatestVersion
		if latestVersion == "" {
			latestVersion = "latest"
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%s): %s %s -> %s %s\n",
			entry.Name,
			entry.Ecosystem,
			entry.CurrentVersion,
			entry.CurrentLicense,
			latestVersion,
			entry.LatestLicense,
		)
	}
}

func outputLicensesJSON(cmd *cobra.Command, infos []LicenseInfo) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(infos))
}

func outputLicensesCSV(cmd *cobra.Command, infos []LicenseInfo) error {
	w := csv.NewWriter(cmd.OutOrStdout())
	defer w.Flush()

	if err := w.Write([]string{"Name", "Ecosystem", "Version", "Licenses", "Manifest", "Flagged", "Reason"}); err != nil {
		return err
	}

	for _, info := range infos {
		flagged := ""
		if info.Flagged {
			flagged = displayYes
		}
		if err := w.Write([]string{
			info.Name,
			info.Ecosystem,
			info.Version,
			strings.Join(info.Licenses, ", "),
			info.ManifestPath,
			flagged,
			info.FlagReason,
		}); err != nil {
			return err
		}
	}
	return nil
}

func outputLicensesText(cmd *cobra.Command, infos []LicenseInfo) {
	for _, info := range infos {
		licenses := strings.Join(info.Licenses, ", ")
		line := fmt.Sprintf("%s (%s): %s", info.Name, info.Ecosystem, licenses)
		if info.Flagged {
			line += fmt.Sprintf(" [FLAGGED: %s]", info.FlagReason)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
	}
}

func outputLicensesGrouped(cmd *cobra.Command, infos []LicenseInfo) {
	groups := make(map[string][]LicenseInfo)

	for _, info := range infos {
		key := strings.Join(info.Licenses, ", ")
		groups[key] = append(groups[key], info)
	}

	// Sort keys
	var keys []string
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:\n", key)
		for _, info := range groups[key] {
			line := fmt.Sprintf("  %s", info.Name)
			if info.Flagged {
				line += fmt.Sprintf(" [FLAGGED: %s]", info.FlagReason)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}
