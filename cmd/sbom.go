package cmd

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/sbom"
	"github.com/spf13/cobra"
)

func addSBOMCmd(parent *cobra.Command) {
	sbomCmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate Software Bill of Materials",
		Long: `Generate a Software Bill of Materials (SBOM) in CycloneDX or SPDX format.
The SBOM includes all dependencies and optionally enriched license information.`,
		RunE: runSBOM,
	}

	sbomCmd.Flags().StringP("type", "t", "cyclonedx", "SBOM type: cyclonedx, spdx")
	sbomCmd.Flags().StringP("format", "f", "json", "Output format: json, xml")
	sbomCmd.Flags().StringP("commit", "c", "", "Generate SBOM at specific commit (default: HEAD)")
	sbomCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	sbomCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	sbomCmd.Flags().String("name", "", "Project name (default: git directory name)")
	sbomCmd.Flags().String("version", "", "Project version")
	sbomCmd.Flags().Bool("skip-enrichment", false, "Skip license enrichment from ecosyste.ms")
	parent.AddCommand(sbomCmd)
}

func runSBOM(cmd *cobra.Command, args []string) error {
	sbomType, _ := cmd.Flags().GetString("type")
	format, err := getFormatFlag(cmd, formatJSON, formatXML)
	if err != nil {
		return err
	}
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	projectName, _ := cmd.Flags().GetString("name")
	projectVersion, _ := cmd.Flags().GetString("version")
	skipEnrichment, _ := cmd.Flags().GetBool("skip-enrichment")

	out, err := sbomFormat(sbomType, format)
	if err != nil {
		return err
	}

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
	deps = selectSBOMDependencies(deps)

	licenseMap := map[string]string{}
	if !skipEnrichment {
		var packageFallbacks int
		licenseMap, packageFallbacks, err = enrichLicenses(db, deps)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: SBOM license enrichment incomplete: %v\n", err)
		}
		if packageFallbacks > 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"Warning: using package-level license metadata for %d SBOM component(s) without version license metadata\n",
				packageFallbacks,
			)
		}
	}

	if projectName == "" {
		projectName = "project"
	}

	projectLicenses, licenseWarnings, err := projectLicensesAtRevision(repo, commit)
	if err != nil {
		return fmt.Errorf("loading project licenses: %w", err)
	}
	for _, warning := range licenseWarnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
	}

	doc := buildSBOM(deps, licenseMap, projectName, projectVersion, projectLicenses)
	return sbom.Encode(cmd.OutOrStdout(), doc, out)
}

func sbomFormat(sbomType, format string) (sbom.Format, error) {
	switch {
	case sbomType == "spdx" && format == "json":
		return sbom.FormatSPDXJSON, nil
	case sbomType == "spdx":
		return 0, fmt.Errorf("SPDX %s format not supported, use json", format)
	case format == "xml":
		return sbom.FormatCycloneDXXML, nil
	default:
		return sbom.FormatCycloneDXJSON, nil
	}
}

func buildSBOM(
	deps []database.Dependency,
	licenses map[string]string,
	name, ver string,
	projectLicenseData projectLicenses,
) *sbom.SBOM {
	s := sbom.New(sbom.TypeCycloneDX)
	extractedLicenses := make([]sbom.ExtractedLicense, 0, len(projectLicenseData.Files))
	for _, file := range projectLicenseData.Files {
		extractedLicenses = append(extractedLicenses, sbom.ExtractedLicense{
			Name: file.Path,
			Text: file.Text,
		})
	}
	s.Document = sbom.Document{
		Name:      name,
		Namespace: "https://git-pkgs.example.com/" + name,
		Component: sbom.Component{
			Type:              "application",
			Name:              name,
			Version:           ver,
			LicenseExpression: projectLicenseData.Expression,
			LicenseNames:      projectLicenseData.Names,
			ExtractedLicenses: extractedLicenses,
		},
		Creators: []sbom.Creator{{Type: "Tool", Name: "git-pkgs-" + version}},
	}
	for _, d := range deps {
		purlStr := sbomPURLForDependency(d)
		p := sbom.Package{
			Name:    d.Name,
			Version: d.Requirement,
		}
		if purlStr != "" {
			p.ExternalRefs = []sbom.ExternalRef{{
				Category: "PACKAGE_MANAGER", Type: "purl", Locator: purlStr,
			}}
		}
		if lic := licenses[purlStr]; lic != "" {
			p.LicenseConcluded = lic
			p.LicenseDeclared = lic
		}
		s.AddPackage(p)
	}
	return s
}

func sbomPURLForDependency(dep database.Dependency) string {
	if isResolvedDependency(dep) {
		if versionedPURL := versionedPURLForDependency(dep); versionedPURL != "" {
			return versionedPURL
		}
	}
	if dep.PURL != "" {
		return dep.PURL
	}
	if dep.Ecosystem == "" || dep.Name == "" {
		return ""
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, "")
}

func selectSBOMDependencies(deps []database.Dependency) []database.Dependency {
	resolvedLocations := make(map[string]bool)
	for _, dep := range deps {
		if isResolvedDependency(dep) {
			resolvedLocations[sbomDependencyLocation(dep)] = true
		}
	}

	selected := make([]database.Dependency, 0, len(deps))
	seen := make(map[string]bool)
	for _, dep := range deps {
		if !isResolvedDependency(dep) && resolvedLocations[sbomDependencyLocation(dep)] {
			continue
		}
		key := sbomDependencyKey(dep)
		if seen[key] {
			continue
		}
		seen[key] = true
		selected = append(selected, dep)
	}
	return selected
}

func sbomDependencyKey(dep database.Dependency) string {
	if purlStr := sbomPURLForDependency(dep); purlStr != "" {
		return "purl\x00" + purlStr
	}
	return "dependency\x00" + strings.ToLower(dep.Ecosystem) + "\x00" +
		strings.ToLower(dep.Name) + "\x00" + dep.Requirement
}

func sbomDependencyLocation(dep database.Dependency) string {
	return strings.ToLower(dep.Ecosystem) + "\x00" + strings.ToLower(dep.Name) + "\x00" + path.Dir(dep.ManifestPath)
}

func enrichLicenses(db *database.DB, deps []database.Dependency) (map[string]string, int, error) {
	purls := make([]string, 0, len(deps))
	purlToDep := make(map[string]database.Dependency)
	seen := make(map[string]bool)
	for _, d := range deps {
		purlStr := licensePackagePURLForDependency(d)
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
		purlToDep[purlStr] = d
	}
	if len(purls) == 0 {
		return map[string]string{}, 0, nil
	}

	packageLicenses, packageErr := getSBOMLicenseData(db, purls, purlToDep)
	resolved := make([]database.Dependency, 0, len(deps))
	for _, dep := range deps {
		if isResolvedDependency(dep) {
			resolved = append(resolved, dep)
		}
	}
	versionLicenses, versionErr := loadLicenseVersionLicenses(db, resolved, false)

	licenses, packageFallbacks := selectSBOMLicenses(deps, packageLicenses, versionLicenses)
	return licenses, packageFallbacks, errors.Join(packageErr, versionErr)
}

func selectSBOMLicenses(
	deps []database.Dependency,
	packageLicenses map[string]string,
	versionLicenses map[string]string,
) (map[string]string, int) {
	licenses := make(map[string]string)
	fallbacks := make(map[string]bool)
	for _, dep := range deps {
		componentPURL := sbomPURLForDependency(dep)
		if componentPURL == "" {
			continue
		}
		if versionLicense := versionLicenses[versionedPURLForDependency(dep)]; versionLicense != "" {
			licenses[componentPURL] = versionLicense
			continue
		}
		packageLicense := packageLicenses[licensePackagePURLForDependency(dep)]
		if packageLicense == "" {
			continue
		}
		licenses[componentPURL] = packageLicense
		fallbacks[componentPURL] = true
	}
	return licenses, len(fallbacks)
}

func getSBOMLicenseData(db *database.DB, purls []string, purlToDep map[string]database.Dependency) (map[string]string, error) {
	result := make(map[string]string)
	var uncachedPurls []string

	// Check cache if DB is available
	if db != nil {
		cached, err := db.GetCachedPackages(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, err
		}
		for purl, cp := range cached {
			result[purl] = cp.License
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

		const sbomTimeout = 60 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), sbomTimeout)
		defer cancel()

		packages, err := client.BulkLookup(ctx, uncachedPurls)
		if err != nil {
			return nil, wrapEcosystemsError(err)
		}

		for purl, pkg := range packages {
			license := ""
			if pkg != nil {
				license = pkg.License
			}
			result[purl] = license

			// Save to cache if DB available
			if db != nil && pkg != nil {
				dep := purlToDep[purl]
				_ = db.SavePackageEnrichment(purl, dep.Ecosystem, dep.Name, pkg.LatestVersion, pkg.License, pkg.RegistryURL, pkg.Source)
			}
		}
	}

	return result, nil
}
