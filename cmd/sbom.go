package cmd

import (
	"context"
	"fmt"
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
	format, _ := cmd.Flags().GetString("format")
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

	deps, db, err := repo.GetDependenciesWithDB(commit, branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, ecosystem)

	licenseMap := map[string]string{}
	if !skipEnrichment {
		licenseMap = enrichLicenses(db, deps)
	}

	if projectName == "" {
		projectName = "project"
	}

	doc := buildSBOM(deps, licenseMap, projectName, projectVersion)
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

func buildSBOM(deps []database.Dependency, licenses map[string]string, name, ver string) *sbom.SBOM {
	s := sbom.New(sbom.TypeCycloneDX)
	s.Document = sbom.Document{
		Name:      name,
		Namespace: "https://git-pkgs.example.com/" + name,
		Component: sbom.Component{Type: "application", Name: name, Version: ver},
		Creators:  []sbom.Creator{{Type: "Tool", Name: "git-pkgs-" + version}},
	}
	for _, d := range deps {
		purlStr := d.PURL
		if purlStr == "" {
			purlStr = purl.MakePURLString(d.Ecosystem, d.Name, d.Requirement)
		}
		p := sbom.Package{
			Name:    d.Name,
			Version: d.Requirement,
		}
		if purlStr != "" {
			p.ExternalRefs = []sbom.ExternalRef{{
				Category: "PACKAGE_MANAGER", Type: "purl", Locator: purlStr,
			}}
		}
		licKey := purl.MakePURLString(d.Ecosystem, d.Name, "")
		if lic := licenses[licKey]; lic != "" {
			p.LicenseConcluded = lic
			p.LicenseDeclared = lic
		}
		s.AddPackage(p)
	}
	return s
}

func enrichLicenses(db *database.DB, deps []database.Dependency) map[string]string {
	purls := make([]string, 0, len(deps))
	purlToDep := make(map[string]database.Dependency)
	for _, d := range deps {
		purlStr := purl.MakePURLString(d.Ecosystem, d.Name, "")
		if purlStr != "" {
			purls = append(purls, purlStr)
			purlToDep[purlStr] = d
		}
	}
	if len(purls) == 0 {
		return nil
	}
	data, err := getSBOMLicenseData(db, purls, purlToDep)
	if err != nil {
		return nil
	}
	return data
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
