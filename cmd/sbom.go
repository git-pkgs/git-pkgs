package cmd

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
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
	sbomCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	sbomCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	sbomCmd.Flags().String("name", "", "Project name (default: git directory name)")
	sbomCmd.Flags().String("version", "", "Project version")
	sbomCmd.Flags().Bool("skip-enrichment", false, "Skip license enrichment from ecosyste.ms")
	sbomCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
	parent.AddCommand(sbomCmd)
}

// CycloneDX BOM structure
type CycloneDXBOM struct {
	XMLName      xml.Name                  `xml:"bom" json:"-"`
	XMLNS        string                    `xml:"xmlns,attr" json:"-"`
	Version      int                       `xml:"version,attr" json:"version"`
	BOMFormat    string                    `xml:"-" json:"bomFormat"`
	SpecVersion  string                    `xml:"-" json:"specVersion"`
	SerialNumber string                    `xml:"serialNumber,attr,omitempty" json:"serialNumber,omitempty"`
	Metadata     *CycloneDXMetadata        `xml:"metadata,omitempty" json:"metadata,omitempty"`
	Components   []CycloneDXComponent      `xml:"components>component" json:"components"`
	Dependencies []CycloneDXDependency     `xml:"dependencies>dependency,omitempty" json:"dependencies,omitempty"`
}

type CycloneDXMetadata struct {
	Timestamp string              `xml:"timestamp" json:"timestamp"`
	Tools     []CycloneDXTool     `xml:"tools>tool,omitempty" json:"tools,omitempty"`
	Component *CycloneDXComponent `xml:"component,omitempty" json:"component,omitempty"`
}

type CycloneDXTool struct {
	Vendor  string `xml:"vendor" json:"vendor"`
	Name    string `xml:"name" json:"name"`
	Version string `xml:"version" json:"version"`
}

type CycloneDXComponent struct {
	Type        string             `xml:"type,attr" json:"type"`
	BOMRef      string             `xml:"bom-ref,attr,omitempty" json:"bom-ref,omitempty"`
	Name        string             `xml:"name" json:"name"`
	Version     string             `xml:"version,omitempty" json:"version,omitempty"`
	PURL        string             `xml:"purl,omitempty" json:"purl,omitempty"`
	Licenses    []CycloneDXLicense `xml:"licenses>license,omitempty" json:"licenses,omitempty"`
	Description string             `xml:"description,omitempty" json:"description,omitempty"`
}

type CycloneDXLicense struct {
	ID   string `xml:"id,omitempty" json:"id,omitempty"`
	Name string `xml:"name,omitempty" json:"name,omitempty"`
}

type CycloneDXDependency struct {
	Ref       string   `xml:"ref,attr" json:"ref"`
	DependsOn []string `xml:"dependency,omitempty" json:"dependsOn,omitempty"`
}

// SPDX structure
type SPDXSBOM struct {
	SPDXVersion       string            `json:"spdxVersion"`
	DataLicense       string            `json:"dataLicense"`
	SPDXID            string            `json:"SPDXID"`
	Name              string            `json:"name"`
	DocumentNamespace string            `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo  `json:"creationInfo"`
	Packages          []SPDXPackage     `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships,omitempty"`
}

type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
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
	stateless, _ := cmd.Flags().GetBool("stateless")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var deps []database.Dependency
	var db *database.DB

	if stateless {
		deps, err = listStateless(repo, commit)
		if err != nil {
			return err
		}
	} else {
		dbPath := repo.DatabasePath()
		if !database.Exists(dbPath) {
			return fmt.Errorf("database not found. Run 'git pkgs init' first")
		}

		db, err = database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer func() { _ = db.Close() }()

		var branch *database.BranchInfo
		if branchName != "" {
			branch, err = db.GetBranch(branchName)
			if err != nil {
				return fmt.Errorf("branch %q not found: %w", branchName, err)
			}
		} else {
			branch, err = db.GetDefaultBranch()
			if err != nil {
				return fmt.Errorf("getting branch: %w", err)
			}
		}

		if commit != "" {
			deps, err = db.GetDependenciesAtRef(commit, branch.ID)
		} else {
			deps, err = db.GetLatestDependencies(branch.ID)
		}
		if err != nil {
			return fmt.Errorf("getting dependencies: %w", err)
		}
	}

	if ecosystem != "" {
		var filtered []database.Dependency
		for _, d := range deps {
			if d.Ecosystem == ecosystem {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	// Get licenses from cache or ecosyste.ms if not skipped
	licenseMap := make(map[string][]string)
	if !skipEnrichment {
		purls := make([]string, 0, len(deps))
		purlToDep := make(map[string]database.Dependency)
		for _, d := range deps {
			purlStr := d.PURL
			if purlStr == "" {
				purlStr = purl.MakePURLString(d.Ecosystem, d.Name, "")
			}
			if purlStr != "" {
				purls = append(purls, purlStr)
				purlToDep[purlStr] = d
			}
		}

		if len(purls) > 0 {
			data, err := getSBOMLicenseData(db, purls, purlToDep)
			if err == nil {
				for purl, license := range data {
					if license != "" {
						licenseMap[purl] = []string{license}
					}
				}
			}
		}
	}

	if projectName == "" {
		projectName = "project"
	}

	switch sbomType {
	case "spdx":
		return generateSPDX(cmd, deps, licenseMap, projectName, projectVersion, format)
	default:
		return generateCycloneDX(cmd, deps, licenseMap, projectName, projectVersion, format)
	}
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
		client, err := enrichment.NewClient()
		if err != nil {
			return nil, err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		packages, err := client.BulkLookup(ctx, uncachedPurls)
		if err != nil {
			return nil, err
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

func generateCycloneDX(cmd *cobra.Command, deps []database.Dependency, licenseMap map[string][]string, name, version, format string) error {
	bom := CycloneDXBOM{
		XMLNS:       "http://cyclonedx.org/schema/bom/1.5",
		Version:     1,
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Metadata: &CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "git-pkgs", Name: "git-pkgs", Version: "1.0.0"},
			},
		},
	}

	if name != "" {
		bom.Metadata.Component = &CycloneDXComponent{
			Type:    "application",
			Name:    name,
			Version: version,
		}
	}

	for _, dep := range deps {
		purlStr := dep.PURL
		if purlStr == "" {
			purlStr = purl.MakePURLString(dep.Ecosystem, dep.Name, "")
		}

		comp := CycloneDXComponent{
			Type:    "library",
			BOMRef:  purlStr,
			Name:    dep.Name,
			Version: dep.Requirement,
			PURL:    purlStr,
		}

		if licenses, ok := licenseMap[purlStr]; ok {
			for _, lic := range licenses {
				comp.Licenses = append(comp.Licenses, CycloneDXLicense{ID: lic})
			}
		}

		bom.Components = append(bom.Components, comp)
	}

	if format == "xml" {
		enc := xml.NewEncoder(cmd.OutOrStdout())
		enc.Indent("", "  ")
		_, _ = fmt.Fprint(cmd.OutOrStdout(), xml.Header)
		return enc.Encode(bom)
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func generateSPDX(cmd *cobra.Command, deps []database.Dependency, licenseMap map[string][]string, name, version, format string) error {
	sbom := SPDXSBOM{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: fmt.Sprintf("https://git-pkgs.example.com/%s", name),
		CreationInfo: SPDXCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: git-pkgs-1.0.0"},
		},
	}

	// Add root package
	rootPkg := SPDXPackage{
		SPDXID:           "SPDXRef-Package-root",
		Name:             name,
		VersionInfo:      version,
		DownloadLocation: "NOASSERTION",
	}
	sbom.Packages = append(sbom.Packages, rootPkg)

	for i, dep := range deps {
		purlStr := dep.PURL
		if purlStr == "" {
			purlStr = purl.MakePURLString(dep.Ecosystem, dep.Name, "")
		}

		pkg := SPDXPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i),
			Name:             dep.Name,
			VersionInfo:      dep.Requirement,
			DownloadLocation: "NOASSERTION",
		}

		if licenses, ok := licenseMap[purlStr]; ok && len(licenses) > 0 {
			pkg.LicenseConcluded = licenses[0]
			pkg.LicenseDeclared = licenses[0]
		} else {
			pkg.LicenseConcluded = "NOASSERTION"
			pkg.LicenseDeclared = "NOASSERTION"
		}

		if purlStr != "" {
			pkg.ExternalRefs = []SPDXExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  purlStr,
				},
			}
		}

		sbom.Packages = append(sbom.Packages, pkg)

		// Add dependency relationship
		sbom.Relationships = append(sbom.Relationships, SPDXRelationship{
			SPDXElementID:      "SPDXRef-Package-root",
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: pkg.SPDXID,
		})
	}

	if format == "xml" {
		return fmt.Errorf("SPDX XML format not supported, use json")
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(sbom)
}
