package cmd

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/sbom"
	"github.com/git-pkgs/vers"
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
	sbomCmd.Flags().Bool("skip-enrichment", false, "Skip license and ancestry enrichment from ecosyste.ms")
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

	deps, db, err := repo.GetDependenciesWithDB(commit, branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, ecosystem)
	components := selectSBOMDependencies(deps)
	deps = sbomComponentDependencies(components)

	var enriched sbomEnrichment
	if !skipEnrichment {
		enriched, err = enrichSBOMPackages(db, deps)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: SBOM license enrichment incomplete: %v\n", err)
		}
		if enriched.packageFallbacks > 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"Warning: using package-level license metadata for %d SBOM component(s) without version license metadata\n",
				enriched.packageFallbacks,
			)
		}
		if enriched.ancestryUnavailable {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
				"Warning: database schema predates the repository ancestry cache; run 'git pkgs upgrade' to include pedigree ancestors")
		}
	}

	if projectName == "" {
		projectName = "project"
	}

	projectLicenses, licenseWarnings, err := projectLicensesAtRevision(repo, db, commit, branchName)
	if err != nil {
		return fmt.Errorf("loading project licenses: %w", err)
	}
	for _, warning := range licenseWarnings {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %s\n", warning)
	}

	doc := buildSBOM(
		components,
		enriched.licenses,
		enriched.ancestors,
		projectName,
		projectVersion,
		projectLicenses,
		out != sbom.FormatSPDXJSON,
	)
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
	components []sbomComponent,
	licenses map[string]string,
	ancestors map[string][]sbom.Ancestor,
	name, ver string,
	projectLicenseData projectLicenses,
	includeOccurrenceProperties bool,
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
	for _, component := range components {
		d := component.primary
		purlStr := sbomPURLForDependency(d)
		p := sbom.Package{
			Name:    d.Name,
			Version: d.Requirement,
		}
		if includeOccurrenceProperties {
			for i, occurrence := range component.occurrences {
				prefix := fmt.Sprintf("git-pkgs:occurrence:%d:", i)
				p.Properties = append(p.Properties,
					sbom.Property{Name: prefix + "manifest_path", Value: occurrence.ManifestPath},
					sbom.Property{Name: prefix + "requirement", Value: occurrence.Requirement},
					sbom.Property{Name: prefix + "dependency_type", Value: occurrence.DependencyType},
				)
			}
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
		p.Ancestors = ancestors[purlStr]
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

type sbomComponent struct {
	primary     database.Dependency
	occurrences []database.Dependency
	order       int
}

type sbomResolvedCandidate struct {
	component int
	direct    bool
	directory string
}

func selectSBOMDependencies(deps []database.Dependency) []sbomComponent {
	components := make([]sbomComponent, 0, len(deps))
	componentByKey := make(map[string]int)
	for _, dep := range deps {
		if !isResolvedDependency(dep) {
			continue
		}
		key := sbomDependencyKey(dep)
		if _, ok := componentByKey[key]; ok {
			continue
		}
		componentByKey[key] = len(components)
		components = append(components, sbomComponent{primary: dep, order: len(deps)})
	}

	resolvedByPackage := make(map[string][]sbomResolvedCandidate)
	for _, dep := range deps {
		if !isResolvedDependency(dep) {
			continue
		}
		component, ok := componentByKey[sbomDependencyKey(dep)]
		if !ok {
			continue
		}
		packageKey := sbomDependencyPackageKey(dep)
		resolvedByPackage[packageKey] = addSBOMResolvedCandidate(
			resolvedByPackage[packageKey],
			component,
			dep.Direct,
			path.Dir(dep.ManifestPath),
		)
	}

	for order, dep := range deps {
		if !isResolvedDependency(dep) {
			matched := matchingSBOMResolvedComponents(
				dep,
				resolvedByPackage[sbomDependencyPackageKey(dep)],
				components,
			)
			if len(matched) == 0 {
				component := ensureSBOMComponent(&components, componentByKey, dep, len(deps))
				appendSBOMOccurrence(&components[component], dep, order)
				continue
			}
			for _, component := range matched {
				appendSBOMOccurrence(&components[component], dep, order)
			}
			continue
		}

		component, ok := componentByKey[sbomDependencyKey(dep)]
		if ok {
			appendSBOMOccurrence(&components[component], dep, order)
		}
	}
	sort.SliceStable(components, func(i, j int) bool {
		return components[i].order < components[j].order
	})

	return components
}

func ensureSBOMComponent(
	components *[]sbomComponent,
	componentByKey map[string]int,
	dep database.Dependency,
	defaultOrder int,
) int {
	key := sbomDependencyKey(dep)
	if component, ok := componentByKey[key]; ok {
		return component
	}
	component := len(*components)
	componentByKey[key] = component
	*components = append(*components, sbomComponent{primary: dep, order: defaultOrder})
	return component
}

func appendSBOMOccurrence(component *sbomComponent, dep database.Dependency, order int) {
	component.occurrences = append(component.occurrences, dep)
	if order < component.order {
		component.order = order
	}
}

func sbomComponentDependencies(components []sbomComponent) []database.Dependency {
	deps := make([]database.Dependency, 0, len(components))
	for _, component := range components {
		deps = append(deps, component.primary)
	}
	return deps
}

func addSBOMResolvedCandidate(
	candidates []sbomResolvedCandidate,
	component int,
	direct bool,
	directory string,
) []sbomResolvedCandidate {
	for i := range candidates {
		if candidates[i].component == component && candidates[i].directory == directory {
			candidates[i].direct = candidates[i].direct || direct
			return candidates
		}
	}
	return append(candidates, sbomResolvedCandidate{
		component: component,
		direct:    direct,
		directory: directory,
	})
}

func matchingSBOMResolvedComponents(
	dep database.Dependency,
	candidates []sbomResolvedCandidate,
	components []sbomComponent,
) []int {
	manifestDirectory := path.Clean(path.Dir(dep.ManifestPath))
	candidates = nearestSBOMResolvedCandidates(manifestDirectory, candidates)
	if len(candidates) == 0 {
		return nil
	}

	direct := make([]sbomResolvedCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.direct && path.Clean(candidate.directory) == manifestDirectory {
			direct = append(direct, candidate)
		}
	}
	if len(direct) > 0 {
		candidates = direct
	}

	matching := make([]sbomResolvedCandidate, 0, len(candidates))
	constraintSupported := false
	for _, candidate := range candidates {
		version := components[candidate.component].primary.Requirement
		matches, err := vers.Satisfies(version, dep.Requirement, strings.ToLower(dep.Ecosystem))
		if err != nil {
			continue
		}
		constraintSupported = true
		if matches {
			matching = append(matching, candidate)
		}
	}
	if constraintSupported {
		if len(matching) == 0 {
			return nil
		}
		candidates = matching
	}

	result := make([]int, 0, len(candidates))
	seen := make(map[int]bool)
	for _, candidate := range candidates {
		if seen[candidate.component] {
			continue
		}
		seen[candidate.component] = true
		result = append(result, candidate.component)
	}
	return result
}

func nearestSBOMResolvedCandidates(
	manifestDirectory string,
	candidates []sbomResolvedCandidate,
) []sbomResolvedCandidate {
	nearestDepth := -1
	nearest := make([]sbomResolvedCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !sbomDirectoryContains(candidate.directory, manifestDirectory) {
			continue
		}
		depth := sbomDirectoryDepth(candidate.directory)
		switch {
		case depth > nearestDepth:
			nearestDepth = depth
			nearest = append(nearest[:0], candidate)
		case depth == nearestDepth:
			nearest = append(nearest, candidate)
		}
	}
	return nearest
}

func sbomDirectoryContains(parent, child string) bool {
	parent = path.Clean(parent)
	child = path.Clean(child)
	return parent == "." || parent == child || strings.HasPrefix(child, parent+"/")
}

func sbomDirectoryDepth(directory string) int {
	directory = path.Clean(directory)
	if directory == "." {
		return 0
	}
	return strings.Count(directory, "/") + 1
}

func sbomDependencyKey(dep database.Dependency) string {
	if purlStr := sbomPURLForDependency(dep); purlStr != "" {
		return "purl\x00" + purlStr
	}
	return "dependency\x00" + strings.ToLower(dep.Ecosystem) + "\x00" +
		strings.ToLower(dep.Name) + "\x00" + dep.Requirement
}

func sbomDependencyPackageKey(dep database.Dependency) string {
	return strings.ToLower(dep.Ecosystem) + "\x00" + strings.ToLower(dep.Name)
}

// sbomEnrichment holds enrichment results keyed by component PURL.
type sbomEnrichment struct {
	licenses            map[string]string
	ancestors           map[string][]sbom.Ancestor
	packageFallbacks    int
	ancestryUnavailable bool
}

// sbomPackageData is the package-level enrichment for one package PURL.
type sbomPackageData struct {
	license string
	parent  *database.RepositoryParent
}

func enrichSBOMPackages(db *database.DB, deps []database.Dependency) (sbomEnrichment, error) {
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
		return sbomEnrichment{}, nil
	}

	packageData, ancestryCached, packageErr := getSBOMPackageData(db, purls, purlToDep)
	packageLicenses := make(map[string]string, len(packageData))
	for purlStr, data := range packageData {
		packageLicenses[purlStr] = data.license
	}
	resolved := make([]database.Dependency, 0, len(deps))
	for _, dep := range deps {
		if isResolvedDependency(dep) {
			resolved = append(resolved, dep)
		}
	}
	versionLicenses, versionErr := loadLicenseVersionLicenses(db, resolved, false)

	licenses, packageFallbacks := selectSBOMLicenses(deps, packageLicenses, versionLicenses)
	return sbomEnrichment{
		licenses:            licenses,
		ancestors:           selectSBOMAncestors(deps, packageData),
		packageFallbacks:    packageFallbacks,
		ancestryUnavailable: packageErr == nil && !ancestryCached,
	}, errors.Join(packageErr, versionErr)
}

func selectSBOMAncestors(deps []database.Dependency, packageData map[string]sbomPackageData) map[string][]sbom.Ancestor {
	ancestors := make(map[string][]sbom.Ancestor)
	for _, dep := range deps {
		componentPURL := sbomPURLForDependency(dep)
		if componentPURL == "" {
			continue
		}
		if ancestor, ok := repositoryAncestor(packageData[licensePackagePURLForDependency(dep)].parent); ok {
			ancestors[componentPURL] = []sbom.Ancestor{ancestor}
		}
	}
	return ancestors
}

// repositoryAncestorPURLTypes are the PURL types that identify a repository on
// its public host.
var repositoryAncestorPURLTypes = map[string]bool{"github": true, "bitbucket": true}

// repositoryAncestor converts a declared fork parent into an unversioned
// repository ancestor. Hosts without a PURL type, such as self-hosted
// instances, yield no ancestor.
func repositoryAncestor(parent *database.RepositoryParent) (sbom.Ancestor, bool) {
	if parent == nil || parent.Evidence != enrichment.AncestryDeclaredFork ||
		!repositoryAncestorPURLTypes[parent.HostKind] ||
		strings.TrimSuffix(parent.HostURL, "/") != purl.DefaultRegistry(parent.HostKind) {
		return sbom.Ancestor{}, false
	}
	owner, name, ok := strings.Cut(parent.FullName, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return sbom.Ancestor{}, false
	}
	return sbom.Ancestor{
		Name: parent.FullName,
		PURL: purl.New(parent.HostKind, owner, name, "", nil).String(),
	}, true
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

// getSBOMPackageData returns package-level enrichment keyed by package PURL.
// When the database cannot cache repository parents, it returns no parents and
// reports ancestryCached as false.
func getSBOMPackageData(
	db *database.DB,
	purls []string,
	purlToDep map[string]database.Dependency,
) (map[string]sbomPackageData, bool, error) {
	result := make(map[string]sbomPackageData)
	ancestryCached := true
	uncachedPurls := purls

	if db != nil {
		cached, err := db.GetCachedPackages(purls, enrichmentCacheTTL)
		if err != nil {
			return nil, false, err
		}
		ancestryCached, err = db.HasRepositoryParentCache()
		if err != nil {
			return nil, false, err
		}
		var cachedParents map[string]*database.CachedRepositoryParent
		if ancestryCached {
			cachedParents, err = db.GetCachedRepositoryParents(purls, enrichmentCacheTTL)
			if err != nil {
				return nil, false, err
			}
		}
		uncachedPurls = nil
		for _, purlStr := range purls {
			cachedPackage, ok := cached[purlStr]
			cachedParent, parentOK := cachedParents[purlStr]
			if !ok || (ancestryCached && !parentOK) {
				uncachedPurls = append(uncachedPurls, purlStr)
				continue
			}
			data := sbomPackageData{license: cachedPackage.License}
			if cachedParent != nil {
				data.parent = cachedParent.Parent
			}
			result[purlStr] = data
		}
	}

	if len(uncachedPurls) == 0 {
		return result, ancestryCached, nil
	}

	client, err := newEnrichmentClient()
	if err != nil {
		return nil, ancestryCached, err
	}

	const sbomTimeout = 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), sbomTimeout)
	defer cancel()

	packages, err := client.BulkLookup(ctx, uncachedPurls)
	if err != nil {
		return nil, ancestryCached, wrapEcosystemsError(err)
	}

	var parentsToSave []database.PackageRepositoryParentData
	for purlStr, pkg := range packages {
		var data sbomPackageData
		if pkg != nil {
			data.license = pkg.License
			if ancestryCached {
				data.parent = databaseRepositoryParent(pkg.RepositoryParent)
			}
		}
		result[purlStr] = data

		if db != nil && pkg != nil {
			dep := purlToDep[purlStr]
			_ = db.SavePackageEnrichment(purlStr, dep.Ecosystem, dep.Name, pkg.LatestVersion, pkg.License, pkg.RegistryURL, pkg.Source)
			if ancestryCached {
				parentsToSave = append(parentsToSave, database.PackageRepositoryParentData{
					PURL: purlStr, Ecosystem: dep.Ecosystem, Name: dep.Name, Parent: data.parent,
				})
			}
		}
	}
	if db != nil {
		_ = db.SavePackageRepositoryParentBatch(parentsToSave)
	}

	return result, ancestryCached, nil
}

func databaseRepositoryParent(parent *enrichment.RepositoryParent) *database.RepositoryParent {
	if parent == nil {
		return nil
	}
	return &database.RepositoryParent{
		FullName: parent.FullName,
		Evidence: parent.Evidence,
		HostName: parent.HostName,
		HostKind: parent.HostKind,
		HostURL:  parent.HostURL,
	}
}
