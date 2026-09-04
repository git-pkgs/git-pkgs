package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	licensespkg "github.com/git-pkgs/licenses"
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
	licensesCmd.Flags().Bool("offline", false, "Use cached metadata without making network requests")
	licensesCmd.Flags().Bool("license-text", false, "Include license and notice text from package artifacts in JSON output")
	licensesCmd.Flags().String("dependencies", licenseDependenciesDirect, "Dependencies to include: direct, indirect, all")
	parent.AddCommand(licensesCmd)
}

type LicenseInfo struct {
	Name          string                       `json:"name"`
	Ecosystem     string                       `json:"ecosystem"`
	Version       string                       `json:"version,omitempty"`
	Licenses      []string                     `json:"licenses"`
	LicenseText   string                       `json:"license_text,omitempty"`
	NoticeText    string                       `json:"notice_text,omitempty"`
	Declared      []licensespkg.DeclaredRecord `json:"declared,omitempty"`
	ManifestPath  string                       `json:"manifest_path"`
	PURL          string                       `json:"purl,omitempty"`
	LicenseSource string                       `json:"license_source,omitempty"`
	Flagged       bool                         `json:"flagged,omitempty"`
	FlagReason    string                       `json:"flag_reason,omitempty"`
}

const (
	licenseSourcePackage = "package"
	licenseSourceScan    = "scan"
	licenseSourceVersion = "version"

	licenseDependenciesDirect   = "direct"
	licenseDependenciesIndirect = "indirect"
	licenseDependenciesAll      = "all"
)

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

type licenseOptions struct {
	commit         string
	branchName     string
	ecosystem      string
	format         string
	allowList      []string
	denyList       []string
	flagPermissive bool
	flagCopyleft   bool
	flagUnknown    bool
	groupBy        bool
	driftOnly      bool
	offline        bool
	includeText    bool
	dependencies   string
}

func runLicenses(cmd *cobra.Command, args []string) error {
	opts, err := licenseOptionsFromCommand(cmd)
	if err != nil {
		return err
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	deps, db, err := repo.GetDependenciesWithDB(opts.commit, opts.branchName)
	if db != nil {
		defer func() { _ = db.Close() }()
	}
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, opts.ecosystem)

	if opts.driftOnly {
		return runLicenseDrift(cmd, db, deps, opts.format, opts.offline)
	}

	targets := selectLicenseTargets(deps, opts.dependencies)
	if len(targets) == 0 {
		if opts.format == formatJSON {
			return outputLicensesJSON(cmd, nil)
		}
		scope := opts.dependencies + " "
		if opts.dependencies == licenseDependenciesAll {
			scope = ""
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No %sdependencies found.\n", scope)
		return nil
	}
	if opts.includeText {
		warnUnresolvedLicenseTextTargets(cmd, targets)
	}

	purls := licenseTargetPackagePURLs(targets)
	packageData, err := getLicenseData(db, purls, opts.offline)
	if err != nil {
		return fmt.Errorf("looking up packages: %w", err)
	}
	resolvedDeps := resolvedLicenseTargetDependencies(targets)
	versionLicenses, versionLicenseErr := loadLicenseVersionLicenses(db, resolvedDeps, opts.offline)
	if versionLicenseErr != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: version license lookup failed; using package metadata where version data is unavailable: %v\n",
			versionLicenseErr,
		)
	}

	var licenseScans map[string]licenseScanResult
	if opts.includeText {
		artifactLoader, err := newLicenseArtifactLoader()
		if err != nil {
			return fmt.Errorf("preparing package artifact cache: %w", err)
		}
		defer func() { _ = artifactLoader.Close() }()
		licenseScans, err = scanDependencyArtifacts(
			cmd.Context(),
			resolvedDeps,
			artifactLoader,
			opts.offline,
		)
		if err != nil {
			return err
		}
	}

	result := buildLicenseInfos(
		packageData,
		targets,
		versionLicenses,
		licenseScans,
		newLicensePolicy(opts),
	)
	warnAmbiguousLicenseFallbacks(cmd, result.ambiguousFallbacks)

	if err := outputLicenses(cmd, result.infos, opts.format, opts.groupBy); err != nil {
		return err
	}
	if result.hasViolations {
		return fmt.Errorf("license violations found")
	}
	return nil
}

func licenseOptionsFromCommand(cmd *cobra.Command) (licenseOptions, error) {
	opts := licenseOptions{}
	opts.commit, _ = cmd.Flags().GetString("commit")
	opts.branchName, _ = cmd.Flags().GetString("branch")
	opts.ecosystem, _ = cmd.Flags().GetString("ecosystem")
	opts.allowList, _ = cmd.Flags().GetStringSlice("allow")
	opts.denyList, _ = cmd.Flags().GetStringSlice("deny")
	opts.flagPermissive, _ = cmd.Flags().GetBool("permissive")
	opts.flagCopyleft, _ = cmd.Flags().GetBool("copyleft")
	opts.flagUnknown, _ = cmd.Flags().GetBool("unknown")
	opts.groupBy, _ = cmd.Flags().GetBool("group")
	opts.driftOnly, _ = cmd.Flags().GetBool("drift")
	opts.offline, _ = cmd.Flags().GetBool("offline")
	opts.includeText, _ = cmd.Flags().GetBool("license-text")
	opts.dependencies, _ = cmd.Flags().GetString("dependencies")
	opts.dependencies = strings.ToLower(strings.TrimSpace(opts.dependencies))

	format, err := getFormatFlag(cmd, formatText, formatJSON, formatCSV)
	if err != nil {
		return licenseOptions{}, err
	}
	opts.format = format
	if opts.includeText && opts.format != formatJSON {
		return licenseOptions{}, fmt.Errorf("--license-text requires --format json")
	}
	if !slices.Contains([]string{
		licenseDependenciesDirect,
		licenseDependenciesIndirect,
		licenseDependenciesAll,
	}, opts.dependencies) {
		return licenseOptions{}, fmt.Errorf(
			"unsupported dependency selection %q; supported values: direct, indirect, all",
			opts.dependencies,
		)
	}
	if opts.driftOnly {
		if cmd.Flags().Changed("dependencies") {
			return licenseOptions{}, fmt.Errorf("--drift cannot be combined with --dependencies")
		}
		err = validateLicenseDriftFlags(
			opts.allowList,
			opts.denyList,
			opts.flagPermissive,
			opts.flagCopyleft,
			opts.flagUnknown,
			opts.groupBy,
			opts.includeText,
		)
	}
	return opts, err
}

func directLicenseDependencies(deps []database.Dependency) []database.Dependency {
	direct := make([]database.Dependency, 0, len(deps))
	for _, dep := range deps {
		if dep.ManifestKind == manifestKindManifest && (!isResolvedDependency(dep) || dep.Direct) {
			direct = append(direct, dep)
		}
	}
	return direct
}

type licenseTarget struct {
	lookupPURL    string
	dependency    database.Dependency
	resolved      database.Dependency
	versionedPURL string
	ambiguous     bool
}

func selectLicenseTargets(deps []database.Dependency, selection string) []licenseTarget {
	direct, directInstances := directLicenseTargets(deps)
	indirect := indirectLicenseTargets(deps, directInstances)

	var targets []licenseTarget
	switch selection {
	case licenseDependenciesIndirect:
		targets = indirect
	case licenseDependenciesAll:
		targets = append(targets, direct...)
		targets = append(targets, indirect...)
	default:
		targets = direct
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].dependency.Name != targets[j].dependency.Name {
			return targets[i].dependency.Name < targets[j].dependency.Name
		}
		if targets[i].versionedPURL != targets[j].versionedPURL {
			return targets[i].versionedPURL < targets[j].versionedPURL
		}
		return targets[i].dependency.ManifestPath < targets[j].dependency.ManifestPath
	})
	return targets
}

func directLicenseTargets(deps []database.Dependency) ([]licenseTarget, map[string]bool) {
	candidatesByLocation := resolvedLicenseCandidatesByLocation(deps)
	targets := make([]licenseTarget, 0)
	directInstances := make(map[string]bool)
	seenTargets := make(map[string]bool)

	for _, dependency := range directLicenseDependencies(deps) {
		target := licenseTargetForDirectDependency(dependency, candidatesByLocation)
		key := target.lookupPURL + "\x00" + dependency.ManifestPath
		if target.lookupPURL == "" || seenTargets[key] {
			continue
		}
		seenTargets[key] = true
		targets = append(targets, target)
		if target.versionedPURL != "" {
			directInstances[licenseResolvedInstanceKey(target.resolved)] = true
		}
	}

	for _, dependency := range deps {
		if !dependency.Direct || !isResolvedDependency(dependency) {
			continue
		}
		versionedPURL := versionedPURLForDependency(dependency)
		instanceKey := licenseResolvedInstanceKey(dependency)
		if versionedPURL == "" || directInstances[instanceKey] {
			continue
		}
		lookupPURL := licensePackagePURLForDependency(dependency)
		key := lookupPURL + "\x00" + dependency.ManifestPath
		if lookupPURL == "" || seenTargets[key] {
			continue
		}
		seenTargets[key] = true
		directInstances[instanceKey] = true
		targets = append(targets, licenseTarget{
			lookupPURL:    lookupPURL,
			dependency:    dependency,
			resolved:      dependency,
			versionedPURL: versionedPURL,
		})
	}

	return targets, directInstances
}

func licenseTargetForDirectDependency(
	dependency database.Dependency,
	candidatesByLocation map[string]map[string]database.Dependency,
) licenseTarget {
	target := licenseTarget{
		lookupPURL: licensePackagePURLForDependency(dependency),
		dependency: dependency,
	}
	if isResolvedDependency(dependency) {
		target.resolved = dependency
		target.versionedPURL = versionedPURLForDependency(dependency)
		return target
	}

	versionedPURL, resolved, ambiguous := resolvedLicenseCandidate(
		candidatesByLocation[licenseDependencyLocation(dependency)],
	)
	target.resolved = resolved
	target.versionedPURL = versionedPURL
	target.ambiguous = ambiguous
	return target
}

func indirectLicenseTargets(deps []database.Dependency, directInstances map[string]bool) []licenseTarget {
	targets := make([]licenseTarget, 0)
	seen := make(map[string]bool)
	for _, dependency := range deps {
		if !isResolvedDependency(dependency) || dependency.Direct ||
			directInstances[licenseResolvedInstanceKey(dependency)] {
			continue
		}
		versionedPURL := versionedPURLForDependency(dependency)
		lookupPURL := licensePackagePURLForDependency(dependency)
		key := versionedPURL + "\x00" + dependency.ManifestPath
		if versionedPURL == "" || lookupPURL == "" || seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, licenseTarget{
			lookupPURL:    lookupPURL,
			dependency:    dependency,
			resolved:      dependency,
			versionedPURL: versionedPURL,
		})
	}
	return targets
}

func resolvedLicenseCandidatesByLocation(
	deps []database.Dependency,
) map[string]map[string]database.Dependency {
	candidatesByLocation := make(map[string]map[string]database.Dependency)
	for _, dependency := range deps {
		if !isResolvedDependency(dependency) {
			continue
		}
		versionedPURL := versionedPURLForDependency(dependency)
		if versionedPURL == "" {
			continue
		}
		location := licenseDependencyLocation(dependency)
		if candidatesByLocation[location] == nil {
			candidatesByLocation[location] = make(map[string]database.Dependency)
		}
		existing, ok := candidatesByLocation[location][versionedPURL]
		if !ok || (dependency.Direct && !existing.Direct) {
			candidatesByLocation[location][versionedPURL] = dependency
		}
	}
	return candidatesByLocation
}

func licenseResolvedInstanceKey(dependency database.Dependency) string {
	return versionedPURLForDependency(dependency) + "\x00" + path.Dir(dependency.ManifestPath)
}

func licenseTargetPackagePURLs(targets []licenseTarget) []string {
	seen := make(map[string]bool)
	purls := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.lookupPURL == "" || seen[target.lookupPURL] {
			continue
		}
		seen[target.lookupPURL] = true
		purls = append(purls, target.lookupPURL)
	}
	sort.Strings(purls)
	return purls
}

func resolvedLicenseTargetDependencies(targets []licenseTarget) []database.Dependency {
	dependencies := make([]database.Dependency, 0, len(targets))
	for _, target := range targets {
		if target.versionedPURL != "" {
			dependencies = append(dependencies, target.resolved)
		}
	}
	return dependencies
}

func warnUnresolvedLicenseTextTargets(cmd *cobra.Command, targets []licenseTarget) {
	skippedByManifest := make(map[string][]string)
	for _, target := range targets {
		if target.versionedPURL != "" {
			continue
		}
		if !hasArtifactRegistry(target.dependency.Ecosystem) {
			continue
		}
		manifest := target.dependency.ManifestPath
		skippedByManifest[manifest] = append(skippedByManifest[manifest], target.dependency.Name)
	}
	manifests := make([]string, 0, len(skippedByManifest))
	for manifest := range skippedByManifest {
		manifests = append(manifests, manifest)
	}
	sort.Strings(manifests)
	for _, manifest := range manifests {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
			"Warning: --license-text skipped %s from %s: no resolved version (add a lockfile)\n",
			strings.Join(skippedByManifest[manifest], ", "),
			manifest,
		)
	}
}

type licensePolicy struct {
	allowSet       map[string]bool
	denySet        map[string]bool
	flagPermissive bool
	flagCopyleft   bool
	flagUnknown    bool
}

func newLicensePolicy(opts licenseOptions) licensePolicy {
	return licensePolicy{
		allowSet:       normalizedLicenseSet(opts.allowList),
		denySet:        normalizedLicenseSet(opts.denyList),
		flagPermissive: opts.flagPermissive,
		flagCopyleft:   opts.flagCopyleft,
		flagUnknown:    opts.flagUnknown,
	}
}

func normalizedLicenseSet(licenses []string) map[string]bool {
	set := make(map[string]bool, len(licenses))
	for _, license := range licenses {
		normalized, err := spdx.Normalize(license)
		if err == nil {
			set[normalized] = true
			continue
		}
		set[strings.ToLower(license)] = true
	}
	return set
}

func (policy licensePolicy) evaluate(licenses []string) (bool, string) {
	if len(licenses) == 0 {
		if policy.flagUnknown {
			return true, "unknown license"
		}
		return false, ""
	}

	flagged := false
	reason := ""
	for _, license := range licenses {
		if len(policy.allowSet) > 0 && !licenseSetContains(policy.allowSet, license) {
			flagged = true
			reason = fmt.Sprintf("license %q not in allow list", license)
		}
		if licenseSetContains(policy.denySet, license) {
			flagged = true
			reason = fmt.Sprintf("license %q is denied", license)
		}
		if policy.flagPermissive && !spdx.IsFullyPermissive(license) {
			flagged = true
			reason = fmt.Sprintf("license %q is not permissive", license)
		}
		if policy.flagCopyleft && spdx.HasCopyleft(license) {
			flagged = true
			reason = fmt.Sprintf("license %q is copyleft", license)
		}
	}
	return flagged, reason
}

func licenseSetContains(set map[string]bool, license string) bool {
	if set[license] {
		return true
	}
	if normalized, err := spdx.Normalize(license); err == nil && set[normalized] {
		return true
	}
	return set[strings.ToLower(license)]
}

type licenseBuildResult struct {
	infos              []LicenseInfo
	ambiguousFallbacks []string
	hasViolations      bool
}

func buildLicenseInfos(
	packageData map[string]*licenseData,
	targets []licenseTarget,
	versionLicenses map[string]string,
	licenseScans map[string]licenseScanResult,
	policy licensePolicy,
) licenseBuildResult {
	result := licenseBuildResult{infos: make([]LicenseInfo, 0, len(targets))}
	for _, target := range targets {
		data := packageData[target.lookupPURL]
		if data == nil {
			data = &licenseData{}
		}
		info, ambiguousFallback := buildLicenseInfo(
			target.lookupPURL,
			data,
			target.dependency,
			target.versionedPURL,
			versionLicenses,
			target.ambiguous,
		)
		if ambiguousFallback {
			result.ambiguousFallbacks = append(result.ambiguousFallbacks, target.lookupPURL)
		}
		if licenseScans != nil {
			if scan, ok := licenseScans[target.versionedPURL]; ok {
				applyVersionedLicenseIdentity(&info, target.versionedPURL)
				applyLicenseScan(&info, scan)
			}
		}
		info.Flagged, info.FlagReason = policy.evaluate(info.Licenses)
		if info.Flagged {
			result.hasViolations = true
		}
		if len(info.Licenses) == 0 {
			info.Licenses = []string{"Unknown"}
		}
		result.infos = append(result.infos, info)
	}
	return result
}

type licenseScanResult struct {
	licenses    []string
	licenseText string
	noticeText  string
	declared    []licensespkg.DeclaredRecord
}

func scanDependencyLicense(
	ctx context.Context,
	matcher *licensespkg.Matcher,
	packageRoot string,
) (licenseScanResult, error) {
	options := licensespkg.DefaultScanOptions()
	options.IncludeLegalFiles = true
	report, err := licensespkg.ScanRepository(ctx, matcher, packageRoot, options)
	if err != nil {
		return licenseScanResult{}, err
	}
	if report.Summary.Truncated {
		return licenseScanResult{}, fmt.Errorf("scan reached its file limit")
	}
	if len(report.Errors) != 0 {
		return licenseScanResult{}, fmt.Errorf("%s: %s", report.Errors[0].Path, report.Errors[0].Error)
	}
	for _, skipped := range report.Skipped {
		if len(licensespkg.LegalFileRoles(skipped.Path)) != 0 {
			return licenseScanResult{}, fmt.Errorf("legal file %s was skipped: %s", skipped.Path, skipped.Reason)
		}
	}

	result := licenseScanResult{
		declared: append([]licensespkg.DeclaredRecord(nil), report.Declared...),
	}
	for _, expression := range report.Expressions {
		if expression.Root {
			result.licenses = append(result.licenses, expression.Expression)
		}
	}
	for _, file := range report.Files {
		if file.Text == "" {
			continue
		}
		for _, role := range file.Roles {
			switch role {
			case "license":
				result.licenseText = appendLegalText(result.licenseText, file.Text)
			case "notice":
				result.noticeText = appendLegalText(result.noticeText, file.Text)
			}
		}
	}
	return result, nil
}

func appendLegalText(existing, text string) string {
	if existing == "" {
		return text
	}
	return existing + "\n" + text
}

func mergeLicenseScanResult(result *licenseScanResult, addition licenseScanResult) {
	for _, license := range addition.licenses {
		if !slices.Contains(result.licenses, license) {
			result.licenses = append(result.licenses, license)
		}
	}
	if addition.licenseText != "" {
		result.licenseText = appendLegalText(result.licenseText, addition.licenseText)
	}
	if addition.noticeText != "" {
		result.noticeText = appendLegalText(result.noticeText, addition.noticeText)
	}
	result.declared = append(result.declared, addition.declared...)
}

func applyLicenseScan(info *LicenseInfo, scan licenseScanResult) {
	info.LicenseText = scan.licenseText
	info.NoticeText = scan.noticeText
	info.Declared = scan.declared
	if len(scan.licenses) != 0 {
		info.Licenses = append([]string(nil), scan.licenses...)
		info.LicenseSource = licenseSourceScan
	}
}

func buildLicenseInfo(
	lookupPURL string,
	data *licenseData,
	dep database.Dependency,
	versionedPURL string,
	versionLicenses map[string]string,
	ambiguousVersion bool,
) (LicenseInfo, bool) {
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
		PURL:         lookupPURL,
	}
	license := data.License
	if versionLicense := versionLicenses[versionedPURL]; versionLicense != "" {
		license = versionLicense
		info.LicenseSource = licenseSourceVersion
		applyVersionedLicenseIdentity(&info, versionedPURL)
	} else if license != "" {
		info.LicenseSource = licenseSourcePackage
	}
	if license != "" {
		info.Licenses = []string{license}
	}
	return info, license != "" && info.LicenseSource == licenseSourcePackage && ambiguousVersion
}

func applyVersionedLicenseIdentity(info *LicenseInfo, versionedPURL string) {
	if versionedPURL == "" {
		return
	}
	info.PURL = versionedPURL
	if parsed, err := purl.Parse(versionedPURL); err == nil {
		info.Version = parsed.Version
	}
}

func warnAmbiguousLicenseFallbacks(cmd *cobra.Command, fallbacks []string) {
	if len(fallbacks) == 0 {
		return
	}
	sort.Strings(fallbacks)
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"Warning: could not determine installed versions for %d dependencies; using package-level license metadata: %s\n",
		len(fallbacks), strings.Join(fallbacks, ", "),
	)
}

func outputLicenses(cmd *cobra.Command, infos []LicenseInfo, format string, groupBy bool) error {
	switch format {
	case formatJSON:
		return outputLicensesJSON(cmd, infos)
	case formatCSV:
		return outputLicensesCSV(cmd, infos)
	default:
		if groupBy {
			outputLicensesGrouped(cmd, infos)
		} else {
			outputLicensesText(cmd, infos)
		}
		return nil
	}
}

func validateLicenseDriftFlags(
	allowList, denyList []string,
	flagPermissive, flagCopyleft, flagUnknown, groupBy, includeText bool,
) error {
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
	if includeText {
		incompatible = append(incompatible, "--license-text")
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

func getLicenseData(
	db *database.DB,
	purls []string,
	offline bool,
) (map[string]*licenseData, error) {
	result, uncachedPURLs, err := cachedLicenseData(db, purls, offline)
	if err != nil {
		return nil, err
	}
	if offline && len(uncachedPURLs) > 0 {
		return nil, fmt.Errorf(
			"offline mode: license metadata is not cached for %d package(s); run 'git pkgs licenses' without --offline to populate the cache",
			len(uncachedPURLs),
		)
	}
	if len(uncachedPURLs) == 0 {
		return result, nil
	}

	fetched, err := fetchLicenseData(db, uncachedPURLs)
	if err != nil {
		return nil, err
	}
	for purl, data := range fetched {
		result[purl] = data
	}
	return result, nil
}

func cachedLicenseData(
	db *database.DB,
	purls []string,
	includeStale bool,
) (map[string]*licenseData, []string, error) {
	result := make(map[string]*licenseData)
	if db == nil {
		return result, purls, nil
	}

	var cached map[string]*database.CachedPackage
	var err error
	if includeStale {
		cached, err = db.GetCachedPackagesIncludingStale(purls)
	} else {
		cached, err = db.GetCachedPackages(purls, enrichmentCacheTTL)
	}
	if err != nil {
		return nil, nil, err
	}

	for purl, pkg := range cached {
		result[purl] = &licenseData{
			License:       normalizeLicenseString(pkg.License),
			Name:          pkg.Name,
			Ecosystem:     pkg.Ecosystem,
			LatestVersion: pkg.LatestVersion,
		}
	}
	uncached := make([]string, 0, len(purls)-len(cached))
	for _, purl := range purls {
		if _, ok := cached[purl]; !ok {
			uncached = append(uncached, purl)
		}
	}
	return result, uncached, nil
}

func fetchLicenseData(db *database.DB, purls []string) (map[string]*licenseData, error) {
	client, err := newEnrichmentClient()
	if err != nil {
		return nil, err
	}

	const licensesTimeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), licensesTimeout)
	defer cancel()

	packages, err := client.BulkLookup(ctx, purls)
	if err != nil {
		return nil, wrapEcosystemsError(err)
	}

	result := make(map[string]*licenseData, len(packages))
	for purl, pkg := range packages {
		result[purl] = licenseDataFromPackage(pkg)
		if db != nil && pkg != nil {
			_ = db.SavePackageEnrichment(purl, pkg.Ecosystem, pkg.Name, pkg.LatestVersion, pkg.License, pkg.RegistryURL, pkg.Source)
		}
	}
	return result, nil
}

func licenseDataFromPackage(pkg *enrichment.PackageInfo) *licenseData {
	data := &licenseData{}
	if pkg == nil {
		return data
	}
	data.Name = pkg.Name
	data.Ecosystem = pkg.Ecosystem
	data.LatestVersion = pkg.LatestVersion
	data.License = normalizeLicenseString(pkg.License)
	return data
}

func resolvedLicenseCandidate(candidates map[string]database.Dependency) (string, database.Dependency, bool) {
	if len(candidates) == 1 {
		for versionedPURL, dep := range candidates {
			return versionedPURL, dep, false
		}
	}

	var directPURL string
	var directDep database.Dependency
	directCount := 0
	for versionedPURL, dep := range candidates {
		if !dep.Direct {
			continue
		}
		directPURL = versionedPURL
		directDep = dep
		directCount++
	}
	if directCount == 1 {
		return directPURL, directDep, false
	}
	return "", database.Dependency{}, len(candidates) > 1
}

func licenseDependencyLocation(dep database.Dependency) string {
	return strings.ToLower(dep.Ecosystem) + "\x00" + strings.ToLower(dep.Name) + "\x00" + path.Dir(dep.ManifestPath)
}

func runLicenseDrift(cmd *cobra.Command, db *database.DB, deps []database.Dependency, format string, offline bool) error {
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

	result, err := computeLicenseDrift(db, resolved, offline)
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

func computeLicenseDrift(db *database.DB, deps []database.Dependency, offline bool) (*LicenseDriftResult, error) {
	result := emptyLicenseDriftResult()
	result.Summary.TotalDependencies = len(deps)

	packagePURLs := make([]string, 0, len(deps))
	seenPURLs := make(map[string]bool)
	for _, dep := range deps {
		packagePURL := licensePackagePURLForDependency(dep)
		if packagePURL == "" {
			continue
		}
		if !seenPURLs[packagePURL] {
			seenPURLs[packagePURL] = true
			packagePURLs = append(packagePURLs, packagePURL)
		}
	}

	packageLicenses, err := getLicenseData(db, packagePURLs, offline)
	if err != nil {
		return nil, fmt.Errorf("looking up package licenses: %w", err)
	}

	versionLicenses, err := loadLicenseVersionLicenses(db, deps, offline)
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

func loadLicenseVersionLicenses(db *database.DB, deps []database.Dependency, offline bool) (map[string]string, error) {
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

	result := cachedLicenseDriftVersionLicenses(db, needed, offline)
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
	if offline {
		return result, fmt.Errorf(
			"offline mode: license metadata is not cached for %d package version(s); rerun without --offline to populate the cache",
			len(missing),
		)
	}

	client, err := newEnrichmentClient()
	if err != nil {
		return result, err
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
		return result, fmt.Errorf("fetching license version metadata failed for all %d uncached versions: %w",
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

func cachedLicenseDriftVersionLicenses(
	db *database.DB,
	needed map[string]map[string]bool,
	includeStale bool,
) map[string]string {
	result := make(map[string]string)
	if db == nil {
		return result
	}

	for packagePURL := range needed {
		var cached []database.CachedVersion
		var err error
		if includeStale {
			cached, err = db.GetCachedVersionsIncludingStale(packagePURL)
		} else {
			cached, err = db.GetCachedVersions(packagePURL, enrichmentCacheTTL)
		}
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
