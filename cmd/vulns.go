package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/config"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/sarif"
	"github.com/git-pkgs/vers"
	"github.com/git-pkgs/vulns"
	"github.com/git-pkgs/vulns/osv"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

const (
	vulnsSyncTimeout         = 5 * time.Minute
	vulnsQueryTimeout        = 120 * time.Second
	vulnsShowTimeout         = 30 * time.Second
	vulnsHistoryTimeout      = 10 * time.Second
	vulnsSemaphoreSize       = 20
	defaultVulnsLogLimit     = 20
	defaultVulnsHistoryLimit = 50
	defaultVulnsPraiseLimit  = 50
	minCommitsForAnalysis    = 2
	separatorMediumLen       = 30
)

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

type osvQuery struct {
	dependency  database.Dependency
	purl        *purl.PURL
	requestPURL *purl.PURL
}

type osvSkipReason uint8

const (
	osvSkipUnsupportedEcosystem osvSkipReason = iota
	osvSkipUnrepresentablePURL
)

type skippedOSVDependency struct {
	dependency database.Dependency
	reason     osvSkipReason
}

// osvBatchSize must not exceed the OSV client's internal batch size so error
// indexes can be offset to the original query list.
const osvBatchSize = 1000

func buildOSVQueries(deps []database.Dependency, includeVersion bool) (queries []osvQuery, skipped []skippedOSVDependency) {
	for _, dep := range deps {
		version := ""
		if includeVersion {
			version = dep.Requirement
		}

		packagePURL := purl.MakePURL(dep.Ecosystem, dep.Name, version)
		if packagePURL == nil {
			skipped = append(skipped, skippedOSVDependency{dependency: dep, reason: osvSkipUnrepresentablePURL})
			continue
		}
		osvEcosystem, supported, overrideType := osvEcosystemForPURLType(packagePURL.Type)
		if !supported {
			skipped = append(skipped, skippedOSVDependency{dependency: dep, reason: osvSkipUnsupportedEcosystem})
			continue
		}

		// Preserve native types for the client's existing mappings. In particular,
		// Maven's FullName uses its lowercase type to retain the group:artifact form.
		requestPURL := *packagePURL
		if overrideType {
			requestPURL.Type = osvEcosystem
		}
		queries = append(queries, osvQuery{
			dependency:  dep,
			purl:        packagePURL,
			requestPURL: &requestPURL,
		})
	}
	return queries, skipped
}

// osvEcosystemForPURLType maps PURL types to names accepted by OSV's query API.
// The third return value indicates that the vulns client lacks this mapping and
// needs the PURL type temporarily replaced with the API ecosystem name.
func osvEcosystemForPURLType(purlType string) (string, bool, bool) {
	switch purlType {
	case "cargo":
		return "crates.io", true, false
	case "composer":
		return "Packagist", true, false
	case "conan":
		return "ConanCenter", true, true
	case "cran":
		return "CRAN", true, true
	case "gem":
		return "RubyGems", true, false
	case "githubactions":
		return "GitHub Actions", true, false
	case "golang":
		return "Go", true, false
	case "hackage":
		return "Hackage", true, true
	case "hex":
		return "Hex", true, false
	case "julia":
		return "Julia", true, true
	case "maven":
		return "Maven", true, false
	case "npm":
		return "npm", true, false
	case "nuget":
		return "NuGet", true, false
	case "opam":
		return "opam", true, true
	case "pub":
		return "Pub", true, false
	case "pypi":
		return "PyPI", true, false
	case "swift":
		return "SwiftURL", true, true
	default:
		return "", false, false
	}
}

func reportSkippedOSVDependencies(w io.Writer, skipped []skippedOSVDependency) {
	var unsupported, unrepresentable []database.Dependency
	for _, item := range skipped {
		switch item.reason {
		case osvSkipUnsupportedEcosystem:
			unsupported = append(unsupported, item.dependency)
		case osvSkipUnrepresentablePURL:
			unrepresentable = append(unrepresentable, item.dependency)
		}
	}

	reportUnsupportedOSVDependencies(w, unsupported)
	reportUnrepresentableOSVDependencies(w, unrepresentable)
}

func reportUnsupportedOSVDependencies(w io.Writer, skipped []database.Dependency) {
	if len(skipped) == 0 {
		return
	}

	labels := make(map[string]bool, len(skipped))
	ecosystems := make(map[string]bool, len(skipped))
	for _, dep := range skipped {
		label := dep.Ecosystem
		ecosystems[dep.Ecosystem] = true
		if dep.ManifestPath != "" {
			label += " (" + dep.ManifestPath + ")"
		}
		labels[label] = true
	}

	values := make([]string, 0, len(labels))
	for label := range labels {
		values = append(values, label)
	}
	sort.Strings(values)

	dependencyLabel := "dependency"
	if len(skipped) != 1 {
		dependencyLabel = "dependencies"
	}
	ecosystemLabel := "ecosystem"
	if len(ecosystems) != 1 {
		ecosystemLabel = "ecosystems"
	}
	_, _ = fmt.Fprintf(
		w,
		"Skipping %d %s from unsupported OSV %s: %s.\n",
		len(skipped),
		dependencyLabel,
		ecosystemLabel,
		strings.Join(values, ", "),
	)
}

func reportUnrepresentableOSVDependencies(w io.Writer, skipped []database.Dependency) {
	if len(skipped) == 0 {
		return
	}

	labels := make(map[string]bool, len(skipped))
	for _, dep := range skipped {
		label := fmt.Sprintf("%s package %q", dep.Ecosystem, dep.Name)
		if dep.ManifestPath != "" {
			label += " (" + dep.ManifestPath + ")"
		}
		labels[label] = true
	}

	values := make([]string, 0, len(labels))
	for label := range labels {
		values = append(values, label)
	}
	sort.Strings(values)

	dependencyLabel := "dependency with a package identity"
	purlLabel := "a PURL"
	if len(skipped) != 1 {
		dependencyLabel = "dependencies with package identities"
		purlLabel = "PURLs"
	}
	_, _ = fmt.Fprintf(
		w,
		"Skipping %d %s that cannot be represented as %s: %s.\n",
		len(skipped),
		dependencyLabel,
		purlLabel,
		strings.Join(values, ", "),
	)
}

func queryOSVBatches(ctx context.Context, source vulns.Source, queries []osvQuery) ([][]vulns.Vulnerability, error) {
	var allResults [][]vulns.Vulnerability
	for start := 0; start < len(queries); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(queries) {
			end = len(queries)
		}

		requestPURLs := make([]*purl.PURL, 0, end-start)
		for _, query := range queries[start:end] {
			requestPURLs = append(requestPURLs, query.requestPURL)
		}

		results, err := source.QueryBatch(ctx, requestPURLs)
		if err != nil {
			return nil, wrapOSVBatchError(err, queries, start)
		}
		allResults = append(allResults, results...)
	}
	return allResults, nil
}

func wrapOSVBatchError(err error, queries []osvQuery, batchOffset int) error {
	const marker = "error in query at index "

	remainder, found := strings.CutPrefix(err.Error(), marker)
	if !found {
		if index := strings.Index(err.Error(), marker); index >= 0 {
			remainder = err.Error()[index+len(marker):]
		} else {
			return fmt.Errorf("querying OSV: %w", err)
		}
	}

	indexText, _, found := strings.Cut(remainder, ":")
	if !found {
		return fmt.Errorf("querying OSV: %w", err)
	}
	index, parseErr := strconv.Atoi(indexText)
	if parseErr != nil {
		return fmt.Errorf("querying OSV: %w", err)
	}
	index += batchOffset
	if index < 0 || index >= len(queries) {
		return fmt.Errorf("querying OSV: %w", err)
	}

	query := queries[index]
	if query.dependency.ManifestPath == "" {
		return fmt.Errorf("querying OSV for %s: %w", query.purl.String(), err)
	}
	return fmt.Errorf("querying OSV for %s from %s: %w", query.purl.String(), query.dependency.ManifestPath, err)
}

func addVulnsCmd(parent *cobra.Command) {
	vulnsCmd := &cobra.Command{
		Use:     "vulns",
		Aliases: []string{"audit"},
		Short:   "Vulnerability scanning commands",
		Long:    `Commands for scanning dependencies for known vulnerabilities using OSV.`,
	}

	addVulnsSyncCmd(vulnsCmd)
	addVulnsScanCmd(vulnsCmd)
	addVulnsShowCmd(vulnsCmd)
	addVulnsDiffCmd(vulnsCmd)
	addVulnsBlameCmd(vulnsCmd)
	addVulnsLogCmd(vulnsCmd)
	addVulnsHistoryCmd(vulnsCmd)
	addVulnsExposureCmd(vulnsCmd)
	addVulnsPraiseCmd(vulnsCmd)

	parent.AddCommand(vulnsCmd)
}

// VulnResult represents a vulnerability found in a dependency.
type VulnResult struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases,omitempty"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity"`
	Package      string   `json:"package"`
	Ecosystem    string   `json:"ecosystem"`
	Version      string   `json:"version"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	ManifestPath string   `json:"manifest_path"`
	References   []string `json:"references,omitempty"`
}

// vulns sync command
func addVulnsSyncCmd(parent *cobra.Command) {
	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "Sync vulnerability data from OSV",
		Long: `Fetch and store vulnerability data from OSV for all current dependencies.
This allows subsequent vulnerability queries to use cached data instead of making API calls.`,
		RunE: runVulnsSync,
	}

	syncCmd.Flags().StringP("branch", "b", "", "Branch to sync (default: first tracked branch)")
	syncCmd.Flags().StringP("ecosystem", "e", "", "Only sync specific ecosystem")
	syncCmd.Flags().Bool("force", false, "Force re-sync even if recently synced")
	parent.AddCommand(syncCmd)
}

func runVulnsSync(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	force, _ := cmd.Flags().GetBool("force")
	quiet, _ := cmd.Flags().GetBool("quiet")

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get current lockfile dependencies
	deps, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		return fmt.Errorf("getting dependencies: %w", err)
	}

	// Filter to resolved lockfile deps
	deps = git.FilterDependenciesByEcosystemConfig(deps, ecosystemFilter)
	deps = filterByEcosystem(deps, ecosystem)
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if isResolvedDependency(d) {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	source := osv.New(osv.WithUserAgent(userAgent))
	return syncVulnerabilitiesForDeps(db, source, lockfileDeps, force, quiet, cmd.OutOrStdout())
}

func syncVulnerabilitiesForDeps(db *database.DB, source vulns.Source, lockfileDeps []database.Dependency, force, quiet bool, w io.Writer) error {
	if len(lockfileDeps) == 0 {
		if !quiet {
			_, _ = fmt.Fprintln(w, "No lockfile dependencies to sync.")
		}
		return nil
	}

	queries, skipped := buildOSVQueries(lockfileDeps, false)
	if !quiet {
		reportSkippedOSVDependencies(w, skipped)
	}

	// Report every skipped source, but query each package only once.
	uniqueQueries := make(map[string]osvQuery, len(queries))
	for _, query := range queries {
		purlStr := query.purl.String()
		if _, ok := uniqueQueries[purlStr]; !ok {
			uniqueQueries[purlStr] = query
		}
	}
	keys := make([]string, 0, len(uniqueQueries))
	for key := range uniqueQueries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	queries = make([]osvQuery, 0, len(keys))
	for _, key := range keys {
		queries = append(queries, uniqueQueries[key])
	}

	if len(queries) == 0 {
		if !quiet {
			_, _ = fmt.Fprintln(w, "No dependencies with OSV-supported ecosystems to sync.")
		}
		return nil
	}

	if !quiet {
		_, _ = fmt.Fprintf(w, "Syncing vulnerabilities for %d packages...\n", len(queries))
	}

	ctx, cancel := context.WithTimeout(context.Background(), vulnsSyncTimeout)
	defer cancel()

	// Fetch only packages whose vulnerability data is stale.
	var pending []osvQuery
	for _, query := range queries {
		// Check if recently synced (unless force)
		if !force {
			purlStr := query.purl.String()
			syncedAt, _ := db.GetVulnsSyncedAt(purlStr)
			if !syncedAt.IsZero() && time.Since(syncedAt) < 24*time.Hour {
				continue
			}
		}

		pending = append(pending, query)
	}

	if len(pending) == 0 {
		if !quiet {
			_, _ = fmt.Fprintln(w, "All packages already synced.")
		}
		return nil
	}
	queries = pending

	// Query OSV in batches to get vuln IDs
	results, err := queryOSVBatches(ctx, source, queries)
	if err != nil {
		return err
	}

	// Collect unique vuln IDs across all batch results
	uniqueVulnIDs := make(map[string]bool)
	for _, batchVulns := range results {
		for _, v := range batchVulns {
			uniqueVulnIDs[v.ID] = true
		}
	}

	// Fetch all unique vulnerability details concurrently
	fetchedVulns := make(map[string]*vulns.Vulnerability)
	var mu sync.Mutex

	isTTY := false
	if f, ok := w.(*os.File); ok {
		isTTY = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}

	totalToFetch := len(uniqueVulnIDs)
	var fetchCount int
	var wg sync.WaitGroup
	sem := make(chan struct{}, vulnsSemaphoreSize)

	for id := range uniqueVulnIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()

			fullVuln, err := source.Get(ctx, id)

			mu.Lock()
			defer mu.Unlock()
			fetchCount++
			if err == nil && fullVuln != nil {
				fetchedVulns[id] = fullVuln
			}
			if isTTY && !quiet {
				_, _ = fmt.Fprintf(w, "\rFetching vulnerability details... %d/%d", fetchCount, totalToFetch)
			}
		}()
	}

	wg.Wait()

	if isTTY && !quiet && totalToFetch > 0 {
		_, _ = fmt.Fprintf(w, "\r\033[K")
	}

	// Clear existing vulns and store results
	now := time.Now().Format(time.RFC3339)
	seenVulns := make(map[string]bool)
	totalVulns := 0

	for i, batchVulns := range results {
		dep := queries[i].dependency

		// Clear existing vulns for this package
		if err := db.DeleteVulnerabilitiesForPackage(dep.Ecosystem, dep.Name); err != nil {
			return fmt.Errorf("clearing vulns for %s/%s: %w", dep.Ecosystem, dep.Name, err)
		}

		for _, v := range batchVulns {
			if seenVulns[v.ID] {
				// Still insert the package mapping for deduped vulns
				fullVuln := fetchedVulns[v.ID]
				if fullVuln == nil {
					continue
				}
				fixedVersion := fullVuln.FixedVersion(dep.Ecosystem, dep.Name)
				affectedVersions := buildVersRange(fullVuln, dep.Ecosystem, dep.Name)
				vpRecord := database.VulnerabilityPackage{
					VulnerabilityID:  fullVuln.ID,
					Ecosystem:        dep.Ecosystem,
					PackageName:      dep.Name,
					AffectedVersions: affectedVersions,
					FixedVersions:    fixedVersion,
				}
				if err := db.InsertVulnerabilityPackage(vpRecord); err != nil {
					return fmt.Errorf("inserting vulnerability package: %w", err)
				}
				continue
			}
			seenVulns[v.ID] = true

			fullVuln := fetchedVulns[v.ID]
			if fullVuln == nil {
				continue
			}

			// Store the vulnerability
			dbVuln := database.Vulnerability{
				ID:          fullVuln.ID,
				Aliases:     fullVuln.Aliases,
				Severity:    fullVuln.SeverityLevel(),
				Summary:     fullVuln.Summary,
				Details:     fullVuln.Details,
				PublishedAt: fullVuln.Published.Format(time.RFC3339),
				ModifiedAt:  fullVuln.Modified.Format(time.RFC3339),
				FetchedAt:   now,
			}

			// Extract CVSS score if available
			if cvss := fullVuln.CVSS(); cvss != nil {
				dbVuln.CVSSVector = cvss.Vector
				dbVuln.CVSSScore = cvss.Score
			}

			// Extract references
			for _, ref := range fullVuln.References {
				dbVuln.References = append(dbVuln.References, ref.URL)
			}

			if err := db.InsertVulnerability(dbVuln); err != nil {
				return fmt.Errorf("inserting vulnerability %s: %w", fullVuln.ID, err)
			}

			// Store the package mapping with affected version ranges
			fixedVersion := fullVuln.FixedVersion(dep.Ecosystem, dep.Name)
			affectedVersions := buildVersRange(fullVuln, dep.Ecosystem, dep.Name)

			vpRecord := database.VulnerabilityPackage{
				VulnerabilityID:  fullVuln.ID,
				Ecosystem:        dep.Ecosystem,
				PackageName:      dep.Name,
				AffectedVersions: affectedVersions,
				FixedVersions:    fixedVersion,
			}

			if err := db.InsertVulnerabilityPackage(vpRecord); err != nil {
				return fmt.Errorf("inserting vulnerability package: %w", err)
			}

			totalVulns++
		}
	}

	// Mark packages as synced
	for _, query := range queries {
		dep := query.dependency
		if err := db.SetVulnsSyncedAt(query.purl.String(), dep.Ecosystem, dep.Name); err != nil {
			return fmt.Errorf("recording sync time for %s/%s: %w", dep.Ecosystem, dep.Name, err)
		}
	}

	if !quiet {
		_, _ = fmt.Fprintf(w, "Synced %d vulnerabilities for %d packages.\n", totalVulns, len(queries))
	}

	return nil
}

// buildVersRange converts a vulnerability's affected ranges to a vers URI string
// for the specified package.
func buildVersRange(v *vulns.Vulnerability, ecosystem, name string) string {
	for _, aff := range v.Affected {
		if !strings.EqualFold(aff.Package.Name, name) {
			continue
		}

		// Filter to SEMVER/ECOSYSTEM ranges only
		filtered := vulns.Affected{
			Package:  aff.Package,
			Versions: aff.Versions,
		}
		for _, r := range aff.Ranges {
			if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
				filtered.Ranges = append(filtered.Ranges, r)
			}
		}

		rangeStr := vulns.AffectedVersionRange(filtered)
		if rangeStr == "" {
			return ""
		}
		return fmt.Sprintf("vers:%s/%s", ecosystem, rangeStr)
	}
	return ""
}

func addVulnsScanCmd(parent *cobra.Command) {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies for vulnerabilities",
		Long: `Check all dependencies against the OSV database for known vulnerabilities.
Results are grouped by severity.

By default, syncs vulnerability data from OSV before scanning. The sync uses a
24-hour cache so repeated scans won't re-fetch everything.
Use --live to query OSV directly for each dependency version.
Use --no-sync to skip the sync and use only previously cached data.`,
		RunE: runVulnsScan,
	}

	scanCmd.Flags().StringP("commit", "c", "", "Scan dependencies at specific commit (default: HEAD)")
	scanCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	scanCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	scanCmd.Flags().StringP("severity", "s", "", "Minimum severity to report: critical, high, medium, low")
	scanCmd.Flags().StringP("format", "f", "text", "Output format: text, json, sarif")
	scanCmd.Flags().Bool("live", false, "Query OSV directly instead of using cached data")
	scanCmd.Flags().Bool("no-sync", false, "Skip auto-sync and use only cached vulnerability data")
	parent.AddCommand(scanCmd)
}

func runVulnsScan(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, err := getFormatFlag(cmd, formatText, formatJSON, formatSARIF)
	if err != nil {
		return err
	}
	live, _ := cmd.Flags().GetBool("live")
	noSync, _ := cmd.Flags().GetBool("no-sync")

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

	// Filter by ecosystem
	deps = filterByEcosystem(deps, ecosystem)

	// Filter to lockfile deps (or Go deps which have pinned versions)
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if isResolvedDependency(d) {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		if format == formatJSON {
			return outputVulnsJSON(cmd, nil)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found to scan.")
		return nil
	}

	// Auto-sync before cached scan (skip for --live and --no-sync)
	if !live && !noSync && db != nil {
		source := osv.New(osv.WithUserAgent(userAgent))
		if err := syncVulnerabilitiesForDeps(db, source, lockfileDeps, false, false, cmd.OutOrStdout()); err != nil {
			return fmt.Errorf("syncing vulnerabilities: %w", err)
		}
	}

	var vulnResults []VulnResult

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	if live || db == nil {
		// Live query mode - use OSV API directly
		var skipped []skippedOSVDependency
		vulnResults, skipped, err = scanLive(lockfileDeps, minSeverity)
		if err != nil {
			return err
		}
		reportSkippedOSVDependencies(cmd.ErrOrStderr(), skipped)
	} else {
		// Cached mode - use stored vulnerability data
		vulnResults, err = scanCached(db, lockfileDeps, minSeverity)
		if err != nil {
			return err
		}
	}

	// Sort by severity, then package name
	sort.Slice(vulnResults, func(i, j int) bool {
		if severityOrder[vulnResults[i].Severity] != severityOrder[vulnResults[j].Severity] {
			return severityOrder[vulnResults[i].Severity] < severityOrder[vulnResults[j].Severity]
		}
		return vulnResults[i].Package < vulnResults[j].Package
	})

	if len(vulnResults) == 0 {
		if format == formatJSON {
			return outputVulnsJSON(cmd, vulnResults)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	switch format {
	case formatJSON:
		return outputVulnsJSON(cmd, vulnResults)
	case "sarif":
		return outputVulnsSARIF(cmd, vulnResults)
	default:
		outputVulnsText(cmd, vulnResults)
		return nil
	}
}

func scanLive(deps []database.Dependency, minSeverity int) ([]VulnResult, []skippedOSVDependency, error) {
	source := osv.New(osv.WithUserAgent(userAgent))
	return scanLiveWithSource(source, deps, minSeverity)
}

func scanLiveWithSource(source vulns.Source, deps []database.Dependency, minSeverity int) ([]VulnResult, []skippedOSVDependency, error) {
	queries, skipped := buildOSVQueries(deps, true)
	if len(queries) == 0 {
		return nil, skipped, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), vulnsQueryTimeout)
	defer cancel()

	results, err := queryOSVBatches(ctx, source, queries)
	if err != nil {
		return nil, skipped, err
	}

	var vulnResults []VulnResult

	for i, batchVulns := range results {
		dep := queries[i].dependency
		for _, v := range batchVulns {
			sev := v.SeverityLevel()
			if severityOrder[sev] > minSeverity {
				continue
			}

			var refs []string
			for _, r := range v.References {
				refs = append(refs, r.URL)
			}

			vulnResults = append(vulnResults, VulnResult{
				ID:           v.ID,
				Aliases:      v.Aliases,
				Summary:      v.Summary,
				Severity:     sev,
				Package:      dep.Name,
				Ecosystem:    dep.Ecosystem,
				Version:      dep.Requirement,
				FixedVersion: v.FixedVersion(dep.Ecosystem, dep.Name),
				ManifestPath: dep.ManifestPath,
				References:   refs,
			})
		}
	}

	return vulnResults, skipped, nil
}

func scanCached(db *database.DB, deps []database.Dependency, minSeverity int) ([]VulnResult, error) {

	var vulnResults []VulnResult

	// Group deps by ecosystem+name for efficient querying
	type pkgKey struct {
		ecosystem string
		name      string
	}
	depsByPkg := make(map[pkgKey][]database.Dependency)
	for _, d := range deps {
		key := pkgKey{d.Ecosystem, d.Name}
		depsByPkg[key] = append(depsByPkg[key], d)
	}

	for key, pkgDeps := range depsByPkg {
		vulns, err := db.GetVulnerabilitiesForPackage(key.ecosystem, key.name)
		if err != nil {
			return nil, fmt.Errorf("getting vulns for %s/%s: %w", key.ecosystem, key.name, err)
		}

		for _, v := range vulns {
			if severityOrder[v.Severity] > minSeverity {
				continue
			}

			// Get the fixed version from the vulnerability package mapping
			vp, err := db.GetVulnerabilityPackageInfo(v.ID, key.ecosystem, key.name)
			if err != nil {
				continue
			}

			fixedVersion := ""
			if vp != nil && vp.FixedVersions != "" {
				// Take the first fixed version
				parts := strings.Split(vp.FixedVersions, ",")
				if len(parts) > 0 {
					fixedVersion = parts[0]
				}
			}

			// Parse the affected version range for matching
			var affectedRange *vers.Range
			if vp != nil && vp.AffectedVersions != "" {
				affectedRange, _ = vers.Parse(vp.AffectedVersions)
			}

			// Check each dep version against the affected range
			for _, dep := range pkgDeps {
				// If we have a range, check if the version is affected
				if affectedRange != nil && !affectedRange.Contains(dep.Requirement) {
					continue
				}

				vulnResults = append(vulnResults, VulnResult{
					ID:           v.ID,
					Aliases:      v.Aliases,
					Summary:      v.Summary,
					Severity:     v.Severity,
					Package:      dep.Name,
					Ecosystem:    dep.Ecosystem,
					Version:      dep.Requirement,
					FixedVersion: fixedVersion,
					ManifestPath: dep.ManifestPath,
					References:   v.References,
				})
			}
		}
	}

	return vulnResults, nil
}

func outputVulnsJSON(cmd *cobra.Command, results []VulnResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(results))
}

func outputVulnsText(cmd *cobra.Command, results []VulnResult) {
	// Group by severity
	bySeverity := make(map[string][]VulnResult)
	for _, r := range results {
		bySeverity[r.Severity] = append(bySeverity[r.Severity], r)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d vulnerabilities:\n\n", len(results))

	severityColors := map[string]func(string) string{
		"critical": Red,
		"high":     Red,
		"medium":   Yellow,
		"low":      Cyan,
		"unknown":  Dim,
	}

	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		vulns := bySeverity[sev]
		if len(vulns) == 0 {
			continue
		}

		colorFn := severityColors[sev]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%d):\n", colorFn(strings.ToUpper(sev)), len(vulns))
		for _, v := range vulns {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s - %s@%s\n", Bold(v.ID), v.Package, v.Version)
			if v.Summary != "" {
				summary := v.Summary
				if len(summary) > summaryTruncLen {
					summary = summary[:summaryTruncLen-3] + "..."
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", Dim(summary))
			}
			if v.FixedVersion != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Fixed in: %s\n", Green(v.FixedVersion))
			}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}

func outputVulnsSARIF(cmd *cobra.Command, results []VulnResult) error {
	driver := sarif.NewToolComponent()
	driver.Name = "git-pkgs"
	driver.Version = version
	driver.InformationURI = "https://github.com/git-pkgs/git-pkgs"

	ruleMap := make(map[string]bool)
	run := sarif.NewRun()
	for _, r := range results {
		if !ruleMap[r.ID] {
			ruleMap[r.ID] = true
			rule := sarif.NewReportingDescriptor()
			rule.ID = r.ID
			rule.ShortDescription = sarif.MultiformatMessageString{Text: r.Summary}
			rule.Properties = sarif.PropertyBag{
				"security-severity": severityToScore(r.Severity),
			}
			driver.Rules = append(driver.Rules, rule)
		}

		level := "warning"
		if r.Severity == "critical" || r.Severity == "high" {
			level = "error"
		}

		artifactLocation := sarif.NewArtifactLocation()
		artifactLocation.URI = r.ManifestPath
		location := sarif.NewLocation()
		location.PhysicalLocation = sarif.PhysicalLocation{ArtifactLocation: artifactLocation}
		result := sarif.NewResult()
		result.RuleID = r.ID
		result.Level = level
		result.Message = sarif.Message{Text: fmt.Sprintf("%s@%s is vulnerable", r.Package, r.Version)}
		result.Locations = []sarif.Location{location}
		run.Results = append(run.Results, result)
	}

	tool := sarif.NewTool()
	tool.Driver = driver
	run.Tool = tool
	report := sarif.Log{
		SchemaURI: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version:   "2.1.0",
		Runs:      []sarif.Run{run},
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

const (
	scoreCritical = 9.0
	scoreHigh     = 7.0
	scoreMedium   = 4.0
	scoreLow      = 1.0
)

func severityToScore(severity string) float64 {
	switch severity {
	case "critical":
		return scoreCritical
	case "high":
		return scoreHigh
	case "medium":
		return scoreMedium
	case "low":
		return scoreLow
	default:
		return 0.0
	}
}

// vulns show command
func addVulnsShowCmd(parent *cobra.Command) {
	showCmd := &cobra.Command{
		Use:   "show <vuln-id>",
		Short: "Show details of a vulnerability",
		Long: `Display detailed information about a specific vulnerability by its ID.
With --ref, also shows exposure analysis for this vulnerability in the repo.`,
		Args: cobra.ExactArgs(1),
		RunE: runVulnsShow,
	}

	showCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	showCmd.Flags().StringP("ref", "r", "", "Analyze exposure at specific commit (shows repo impact)")
	showCmd.Flags().StringP("branch", "b", "", "Branch to query for exposure analysis")
	parent.AddCommand(showCmd)
}

type VulnShowResult struct {
	Vulnerability *vulns.Vulnerability `json:"vulnerability"`
	Exposure      *VulnShowExposure    `json:"exposure,omitempty"`
}

type VulnShowExposure struct {
	Affected        bool   `json:"affected"`
	AffectedPackage string `json:"affected_package,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
	FixedVersion    string `json:"fixed_version,omitempty"`
	Commit          string `json:"commit,omitempty"`
}

func runVulnsShow(cmd *cobra.Command, args []string) error {
	vulnID := args[0]
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	ref, _ := cmd.Flags().GetString("ref")
	branchName, _ := cmd.Flags().GetString("branch")

	source := osv.New(osv.WithUserAgent(userAgent))
	ctx, cancel := context.WithTimeout(context.Background(), vulnsShowTimeout)
	defer cancel()

	vuln, err := source.Get(ctx, vulnID)
	if err != nil {
		return fmt.Errorf("fetching vulnerability: %w", err)
	}

	if vuln == nil {
		return fmt.Errorf("vulnerability %q not found", vulnID)
	}

	// Check exposure if --ref is provided
	var exposure *VulnShowExposure
	if ref != "" {
		exposure, err = analyzeVulnExposure(vuln, ref, branchName)
		if err != nil {
			return fmt.Errorf("analyzing exposure: %w", err)
		}
	}

	if format == formatJSON {
		result := VulnShowResult{
			Vulnerability: vuln,
			Exposure:      exposure,
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Text output
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", vuln.ID)
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", len(vuln.ID)))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if len(vuln.Aliases) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Aliases: %s\n", strings.Join(vuln.Aliases, ", "))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Severity: %s\n", vuln.SeverityLevel())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Published: %s\n", vuln.Published.Format("2006-01-02"))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Modified: %s\n", vuln.Modified.Format("2006-01-02"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if vuln.Summary != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Summary:\n  %s\n\n", Sanitize(vuln.Summary))
	}

	if vuln.Details != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Details:\n  %s\n\n", Sanitize(vuln.Details))
	}

	if len(vuln.Affected) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Affected packages:")
		for _, aff := range vuln.Affected {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s/%s\n", aff.Package.Ecosystem, aff.Package.Name)
			if fixed := vuln.FixedVersion(aff.Package.Ecosystem, aff.Package.Name); fixed != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Fixed in: %s\n", fixed)
			}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(vuln.References) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "References:")
		for _, ref := range vuln.References {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s\n", ref.Type, ref.URL)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	// Show exposure analysis if requested
	if exposure != nil {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Exposure Analysis:")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", separatorShortLen))
		if exposure.Affected {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status: %s\n", Red("AFFECTED"))
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Package: %s @ %s\n", exposure.AffectedPackage, exposure.CurrentVersion)
			if exposure.FixedVersion != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Fix available: %s\n", Green(exposure.FixedVersion))
			}
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Status: %s\n", Green("NOT AFFECTED"))
		}
	}

	return nil
}

func analyzeVulnExposure(vuln *vulns.Vulnerability, ref, branchName string) (*VulnShowExposure, error) {
	repo, db, err := openDatabase()
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return nil, fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return nil, err
	}

	sha, err := resolveVulnsRef(repo, ref)
	if err != nil {
		return nil, err
	}

	// Get dependencies at the specified ref
	deps, err := db.GetDependenciesAtRef(sha, branch.ID)
	if err != nil {
		return nil, fmt.Errorf("getting dependencies: %w", err)
	}
	deps = git.FilterDependenciesByEcosystemConfig(deps, ecosystemFilter)

	// Check if any dependency is affected by this vulnerability
	for _, dep := range deps {
		if !isResolvedDependency(dep) {
			continue
		}

		for _, aff := range vuln.Affected {
			if !ecosystemMatches(dep.Ecosystem, aff.Package.Ecosystem) {
				continue
			}
			if dep.Name != aff.Package.Name {
				continue
			}

			// Check if version is affected
			if vuln.IsVersionAffected(dep.Ecosystem, dep.Name, dep.Requirement) {
				return &VulnShowExposure{
					Affected:        true,
					AffectedPackage: dep.Name,
					CurrentVersion:  dep.Requirement,
					FixedVersion:    vuln.FixedVersion(dep.Ecosystem, dep.Name),
					Commit:          ref,
				}, nil
			}
		}
	}

	return &VulnShowExposure{
		Affected: false,
		Commit:   ref,
	}, nil
}

func ecosystemMatches(depEco, vulnEco string) bool {
	depLower := strings.ToLower(depEco)
	vulnLower := strings.ToLower(vulnEco)
	if depLower == vulnLower {
		return true
	}
	// Handle ecosystem aliases
	aliases := map[string][]string{
		"npm":       {"npm"},
		"gem":       {"rubygems", "gem"},
		"rubygems":  {"rubygems", "gem"},
		"pypi":      {"pypi"},
		"cargo":     {"crates.io", "cargo"},
		"crates.io": {"crates.io", "cargo"},
		"go":        {"go", "golang"},
		"golang":    {"go", "golang"},
		"maven":     {"maven"},
		"nuget":     {"nuget"},
		"packagist": {"packagist", "composer"},
		"composer":  {"packagist", "composer"},
		"hex":       {"hex"},
		"pub":       {"pub"},
	}
	for _, alias := range aliases[depLower] {
		if alias == vulnLower {
			return true
		}
	}
	return false
}

// vulns diff command
func addVulnsDiffCmd(parent *cobra.Command) {
	diffCmd := &cobra.Command{
		Use:   "diff [from] [to]",
		Short: "Compare vulnerabilities between commits",
		Long: `Show vulnerabilities that were added or fixed between two commits.
Defaults to comparing HEAD~1 with HEAD.`,
		RunE: runVulnsDiff,
	}

	diffCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	diffCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	diffCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	diffCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(diffCmd)
}

type VulnsDiffResult struct {
	Added []VulnResult `json:"added"`
	Fixed []VulnResult `json:"fixed"`
}

func runVulnsDiff(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	fromRef := "HEAD~1"
	toRef := refHEAD
	if len(args) >= 1 {
		fromRef = args[0]
	}
	if len(args) >= 2 {
		toRef = args[1]
	}

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get vulnerabilities at both refs
	fromVulns, err := getVulnsAtRef(repo, db, branch.ID, fromRef, ecosystem, ecosystemFilter)
	if err != nil {
		return fmt.Errorf("getting vulns at %s: %w", fromRef, err)
	}

	toVulns, err := getVulnsAtRef(repo, db, branch.ID, toRef, ecosystem, ecosystemFilter)
	if err != nil {
		return fmt.Errorf("getting vulns at %s: %w", toRef, err)
	}

	// Build sets for comparison
	fromSet := make(map[string]VulnResult)
	for _, v := range fromVulns {
		key := v.ID + ":" + v.Package + ":" + v.Version
		fromSet[key] = v
	}

	toSet := make(map[string]VulnResult)
	for _, v := range toVulns {
		key := v.ID + ":" + v.Package + ":" + v.Version
		toSet[key] = v
	}

	// Find added and fixed

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	result := VulnsDiffResult{}
	for key, v := range toSet {
		if _, ok := fromSet[key]; !ok {
			if severityOrder[v.Severity] <= minSeverity {
				result.Added = append(result.Added, v)
			}
		}
	}
	for key, v := range fromSet {
		if _, ok := toSet[key]; !ok {
			if severityOrder[v.Severity] <= minSeverity {
				result.Fixed = append(result.Fixed, v)
			}
		}
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Text output
	if len(result.Added) == 0 && len(result.Fixed) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerability changes between the commits.")
		return nil
	}

	if len(result.Added) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%d):\n", Red("Added vulnerabilities"), len(result.Added))
		for _, v := range result.Added {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s - %s@%s (%s)\n", Red("+"), Bold(v.ID), v.Package, v.Version, v.Severity)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	if len(result.Fixed) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%d):\n", Green("Fixed vulnerabilities"), len(result.Fixed))
		for _, v := range result.Fixed {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s - %s@%s (%s)\n", Green("-"), Bold(v.ID), v.Package, v.Version, v.Severity)
		}
	}

	return nil
}

func getVulnsAtRef(
	repo *git.Repository,
	db *database.DB,
	branchID int64,
	ref, ecosystem string,
	filter config.EcosystemFilter,
) ([]VulnResult, error) {
	sha, err := resolveVulnsRef(repo, ref)
	if err != nil {
		return nil, err
	}

	return getVulnsAtCommit(db, branchID, sha, ecosystem, filter)
}

func resolveVulnsRef(repo *git.Repository, ref string) (string, error) {
	hash, err := repo.ResolveRevision(ref)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", ref, err)
	}

	return hash.String(), nil
}

func getVulnsAtCommit(
	db *database.DB,
	branchID int64,
	sha, ecosystem string,
	filter config.EcosystemFilter,
) ([]VulnResult, error) {
	deps, err := db.GetDependenciesAtRef(sha, branchID)
	if err != nil {
		return nil, err
	}

	deps = git.FilterDependenciesByEcosystemConfig(deps, filter)
	deps = filterByEcosystem(deps, ecosystem)

	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if isResolvedDependency(d) {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		return nil, nil
	}

	// Use cached vulnerability data from the database
	return scanCached(db, lockfileDeps, allSeverities)
}

// getAllTimeVulns gets all vulnerabilities that have ever affected the codebase
// by scanning commit history and collecting any vulnerability that was present.
func getAllTimeVulns(db *database.DB, branchID int64, ecosystem string, filter config.EcosystemFilter) ([]VulnResult, error) {
	// Get recent commits with changes
	const allTimeVulnsLimit = 100
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID:  branchID,
		Ecosystem: ecosystem,
		Limit:     allTimeVulnsLimit,
	})
	if err != nil {
		return nil, err
	}

	// Track unique vulns we've seen
	seen := make(map[string]VulnResult) // key: vulnID:package:version

	for _, c := range commits {
		vulns, err := getVulnsAtCommit(db, branchID, c.SHA, ecosystem, filter)
		if err != nil {
			continue
		}

		for _, v := range vulns {
			key := v.ID + ":" + v.Package + ":" + v.Version
			if _, ok := seen[key]; !ok {
				seen[key] = v
			}
		}
	}

	var results []VulnResult
	for _, v := range seen {
		results = append(results, v)
	}

	return results, nil
}

// vulns blame command
func addVulnsBlameCmd(parent *cobra.Command) {
	blameCmd := &cobra.Command{
		Use:   "blame",
		Short: "Show who introduced current vulnerabilities",
		Long: `Attribute current vulnerabilities to the commits that introduced the vulnerable packages.
Shows which developers added packages that are currently vulnerable.`,
		RunE: runVulnsBlame,
	}

	blameCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	blameCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	blameCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	blameCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	blameCmd.Flags().Bool("all-time", false, "Include historical vulnerabilities that have been fixed")
	parent.AddCommand(blameCmd)
}

type VulnBlameEntry struct {
	VulnID      string `json:"vuln_id"`
	Severity    string `json:"severity"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	FixedIn     string `json:"fixed_in,omitempty"`
	AddedBy     string `json:"added_by"`
	AddedEmail  string `json:"added_email"`
	AddedCommit string `json:"added_commit"`
	AddedDate   string `json:"added_date"`
}

func runVulnsBlame(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	allTime, _ := cmd.Flags().GetBool("all-time")

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get vulnerabilities
	var vulns []VulnResult
	if allTime {
		vulns, err = getAllTimeVulns(db, branch.ID, ecosystem, ecosystemFilter)
	} else {
		vulns, err = getVulnsAtRef(repo, db, branch.ID, refHEAD, ecosystem, ecosystemFilter)
	}
	if err != nil {
		return fmt.Errorf("getting vulnerabilities: %w", err)
	}

	// Apply severity filter

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var filteredVulns []VulnResult
	for _, v := range vulns {
		if severityOrder[v.Severity] <= minSeverity {
			filteredVulns = append(filteredVulns, v)
		}
	}

	if len(filteredVulns) == 0 {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnBlameEntry{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	// Get blame information for each vulnerable package
	blameData, err := db.GetBlame(database.BlameOptions{
		BranchID:  branch.ID,
		Ecosystem: ecosystem,
	})
	if err != nil {
		return fmt.Errorf("getting blame data: %w", err)
	}

	// Build blame lookup
	blameLookup := make(map[string]database.BlameEntry)
	for _, b := range blameData {
		key := b.Name + ":" + b.ManifestPath
		blameLookup[key] = b
	}

	var entries []VulnBlameEntry
	for _, v := range filteredVulns {
		key := v.Package + ":" + v.ManifestPath
		blame, ok := blameLookup[key]
		if !ok {
			continue
		}

		entries = append(entries, VulnBlameEntry{
			VulnID:      v.ID,
			Severity:    v.Severity,
			Package:     v.Package,
			Version:     v.Version,
			FixedIn:     v.FixedVersion,
			AddedBy:     blame.AuthorName,
			AddedEmail:  blame.AuthorEmail,
			AddedCommit: blame.SHA,
			AddedDate:   blame.CommittedAt,
		})
	}

	// Sort by severity, then author
	sort.Slice(entries, func(i, j int) bool {
		if severityOrder[entries[i].Severity] != severityOrder[entries[j].Severity] {
			return severityOrder[entries[i].Severity] < severityOrder[entries[j].Severity]
		}
		return entries[i].AddedBy < entries[j].AddedBy
	})

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(entries))
	}

	// Group by author
	byAuthor := make(map[string][]VulnBlameEntry)
	for _, e := range entries {
		byAuthor[e.AddedBy] = append(byAuthor[e.AddedBy], e)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability blame (%d vulnerabilities):\n\n", len(entries))

	var authors []string
	for a := range byAuthor {
		authors = append(authors, a)
	}
	sort.Strings(authors)

	for _, author := range authors {
		vulnEntries := byAuthor[author]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%d):\n", author, len(vulnEntries))
		for _, e := range vulnEntries {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s - %s@%s (%s)\n", e.VulnID, e.Package, e.Version, e.Severity)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Added in %s\n", shortSHA(e.AddedCommit))
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

// vulns log command
func addVulnsLogCmd(parent *cobra.Command) {
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Show commits that changed vulnerability state",
		Long: `List commits that introduced or fixed vulnerabilities.
Shows a timeline of how vulnerabilities have changed over time.`,
		RunE: runVulnsLog,
	}

	logCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	logCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	logCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	logCmd.Flags().String("since", "", "Only commits after this date (YYYY-MM-DD)")
	logCmd.Flags().String("until", "", "Only commits before this date (YYYY-MM-DD)")
	logCmd.Flags().String("author", "", "Filter by author name or email")
	logCmd.Flags().Bool("introduced", false, "Only show commits that introduced vulnerabilities")
	logCmd.Flags().Bool("fixed", false, "Only show commits that fixed vulnerabilities")
	logCmd.Flags().Int("limit", defaultVulnsLogLimit, "Maximum commits to check")
	logCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(logCmd)
}

type VulnLogEntry struct {
	SHA        string       `json:"sha"`
	Message    string       `json:"message"`
	Author     string       `json:"author"`
	Date       string       `json:"date"`
	Introduced []VulnResult `json:"introduced,omitempty"`
	Fixed      []VulnResult `json:"fixed,omitempty"`
}

func runVulnsLog(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	author, _ := cmd.Flags().GetString("author")
	introducedOnly, _ := cmd.Flags().GetBool("introduced")
	fixedOnly, _ := cmd.Flags().GetBool("fixed")
	limit, _ := cmd.Flags().GetInt("limit")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get commits with changes
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID:  branch.ID,
		Ecosystem: ecosystem,
		Author:    author,
		Since:     since,
		Until:     until,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	if len(commits) == 0 {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnLogEntry{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No commits with dependency changes found.")
		return nil
	}

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var entries []VulnLogEntry
	var prevVulns []VulnResult

	for i, c := range commits {
		// Get vulns at this commit
		currentVulns, err := getVulnsAtCommit(db, branch.ID, c.SHA, ecosystem, ecosystemFilter)
		if err != nil {
			continue
		}

		if i == 0 {
			prevVulns = currentVulns
			continue
		}

		// Compare with previous
		prevSet := make(map[string]VulnResult)
		for _, v := range prevVulns {
			key := v.ID + ":" + v.Package + ":" + v.Version
			prevSet[key] = v
		}

		currSet := make(map[string]VulnResult)
		for _, v := range currentVulns {
			key := v.ID + ":" + v.Package + ":" + v.Version
			currSet[key] = v
		}

		var introduced, fixed []VulnResult
		for key, v := range currSet {
			if _, ok := prevSet[key]; !ok && severityOrder[v.Severity] <= minSeverity {
				introduced = append(introduced, v)
			}
		}
		for key, v := range prevSet {
			if _, ok := currSet[key]; !ok && severityOrder[v.Severity] <= minSeverity {
				fixed = append(fixed, v)
			}
		}

		if len(introduced) > 0 || len(fixed) > 0 {
			if introducedOnly && len(introduced) == 0 {
				prevVulns = currentVulns
				continue
			}
			if fixedOnly && len(fixed) == 0 {
				prevVulns = currentVulns
				continue
			}

			entry := VulnLogEntry{
				SHA:     c.SHA,
				Message: strings.Split(c.Message, "\n")[0],
				Author:  c.AuthorName,
				Date:    c.CommittedAt,
			}
			if !fixedOnly {
				entry.Introduced = introduced
			}
			if !introducedOnly {
				entry.Fixed = fixed
			}
			entries = append(entries, entry)
		}

		prevVulns = currentVulns
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(entries))
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerability changes found in recent commits.")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability changes in %d commits:\n\n", len(entries))

	for _, e := range entries {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s (%s)\n", shortSHA(e.SHA), e.Message, e.Author)

		for _, v := range e.Introduced {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  + %s - %s@%s (%s)\n", v.ID, v.Package, v.Version, v.Severity)
		}
		for _, v := range e.Fixed {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - %s - %s@%s (%s)\n", v.ID, v.Package, v.Version, v.Severity)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

// vulns history command
func addVulnsHistoryCmd(parent *cobra.Command) {
	historyCmd := &cobra.Command{
		Use:   "history <package>",
		Short: "Show vulnerability history for a package",
		Long: `Display the vulnerability history for a specific package across all analyzed commits.
Shows when the package was vulnerable and what vulnerabilities affected it.`,
		Args: cobra.ExactArgs(1),
		RunE: runVulnsHistory,
	}

	historyCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	historyCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	historyCmd.Flags().Int("limit", defaultVulnsHistoryLimit, "Maximum commits to check")
	historyCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(historyCmd)
}

type VulnHistoryEntry struct {
	SHA             string       `json:"sha"`
	Date            string       `json:"date"`
	Version         string       `json:"version"`
	Vulnerabilities []VulnResult `json:"vulnerabilities,omitempty"`
}

func runVulnsHistory(cmd *cobra.Command, args []string) error {
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")
	branchName, _ := cmd.Flags().GetString("branch")
	limit, _ := cmd.Flags().GetInt("limit")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	ecosystem, packageName, _, err := ParsePackageArg(args[0], ecosystemFlag)
	if err != nil {
		return err
	}

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get commits with changes
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID: branch.ID,
		Limit:    limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	source := osv.New(osv.WithUserAgent(userAgent))
	var history []VulnHistoryEntry

	for _, c := range commits {
		deps, err := db.GetDependenciesAtRef(c.SHA, branch.ID)
		if err != nil {
			continue
		}
		deps = git.FilterDependenciesByEcosystemConfig(deps, ecosystemFilter)

		// Find the package in deps
		var pkgDep *database.Dependency
		for _, d := range deps {
			if !strings.EqualFold(d.Name, packageName) {
				continue
			}
			if ecosystem != "" && !strings.EqualFold(d.Ecosystem, ecosystem) {
				continue
			}
			if isResolvedDependency(d) {
				pkgDep = &d
				break
			}
		}

		if pkgDep == nil {
			continue
		}

		p := purl.MakePURL(pkgDep.Ecosystem, pkgDep.Name, pkgDep.Requirement)
		if p == nil {
			return fmt.Errorf(
				"querying OSV for %s package %q: package identity cannot be represented as a PURL",
				pkgDep.Ecosystem,
				pkgDep.Name,
			)
		}

		// Query for vulnerabilities
		ctx, cancel := context.WithTimeout(context.Background(), vulnsHistoryTimeout)
		queryResults, err := source.Query(ctx, p)
		cancel()
		if err != nil {
			continue
		}

		entry := VulnHistoryEntry{
			SHA:     c.SHA,
			Date:    c.CommittedAt,
			Version: pkgDep.Requirement,
		}

		for _, v := range queryResults {
			entry.Vulnerabilities = append(entry.Vulnerabilities, VulnResult{
				ID:       v.ID,
				Summary:  v.Summary,
				Severity: v.SeverityLevel(),
			})
		}

		history = append(history, entry)
	}

	if len(history) == 0 {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnHistoryEntry{})
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in commit history.\n", packageName)
		return nil
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(history))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability history for %s:\n\n", packageName)

	for _, h := range history {
		date := h.Date[:10]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s", shortSHA(h.SHA), date, h.Version)
		if len(h.Vulnerabilities) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  (%d vulnerabilities)\n", len(h.Vulnerabilities))
			for _, v := range h.Vulnerabilities {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    - %s (%s)\n", v.ID, v.Severity)
			}
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  (clean)")
		}
	}

	return nil
}

// vulns exposure command
func addVulnsExposureCmd(parent *cobra.Command) {
	exposureCmd := &cobra.Command{
		Use:   "exposure",
		Short: "Calculate vulnerability exposure time",
		Long: `Calculate how long each current vulnerability has been present in the codebase.
Shows the exposure time from when the vulnerable package was first added.`,
		RunE: runVulnsExposure,
	}

	exposureCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	exposureCmd.Flags().StringP("ref", "r", "", "Check exposure at specific commit (default: HEAD)")
	exposureCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	exposureCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	exposureCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	exposureCmd.Flags().Bool("summary", false, "Show aggregate metrics only")
	exposureCmd.Flags().Bool("all-time", false, "Include historical vulnerabilities that have been fixed")
	parent.AddCommand(exposureCmd)
}

type VulnExposureEntry struct {
	VulnID       string `json:"vuln_id"`
	Severity     string `json:"severity"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	IntroducedAt string `json:"introduced_at"`
	IntroducedBy string `json:"introduced_by"`
	ExposureDays int    `json:"exposure_days"`
}

func runVulnsExposure(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ref, _ := cmd.Flags().GetString("ref")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	summary, _ := cmd.Flags().GetBool("summary")
	allTime, _ := cmd.Flags().GetBool("all-time")

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get vulnerabilities at the specified ref
	targetRef := ref
	if targetRef == "" {
		targetRef = refHEAD
	}

	var vulns []VulnResult
	if allTime {
		// Get all historical vulnerabilities by scanning commit history
		vulns, err = getAllTimeVulns(db, branch.ID, ecosystem, ecosystemFilter)
	} else {
		vulns, err = getVulnsAtRef(repo, db, branch.ID, targetRef, ecosystem, ecosystemFilter)
	}
	if err != nil {
		return fmt.Errorf("getting vulnerabilities: %w", err)
	}

	// Apply severity filter

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var filteredVulns []VulnResult
	for _, v := range vulns {
		if severityOrder[v.Severity] <= minSeverity {
			filteredVulns = append(filteredVulns, v)
		}
	}

	if len(filteredVulns) == 0 {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnExposureEntry{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	// Get blame info to find when each package was introduced
	blameData, err := db.GetBlame(database.BlameOptions{
		BranchID:  branch.ID,
		Ecosystem: ecosystem,
	})
	if err != nil {
		return fmt.Errorf("getting blame data: %w", err)
	}

	blameLookup := make(map[string]database.BlameEntry)
	for _, b := range blameData {
		key := b.Name + ":" + b.ManifestPath
		blameLookup[key] = b
	}

	now := time.Now()
	var entries []VulnExposureEntry

	for _, v := range filteredVulns {
		key := v.Package + ":" + v.ManifestPath
		blame, ok := blameLookup[key]
		if !ok {
			continue
		}

		// Parse the committed date
		committedAt, err := time.Parse(time.RFC3339, blame.CommittedAt)
		if err != nil {
			continue
		}

		exposureDays := int(now.Sub(committedAt).Hours() / 24)

		entries = append(entries, VulnExposureEntry{
			VulnID:       v.ID,
			Severity:     v.Severity,
			Package:      v.Package,
			Version:      v.Version,
			IntroducedAt: blame.CommittedAt,
			IntroducedBy: blame.AuthorName,
			ExposureDays: exposureDays,
		})
	}

	// Sort by exposure days (longest first)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ExposureDays != entries[j].ExposureDays {
			return entries[i].ExposureDays > entries[j].ExposureDays
		}
		return entries[i].VulnID < entries[j].VulnID
	})

	if summary {
		return outputExposureSummary(cmd, entries, format)
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(entries))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability exposure (%d vulnerabilities):\n\n", len(entries))

	for _, e := range entries {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s - %s@%s (%s)\n", e.VulnID, e.Package, e.Version, e.Severity)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Exposed for %d days (since %s by %s)\n\n",
			e.ExposureDays, e.IntroducedAt[:10], e.IntroducedBy)
	}

	return nil
}

type ExposureSummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	TotalExposureDays    int            `json:"total_exposure_days"`
	AverageExposureDays  float64        `json:"average_exposure_days"`
	MaxExposureDays      int            `json:"max_exposure_days"`
	BySeverity           map[string]int `json:"by_severity"`
	OldestExposure       string         `json:"oldest_exposure,omitempty"`
}

func outputExposureSummary(cmd *cobra.Command, entries []VulnExposureEntry, format string) error {
	summary := ExposureSummary{
		TotalVulnerabilities: len(entries),
		BySeverity:           make(map[string]int),
	}

	totalDays := 0
	maxDays := 0
	var oldestDate string

	for _, e := range entries {
		totalDays += e.ExposureDays
		if e.ExposureDays > maxDays {
			maxDays = e.ExposureDays
			oldestDate = e.IntroducedAt
		}
		summary.BySeverity[e.Severity]++
	}

	summary.TotalExposureDays = totalDays
	summary.MaxExposureDays = maxDays
	if len(entries) > 0 {
		summary.AverageExposureDays = float64(totalDays) / float64(len(entries))
	}
	if oldestDate != "" && len(oldestDate) >= 10 {
		summary.OldestExposure = oldestDate[:10]
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Vulnerability Exposure Summary")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", separatorMediumLen))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total vulnerabilities: %d\n", summary.TotalVulnerabilities)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total exposure:        %d days\n", summary.TotalExposureDays)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Average exposure:      %.1f days\n", summary.AverageExposureDays)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Max exposure:          %d days\n", summary.MaxExposureDays)
	if summary.OldestExposure != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Oldest since:          %s\n", summary.OldestExposure)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "By severity:")
	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		if count, ok := summary.BySeverity[sev]; ok && count > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d\n", sev, count)
		}
	}

	return nil
}

// vulns praise command
func addVulnsPraiseCmd(parent *cobra.Command) {
	praiseCmd := &cobra.Command{
		Use:   "praise",
		Short: "Show who fixed vulnerabilities",
		Long: `Attribute vulnerability fixes to the developers who resolved them.
This is the opposite of blame - it shows positive contributions to security.`,
		RunE: runVulnsPraise,
	}

	praiseCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	praiseCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	praiseCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	praiseCmd.Flags().Int("limit", defaultVulnsPraiseLimit, "Maximum commits to check")
	praiseCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	praiseCmd.Flags().Bool("summary", false, "Show author leaderboard only")
	parent.AddCommand(praiseCmd)
}

type VulnPraiseEntry struct {
	VulnID    string `json:"vuln_id"`
	Severity  string `json:"severity"`
	Package   string `json:"package"`
	FixedBy   string `json:"fixed_by"`
	FixedIn   string `json:"fixed_in"`
	FixedDate string `json:"fixed_date"`
}

func runVulnsPraise(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	limit, _ := cmd.Flags().GetInt("limit")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	summary, _ := cmd.Flags().GetBool("summary")

	repo, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return fmt.Errorf("loading ecosystem config: %w", err)
	}

	branch, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	// Get commits with changes
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID:  branch.ID,
		Ecosystem: ecosystem,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	if len(commits) < minCommitsForAnalysis {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnPraiseEntry{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Not enough commits to analyze vulnerability fixes.")
		return nil
	}

	minSeverity := allSeverities
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var entries []VulnPraiseEntry
	var prevVulns []VulnResult

	for i, c := range commits {
		currentVulns, err := getVulnsAtCommit(db, branch.ID, c.SHA, ecosystem, ecosystemFilter)
		if err != nil {
			continue
		}

		if i == 0 {
			prevVulns = currentVulns
			continue
		}

		// Find fixed vulnerabilities (in prev but not in current)
		prevSet := make(map[string]VulnResult)
		for _, v := range prevVulns {
			key := v.ID + ":" + v.Package
			prevSet[key] = v
		}

		currSet := make(map[string]bool)
		for _, v := range currentVulns {
			key := v.ID + ":" + v.Package
			currSet[key] = true
		}

		for key, v := range prevSet {
			if !currSet[key] {
				// Apply severity filter
				if severityOrder[v.Severity] > minSeverity {
					continue
				}
				entries = append(entries, VulnPraiseEntry{
					VulnID:    v.ID,
					Severity:  v.Severity,
					Package:   v.Package,
					FixedBy:   c.AuthorName,
					FixedIn:   c.SHA,
					FixedDate: c.CommittedAt,
				})
			}
		}

		prevVulns = currentVulns
	}

	if len(entries) == 0 {
		if format == formatJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode([]VulnPraiseEntry{})
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerability fixes found in recent commits.")
		return nil
	}

	if summary {
		return outputPraiseSummary(cmd, entries, format)
	}

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(entries))
	}

	// Group by author
	byAuthor := make(map[string][]VulnPraiseEntry)
	for _, e := range entries {
		byAuthor[e.FixedBy] = append(byAuthor[e.FixedBy], e)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability fixes (%d total):\n\n", len(entries))

	var authors []string
	for a := range byAuthor {
		authors = append(authors, a)
	}
	sort.Strings(authors)

	for _, author := range authors {
		fixes := byAuthor[author]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s (%d fixes):\n", author, len(fixes))
		for _, e := range fixes {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  - %s in %s (%s)\n", e.VulnID, e.Package, e.Severity)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Fixed in %s on %s\n", shortSHA(e.FixedIn), e.FixedDate[:10])
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

type PraiseAuthorSummary struct {
	Author         string         `json:"author"`
	TotalFixes     int            `json:"total_fixes"`
	BySeverity     map[string]int `json:"by_severity"`
	UniquePackages int            `json:"unique_packages"`
}

type PraiseSummary struct {
	TotalFixes int                   `json:"total_fixes"`
	Authors    []PraiseAuthorSummary `json:"authors"`
}

func outputPraiseSummary(cmd *cobra.Command, entries []VulnPraiseEntry, format string) error {
	// Group by author
	byAuthor := make(map[string][]VulnPraiseEntry)
	for _, e := range entries {
		byAuthor[e.FixedBy] = append(byAuthor[e.FixedBy], e)
	}

	summary := PraiseSummary{
		TotalFixes: len(entries),
	}

	for author, fixes := range byAuthor {
		as := PraiseAuthorSummary{
			Author:     author,
			TotalFixes: len(fixes),
			BySeverity: make(map[string]int),
		}

		uniquePkgs := make(map[string]bool)
		for _, f := range fixes {
			as.BySeverity[f.Severity]++
			uniquePkgs[f.Package] = true
		}
		as.UniquePackages = len(uniquePkgs)

		summary.Authors = append(summary.Authors, as)
	}

	// Sort by total fixes descending
	sort.Slice(summary.Authors, func(i, j int) bool {
		if summary.Authors[i].TotalFixes != summary.Authors[j].TotalFixes {
			return summary.Authors[i].TotalFixes > summary.Authors[j].TotalFixes
		}
		return summary.Authors[i].Author < summary.Authors[j].Author
	})

	if format == formatJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Vulnerability Fix Leaderboard")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", separatorMediumLen))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total fixes: %d\n\n", summary.TotalFixes)

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Rank  Author                    Fixes  Critical  High  Packages")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", separatorLongLen))

	for i, a := range summary.Authors {
		authorName := a.Author
		if len(authorName) > authorTruncLen {
			authorName = authorName[:authorTruncLen-3] + "..."
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%4d  %-24s  %5d  %8d  %4d  %8d\n",
			i+1,
			authorName,
			a.TotalFixes,
			a.BySeverity["critical"],
			a.BySeverity["high"],
			a.UniquePackages,
		)
	}

	return nil
}
