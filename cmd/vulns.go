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
	"github.com/git-pkgs/git-pkgs/internal/osv"
	"github.com/git-pkgs/vers"
	"github.com/spf13/cobra"
)

func init() {
	addVulnsCmd(rootCmd)
}

func addVulnsCmd(parent *cobra.Command) {
	vulnsCmd := &cobra.Command{
		Use:   "vulns",
		Short: "Vulnerability scanning commands",
		Long:  `Commands for scanning dependencies for known vulnerabilities using OSV.`,
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

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get current lockfile dependencies
	deps, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		return fmt.Errorf("getting dependencies: %w", err)
	}

	// Filter to lockfile deps
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind != "lockfile" || d.Requirement == "" {
			continue
		}
		if ecosystem != "" && d.Ecosystem != ecosystem {
			continue
		}
		lockfileDeps = append(lockfileDeps, d)
	}

	if len(lockfileDeps) == 0 {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies to sync.")
		}
		return nil
	}

	// Group by ecosystem+name for unique packages
	type pkgKey struct {
		ecosystem string
		name      string
	}
	uniquePkgs := make(map[pkgKey]bool)
	for _, d := range lockfileDeps {
		uniquePkgs[pkgKey{d.Ecosystem, d.Name}] = true
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Syncing vulnerabilities for %d packages...\n", len(uniquePkgs))
	}

	client := osv.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build queries for all unique packages
	var queries []osv.QueryRequest
	var queryKeys []pkgKey
	for key := range uniquePkgs {
		// Check if we need to sync (unless force)
		if !force {
			count, _ := db.GetStoredVulnCount(key.ecosystem, key.name)
			if count >= 0 {
				// Already synced, skip unless force
				// Note: count=0 means synced with no vulns, which is valid
				// We'd need a last_synced timestamp to do proper staleness checks
			}
		}

		queries = append(queries, osv.QueryRequest{
			Package: osv.Package{
				Ecosystem: key.ecosystem,
				Name:      key.name,
			},
		})
		queryKeys = append(queryKeys, key)
	}

	if len(queries) == 0 {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All packages already synced.")
		}
		return nil
	}

	// Query OSV in batches
	results, err := client.BatchQuery(ctx, queries)
	if err != nil {
		return fmt.Errorf("querying OSV: %w", err)
	}

	// Store results
	totalVulns := 0
	now := time.Now().Format(time.RFC3339)

	for i, vulns := range results {
		key := queryKeys[i]

		// Clear existing vulns for this package
		if err := db.DeleteVulnerabilitiesForPackage(key.ecosystem, key.name); err != nil {
			return fmt.Errorf("clearing vulns for %s/%s: %w", key.ecosystem, key.name, err)
		}

		for _, v := range vulns {
			// Store the vulnerability
			dbVuln := database.Vulnerability{
				ID:          v.ID,
				Aliases:     v.Aliases,
				Severity:    osv.GetSeverityLevel(&v),
				Summary:     v.Summary,
				Details:     v.Details,
				PublishedAt: v.Published.Format(time.RFC3339),
				ModifiedAt:  v.Modified.Format(time.RFC3339),
				FetchedAt:   now,
			}

			// Extract CVSS score if available
			for _, sev := range v.Severity {
				if sev.Type == "CVSS_V3" {
					dbVuln.CVSSVector = sev.Score
					var score float64
					_, _ = fmt.Sscanf(sev.Score, "%f", &score)
					dbVuln.CVSSScore = score
				}
			}

			// Extract references
			for _, ref := range v.References {
				dbVuln.References = append(dbVuln.References, ref.URL)
			}

			if err := db.InsertVulnerability(dbVuln); err != nil {
				return fmt.Errorf("inserting vulnerability %s: %w", v.ID, err)
			}

			// Store the package mapping
			var fixedVersions []string
			var affectedVersions string

			for _, aff := range v.Affected {
				if strings.EqualFold(aff.Package.Name, key.name) {
					// Collect fixed versions
					for _, r := range aff.Ranges {
						for _, e := range r.Events {
							if e.Fixed != "" {
								fixedVersions = append(fixedVersions, e.Fixed)
							}
						}
					}

					// Build vers range from affected ranges
					affectedVersions = buildVersRange(aff.Ranges)
					break
				}
			}

			vp := database.VulnerabilityPackage{
				VulnerabilityID:  v.ID,
				Ecosystem:        key.ecosystem,
				PackageName:      key.name,
				AffectedVersions: affectedVersions,
				FixedVersions:    strings.Join(fixedVersions, ","),
			}

			if err := db.InsertVulnerabilityPackage(vp); err != nil {
				return fmt.Errorf("inserting vulnerability package: %w", err)
			}

			totalVulns++
		}
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Synced %d vulnerabilities for %d packages.\n", totalVulns, len(queries))
	}

	return nil
}

// buildVersRange converts OSV ranges to a vers URI string.
// Format: vers:generic/<constraints>
func buildVersRange(ranges []osv.Range) string {
	var parts []string

	for _, r := range ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}

		var introduced, fixed, lastAffected string
		for _, e := range r.Events {
			if e.Introduced != "" {
				introduced = e.Introduced
			}
			if e.Fixed != "" {
				fixed = e.Fixed
			}
			if e.LastAffected != "" {
				lastAffected = e.LastAffected
			}
		}

		if introduced != "" {
			// Handle "0" as the minimum version (unbounded lower)
			if introduced == "0" {
				if fixed != "" {
					parts = append(parts, fmt.Sprintf("<=%s", fixed))
				} else if lastAffected != "" {
					parts = append(parts, fmt.Sprintf("<=%s", lastAffected))
				} else {
					parts = append(parts, "*")
				}
			} else {
				if fixed != "" {
					parts = append(parts, fmt.Sprintf(">=%s|<%s", introduced, fixed))
				} else if lastAffected != "" {
					parts = append(parts, fmt.Sprintf(">=%s|<=%s", introduced, lastAffected))
				} else {
					parts = append(parts, fmt.Sprintf(">=%s", introduced))
				}
			}
		}
	}

	if len(parts) == 0 {
		return ""
	}

	return "vers:generic/" + strings.Join(parts, "|")
}

func addVulnsScanCmd(parent *cobra.Command) {
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan dependencies for vulnerabilities",
		Long: `Check all dependencies against the OSV database for known vulnerabilities.
Results are grouped by severity.

By default, uses cached vulnerability data from the database if available.
Use --live to always query OSV directly.`,
		RunE: runVulnsScan,
	}

	scanCmd.Flags().StringP("commit", "c", "", "Scan dependencies at specific commit (default: HEAD)")
	scanCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	scanCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	scanCmd.Flags().StringP("severity", "s", "", "Minimum severity to report: critical, high, medium, low")
	scanCmd.Flags().StringP("format", "f", "text", "Output format: text, json, sarif")
	scanCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
	scanCmd.Flags().Bool("live", false, "Query OSV directly instead of using cached data")
	parent.AddCommand(scanCmd)
}

func runVulnsScan(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, _ := cmd.Flags().GetString("format")
	stateless, _ := cmd.Flags().GetBool("stateless")
	live, _ := cmd.Flags().GetBool("live")

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
		// Stateless mode implies live queries
		live = true
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

	// Filter by ecosystem
	if ecosystem != "" {
		var filtered []database.Dependency
		for _, d := range deps {
			if d.Ecosystem == ecosystem {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	// Filter to lockfile deps (with versions)
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "lockfile" && d.Requirement != "" {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found to scan.")
		return nil
	}

	var vulnResults []VulnResult
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	if live || db == nil {
		// Live query mode - use OSV API directly
		vulnResults, err = scanLive(lockfileDeps, minSeverity)
		if err != nil {
			return err
		}
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	switch format {
	case "json":
		return outputVulnsJSON(cmd, vulnResults)
	case "sarif":
		return outputVulnsSARIF(cmd, vulnResults)
	default:
		return outputVulnsText(cmd, vulnResults)
	}
}

func scanLive(deps []database.Dependency, minSeverity int) ([]VulnResult, error) {
	client := osv.NewClient()
	queries := make([]osv.QueryRequest, len(deps))
	for i, d := range deps {
		queries[i] = osv.QueryRequest{
			Version: d.Requirement,
			Package: osv.Package{
				Ecosystem: d.Ecosystem,
				Name:      d.Name,
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	results, err := client.BatchQuery(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("querying OSV: %w", err)
	}

	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	var vulnResults []VulnResult

	for i, vulns := range results {
		dep := deps[i]
		for _, v := range vulns {
			sev := osv.GetSeverityLevel(&v)
			if severityOrder[sev] > minSeverity {
				continue
			}

			var refs []string
			for _, r := range v.References {
				refs = append(refs, r.URL)
			}

			fixedVersion := ""
			for _, aff := range v.Affected {
				if strings.EqualFold(aff.Package.Name, dep.Name) {
					fixedVersion = osv.GetFixedVersion(aff)
					break
				}
			}

			vulnResults = append(vulnResults, VulnResult{
				ID:           v.ID,
				Aliases:      v.Aliases,
				Summary:      v.Summary,
				Severity:     sev,
				Package:      dep.Name,
				Ecosystem:    dep.Ecosystem,
				Version:      dep.Requirement,
				FixedVersion: fixedVersion,
				ManifestPath: dep.ManifestPath,
				References:   refs,
			})
		}
	}

	return vulnResults, nil
}

func scanCached(db *database.DB, deps []database.Dependency, minSeverity int) ([]VulnResult, error) {
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
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
	return enc.Encode(results)
}

func outputVulnsText(cmd *cobra.Command, results []VulnResult) error {
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
				if len(summary) > 80 {
					summary = summary[:77] + "..."
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", Dim(summary))
			}
			if v.FixedVersion != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Fixed in: %s\n", Green(v.FixedVersion))
			}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

// SARIF output for integration with CI/CD tools
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	ShortDescription SARIFMessage     `json:"shortDescription"`
	FullDescription  SARIFMessage     `json:"fullDescription,omitempty"`
	Help             SARIFMessage     `json:"help,omitempty"`
	Properties       map[string]any   `json:"properties,omitempty"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func outputVulnsSARIF(cmd *cobra.Command, results []VulnResult) error {
	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "git-pkgs",
						Version:        "1.0.0",
						InformationURI: "https://github.com/git-pkgs/git-pkgs",
					},
				},
			},
		},
	}

	ruleMap := make(map[string]bool)
	for _, r := range results {
		if !ruleMap[r.ID] {
			ruleMap[r.ID] = true
			rule := SARIFRule{
				ID:               r.ID,
				ShortDescription: SARIFMessage{Text: r.Summary},
				Properties: map[string]any{
					"security-severity": severityToScore(r.Severity),
				},
			}
			report.Runs[0].Tool.Driver.Rules = append(report.Runs[0].Tool.Driver.Rules, rule)
		}

		level := "warning"
		if r.Severity == "critical" || r.Severity == "high" {
			level = "error"
		}

		result := SARIFResult{
			RuleID:  r.ID,
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("%s@%s is vulnerable", r.Package, r.Version)},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: r.ManifestPath},
					},
				},
			},
		}
		report.Runs[0].Results = append(report.Runs[0].Results, result)
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func severityToScore(severity string) float64 {
	switch severity {
	case "critical":
		return 9.0
	case "high":
		return 7.0
	case "medium":
		return 4.0
	case "low":
		return 1.0
	default:
		return 0.0
	}
}

// vulns show command
func addVulnsShowCmd(parent *cobra.Command) {
	showCmd := &cobra.Command{
		Use:   "show <vuln-id>",
		Short: "Show details of a vulnerability",
		Long:  `Display detailed information about a specific vulnerability by its ID.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runVulnsShow,
	}

	showCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(showCmd)
}

func runVulnsShow(cmd *cobra.Command, args []string) error {
	vulnID := args[0]
	format, _ := cmd.Flags().GetString("format")

	client := osv.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	vuln, err := client.GetVulnerability(ctx, vulnID)
	if err != nil {
		return fmt.Errorf("fetching vulnerability: %w", err)
	}

	if vuln == nil {
		return fmt.Errorf("vulnerability %q not found", vulnID)
	}

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(vuln)
	}

	// Text output
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", vuln.ID)
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", len(vuln.ID)))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if len(vuln.Aliases) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Aliases: %s\n", strings.Join(vuln.Aliases, ", "))
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Severity: %s\n", osv.GetSeverityLevel(vuln))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Published: %s\n", vuln.Published.Format("2006-01-02"))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Modified: %s\n", vuln.Modified.Format("2006-01-02"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if vuln.Summary != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Summary:\n  %s\n\n", vuln.Summary)
	}

	if vuln.Details != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Details:\n  %s\n\n", vuln.Details)
	}

	if len(vuln.Affected) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Affected packages:")
		for _, aff := range vuln.Affected {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s/%s\n", aff.Package.Ecosystem, aff.Package.Name)
			if fixed := osv.GetFixedVersion(aff); fixed != "" {
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
	}

	return nil
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
	Added   []VulnResult `json:"added"`
	Fixed   []VulnResult `json:"fixed"`
}

func runVulnsDiff(cmd *cobra.Command, args []string) error {
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, _ := cmd.Flags().GetString("format")

	fromRef := "HEAD~1"
	toRef := "HEAD"
	if len(args) >= 1 {
		fromRef = args[0]
	}
	if len(args) >= 2 {
		toRef = args[1]
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get vulnerabilities at both refs
	fromVulns, err := getVulnsAtRef(db, branch.ID, fromRef, ecosystem)
	if err != nil {
		return fmt.Errorf("getting vulns at %s: %w", fromRef, err)
	}

	toVulns, err := getVulnsAtRef(db, branch.ID, toRef, ecosystem)
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
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
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

	if format == "json" {
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

func getVulnsAtRef(db *database.DB, branchID int64, ref, ecosystem string) ([]VulnResult, error) {
	deps, err := db.GetDependenciesAtRef(ref, branchID)
	if err != nil {
		return nil, err
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

	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "lockfile" && d.Requirement != "" {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		return nil, nil
	}

	client := osv.NewClient()
	queries := make([]osv.QueryRequest, len(lockfileDeps))
	for i, d := range lockfileDeps {
		queries[i] = osv.QueryRequest{
			Version: d.Requirement,
			Package: osv.Package{
				Ecosystem: d.Ecosystem,
				Name:      d.Name,
			},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	results, err := client.BatchQuery(ctx, queries)
	if err != nil {
		return nil, err
	}

	var vulnResults []VulnResult
	for i, vulns := range results {
		dep := lockfileDeps[i]
		for _, v := range vulns {
			fixedVersion := ""
			for _, aff := range v.Affected {
				if strings.EqualFold(aff.Package.Name, dep.Name) {
					fixedVersion = osv.GetFixedVersion(aff)
					break
				}
			}

			vulnResults = append(vulnResults, VulnResult{
				ID:           v.ID,
				Summary:      v.Summary,
				Severity:     osv.GetSeverityLevel(&v),
				Package:      dep.Name,
				Ecosystem:    dep.Ecosystem,
				Version:      dep.Requirement,
				FixedVersion: fixedVersion,
				ManifestPath: dep.ManifestPath,
			})
		}
	}

	return vulnResults, nil
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
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get current vulnerabilities
	vulns, err := getVulnsAtRef(db, branch.ID, "HEAD", ecosystem)
	if err != nil {
		return fmt.Errorf("getting vulnerabilities: %w", err)
	}

	// Apply severity filter
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	// Get blame information for each vulnerable package
	blameData, err := db.GetBlame(branch.ID, ecosystem)
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

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Added in %s\n", e.AddedCommit[:7])
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
	logCmd.Flags().Int("limit", 20, "Maximum commits to check")
	logCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(logCmd)
}

type VulnLogEntry struct {
	SHA         string       `json:"sha"`
	Message     string       `json:"message"`
	Author      string       `json:"author"`
	Date        string       `json:"date"`
	Introduced  []VulnResult `json:"introduced,omitempty"`
	Fixed       []VulnResult `json:"fixed,omitempty"`
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
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No commits with dependency changes found.")
		return nil
	}

	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var entries []VulnLogEntry
	var prevVulns []VulnResult

	for i, c := range commits {
		// Get vulns at this commit
		currentVulns, err := getVulnsAtRef(db, branch.ID, c.SHA, ecosystem)
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

	if len(entries) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerability changes found in recent commits.")
		return nil
	}

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability changes in %d commits:\n\n", len(entries))

	for _, e := range entries {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s (%s)\n", e.SHA[:7], e.Message, e.Author)

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
	historyCmd.Flags().Int("limit", 50, "Maximum commits to check")
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
	packageName := args[0]
	branchName, _ := cmd.Flags().GetString("branch")
	limit, _ := cmd.Flags().GetInt("limit")
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get commits with changes
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID: branch.ID,
		Limit:    limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	client := osv.NewClient()
	var history []VulnHistoryEntry

	for _, c := range commits {
		deps, err := db.GetDependenciesAtRef(c.SHA, branch.ID)
		if err != nil {
			continue
		}

		// Find the package in deps
		var pkgDep *database.Dependency
		for _, d := range deps {
			if strings.EqualFold(d.Name, packageName) && d.ManifestKind == "lockfile" {
				pkgDep = &d
				break
			}
		}

		if pkgDep == nil {
			continue
		}

		// Query for vulnerabilities
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		queries := []osv.QueryRequest{{
			Version: pkgDep.Requirement,
			Package: osv.Package{
				Ecosystem: pkgDep.Ecosystem,
				Name:      pkgDep.Name,
			},
		}}

		results, err := client.BatchQuery(ctx, queries)
		cancel()
		if err != nil {
			continue
		}

		entry := VulnHistoryEntry{
			SHA:     c.SHA,
			Date:    c.CommittedAt,
			Version: pkgDep.Requirement,
		}

		if len(results) > 0 {
			for _, v := range results[0] {
				entry.Vulnerabilities = append(entry.Vulnerabilities, VulnResult{
					ID:       v.ID,
					Summary:  v.Summary,
					Severity: osv.GetSeverityLevel(&v),
				})
			}
		}

		history = append(history, entry)
	}

	if len(history) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in commit history.\n", packageName)
		return nil
	}

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(history)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Vulnerability history for %s:\n\n", packageName)

	for _, h := range history {
		date := h.Date[:10]
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %s", h.SHA[:7], date, h.Version)
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
	exposureCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	exposureCmd.Flags().StringP("severity", "s", "", "Minimum severity: critical, high, medium, low")
	exposureCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	exposureCmd.Flags().Bool("summary", false, "Show aggregate metrics only")
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
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	severity, _ := cmd.Flags().GetString("severity")
	format, _ := cmd.Flags().GetString("format")
	summary, _ := cmd.Flags().GetBool("summary")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get current vulnerabilities
	vulns, err := getVulnsAtRef(db, branch.ID, "HEAD", ecosystem)
	if err != nil {
		return fmt.Errorf("getting vulnerabilities: %w", err)
	}

	// Apply severity filter
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerabilities found.")
		return nil
	}

	// Get blame info to find when each package was introduced
	blameData, err := db.GetBlame(branch.ID, ecosystem)
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
		return entries[i].ExposureDays > entries[j].ExposureDays
	})

	if summary {
		return outputExposureSummary(cmd, entries, format)
	}

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
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

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Vulnerability Exposure Summary")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 30))
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
	praiseCmd.Flags().Int("limit", 50, "Maximum commits to check")
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
	format, _ := cmd.Flags().GetString("format")
	summary, _ := cmd.Flags().GetBool("summary")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
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

	// Get commits with changes
	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID:  branch.ID,
		Ecosystem: ecosystem,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	if len(commits) < 2 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Not enough commits to analyze vulnerability fixes.")
		return nil
	}

	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
	minSeverity := 4
	if severity != "" {
		if order, ok := severityOrder[strings.ToLower(severity)]; ok {
			minSeverity = order
		}
	}

	var entries []VulnPraiseEntry
	var prevVulns []VulnResult

	for i, c := range commits {
		currentVulns, err := getVulnsAtRef(db, branch.ID, c.SHA, ecosystem)
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
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No vulnerability fixes found in recent commits.")
		return nil
	}

	if summary {
		return outputPraiseSummary(cmd, entries, format)
	}

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
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
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    Fixed in %s on %s\n", e.FixedIn[:7], e.FixedDate[:10])
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

type PraiseAuthorSummary struct {
	Author        string         `json:"author"`
	TotalFixes    int            `json:"total_fixes"`
	BySeverity    map[string]int `json:"by_severity"`
	UniquePackages int           `json:"unique_packages"`
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
		return summary.Authors[i].TotalFixes > summary.Authors[j].TotalFixes
	})

	if format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(summary)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Vulnerability Fix Leaderboard")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 30))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Total fixes: %d\n\n", summary.TotalFixes)

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Rank  Author                    Fixes  Critical  High  Packages")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 70))

	for i, a := range summary.Authors {
		authorName := a.Author
		if len(authorName) > 24 {
			authorName = authorName[:21] + "..."
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
