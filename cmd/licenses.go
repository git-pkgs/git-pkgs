package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addLicensesCmd(rootCmd)
}

func addLicensesCmd(parent *cobra.Command) {
	licensesCmd := &cobra.Command{
		Use:   "licenses",
		Short: "Show license information for dependencies",
		Long: `Query the ecosyste.ms API to retrieve license information
for all dependencies in the project.`,
		RunE: runLicenses,
	}

	licensesCmd.Flags().StringP("commit", "c", "", "Check licenses at specific commit (default: HEAD)")
	licensesCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	licensesCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	licensesCmd.Flags().StringP("format", "f", "text", "Output format: text, json, csv")
	licensesCmd.Flags().StringSlice("allow", nil, "Only allow these licenses (exit 1 on violation)")
	licensesCmd.Flags().StringSlice("deny", nil, "Deny these licenses (exit 1 if found)")
	licensesCmd.Flags().Bool("permissive", false, "Flag non-permissive licenses")
	licensesCmd.Flags().Bool("copyleft", false, "Flag copyleft licenses (GPL, AGPL)")
	licensesCmd.Flags().Bool("unknown", false, "Flag packages with unknown licenses")
	licensesCmd.Flags().Bool("group", false, "Group output by license")
	licensesCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
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

var permissiveLicenses = map[string]bool{
	"MIT":           true,
	"MIT License":   true,
	"Apache-2.0":    true,
	"Apache 2.0":    true,
	"BSD-2-Clause":  true,
	"BSD-3-Clause":  true,
	"ISC":           true,
	"0BSD":          true,
	"CC0-1.0":       true,
	"Unlicense":     true,
	"WTFPL":         true,
	"Zlib":          true,
	"PostgreSQL":    true,
	"BlueOak-1.0.0": true,
}

var copyleftLicenses = map[string]bool{
	"GPL-2.0":      true,
	"GPL-3.0":      true,
	"LGPL-2.0":     true,
	"LGPL-2.1":     true,
	"LGPL-3.0":     true,
	"AGPL-3.0":     true,
	"MPL-2.0":      true,
	"EPL-1.0":      true,
	"EPL-2.0":      true,
	"CDDL-1.0":     true,
	"GPL-2.0-only": true,
	"GPL-3.0-only": true,
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

	// Filter to manifest dependencies (direct deps)
	var directDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "manifest" {
			directDeps = append(directDeps, d)
		}
	}

	if len(directDeps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No direct dependencies found.")
		return nil
	}

	// Build PURLs
	purls := make([]string, 0, len(directDeps))
	purlToDep := make(map[string]database.Dependency)
	for _, d := range directDeps {
		purl := d.PURL
		if purl == "" {
			purl = buildPURL(d.Ecosystem, d.Name)
		}
		if purl != "" {
			purls = append(purls, purl)
			purlToDep[purl] = d
		}
	}

	// Get license data (from cache or API)
	packageData, err := getLicenseData(db, purls, purlToDep)
	if err != nil {
		return fmt.Errorf("looking up packages: %w", err)
	}

	// Build allow/deny sets
	allowSet := make(map[string]bool)
	for _, l := range allowList {
		allowSet[strings.ToLower(l)] = true
	}
	denySet := make(map[string]bool)
	for _, l := range denyList {
		denySet[strings.ToLower(l)] = true
	}

	// Build license info
	var licenseInfos []LicenseInfo
	hasViolations := false

	for purl, data := range packageData {
		dep := purlToDep[purl]

		info := LicenseInfo{
			Name:         dep.Name,
			Ecosystem:    dep.Ecosystem,
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
				licLower := strings.ToLower(lic)

				// Check allow list
				if len(allowSet) > 0 && !allowSet[licLower] {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q not in allow list", lic)
					hasViolations = true
				}

				// Check deny list
				if denySet[licLower] {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q is denied", lic)
					hasViolations = true
				}

				// Check permissive
				if flagPermissive && !permissiveLicenses[lic] {
					info.Flagged = true
					info.FlagReason = fmt.Sprintf("license %q is not permissive", lic)
					hasViolations = true
				}

				// Check copyleft
				if flagCopyleft && copyleftLicenses[lic] {
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
		return licenseInfos[i].Name < licenseInfos[j].Name
	})

	switch format {
	case "json":
		err = outputLicensesJSON(cmd, licenseInfos)
	case "csv":
		err = outputLicensesCSV(cmd, licenseInfos)
	default:
		if groupBy {
			err = outputLicensesGrouped(cmd, licenseInfos)
		} else {
			err = outputLicensesText(cmd, licenseInfos)
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

type licenseData struct {
	License string
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
			result[purl] = &licenseData{License: cp.License}
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
		client, err := ecosystems.NewClient("git-pkgs/1.0")
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
			data := &licenseData{}
			if pkg != nil {
				if len(pkg.NormalizedLicenses) > 0 {
					data.License = pkg.NormalizedLicenses[0]
				} else if pkg.Licenses != nil && *pkg.Licenses != "" {
					data.License = *pkg.Licenses
				}
			}
			result[purl] = data

			// Save to cache if DB available
			if db != nil {
				dep := purlToDep[purl]
				latestVersion := ""
				if pkg != nil && pkg.LatestReleaseNumber != nil {
					latestVersion = *pkg.LatestReleaseNumber
				}
				_ = db.SavePackageEnrichment(purl, dep.Ecosystem, dep.Name, latestVersion, data.License)
			}
		}
	}

	return result, nil
}

func outputLicensesJSON(cmd *cobra.Command, infos []LicenseInfo) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(infos)
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
			flagged = "yes"
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

func outputLicensesText(cmd *cobra.Command, infos []LicenseInfo) error {
	for _, info := range infos {
		licenses := strings.Join(info.Licenses, ", ")
		line := fmt.Sprintf("%s (%s): %s", info.Name, info.Ecosystem, licenses)
		if info.Flagged {
			line += fmt.Sprintf(" [FLAGGED: %s]", info.FlagReason)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
	}
	return nil
}

func outputLicensesGrouped(cmd *cobra.Command, infos []LicenseInfo) error {
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

	return nil
}
