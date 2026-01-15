package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/vers"
	"github.com/spf13/cobra"
)

func init() {
	addOutdatedCmd(rootCmd)
}

func addOutdatedCmd(parent *cobra.Command) {
	outdatedCmd := &cobra.Command{
		Use:   "outdated",
		Short: "Find packages with newer versions available",
		Long: `Check dependencies against the ecosyste.ms API to find packages
with newer versions available.`,
		RunE: runOutdated,
	}

	outdatedCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	outdatedCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	outdatedCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	outdatedCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	outdatedCmd.Flags().Bool("major", false, "Only show major version updates")
	outdatedCmd.Flags().Bool("minor", false, "Skip patch-only updates")
	outdatedCmd.Flags().String("at", "", "Check what was outdated at this date (YYYY-MM-DD)")
	outdatedCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
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

func runOutdated(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	majorOnly, _ := cmd.Flags().GetBool("major")
	minorUp, _ := cmd.Flags().GetBool("minor")
	atDate, _ := cmd.Flags().GetString("at")
	stateless, _ := cmd.Flags().GetBool("stateless")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var deps []database.Dependency

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

		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer func() { _ = db.Close() }()

		// Get branch info
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

		// Get dependencies
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

	// Filter to lockfile dependencies only (those with versions)
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "lockfile" && d.Requirement != "" {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No lockfile dependencies found.")
		return nil
	}

	// Build PURLs for lookup
	purls := make([]string, 0, len(lockfileDeps))
	purlToDep := make(map[string]database.Dependency)
	for _, d := range lockfileDeps {
		purl := d.PURL
		if purl == "" {
			// Build PURL from ecosystem and name
			purl = buildPURL(d.Ecosystem, d.Name)
		}
		if purl != "" {
			purls = append(purls, purl)
			purlToDep[purl] = d
		}
	}

	// Create ecosystems client
	client, err := ecosystems.NewClient("git-pkgs/1.0")
	if err != nil {
		return fmt.Errorf("creating ecosystems client: %w", err)
	}

	// Lookup packages
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	packages, err := client.BulkLookup(ctx, purls)
	if err != nil {
		return fmt.Errorf("looking up packages: %w", err)
	}

	// Parse --at date if provided
	var atTime time.Time
	if atDate != "" {
		atTime, err = time.Parse("2006-01-02", atDate)
		if err != nil {
			return fmt.Errorf("invalid date format (use YYYY-MM-DD): %w", err)
		}
	}

	// Compare versions
	var outdated []OutdatedPackage
	for purl, pkg := range packages {
		if pkg == nil || pkg.LatestReleaseNumber == nil {
			continue
		}

		dep := purlToDep[purl]
		current := dep.Requirement
		latest := *pkg.LatestReleaseNumber

		// If --at is specified, find the latest version at that date
		if !atTime.IsZero() {
			latest = findLatestAtDate(client, ctx, pkg.Ecosystem, pkg.Name, atTime)
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
		if majorOnly && updateType != "major" {
			continue
		}
		if minorUp && updateType == "patch" {
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

	if len(outdated) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All dependencies are up to date.")
		return nil
	}

	if format == "json" {
		return outputOutdatedJSON(cmd, outdated)
	}
	return outputOutdatedText(cmd, outdated)
}

func buildPURL(ecosystem, name string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "pkg:npm/" + name
	case "gem", "rubygems":
		return "pkg:gem/" + name
	case "pypi":
		return "pkg:pypi/" + name
	case "cargo":
		return "pkg:cargo/" + name
	case "go", "golang":
		return "pkg:golang/" + name
	case "maven":
		return "pkg:maven/" + name
	case "nuget":
		return "pkg:nuget/" + name
	case "composer", "packagist":
		return "pkg:composer/" + name
	case "hex":
		return "pkg:hex/" + name
	case "pub":
		return "pkg:pub/" + name
	case "cocoapods":
		return "pkg:cocoapods/" + name
	default:
		return ""
	}
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
		return "major"
	}
	if latestInfo.Minor > currentInfo.Minor {
		return "minor"
	}
	if latestInfo.Patch > currentInfo.Patch {
		return "patch"
	}

	// Handle prerelease upgrades
	if currentInfo.Prerelease != "" && latestInfo.Prerelease == "" {
		return "patch"
	}

	return ""
}

func findLatestAtDate(client *ecosystems.Client, ctx context.Context, ecosystem, name string, atTime time.Time) string {
	// Get registry from ecosystem
	registry := ecosystemToRegistry(ecosystem)
	if registry == "" {
		return ""
	}

	versions, err := client.GetAllVersions(ctx, registry, name)
	if err != nil {
		return ""
	}

	var latestVersion string
	var latestTime time.Time

	for _, v := range versions {
		if v.PublishedAt == nil {
			continue
		}
		publishedAt, err := time.Parse(time.RFC3339, *v.PublishedAt)
		if err != nil {
			continue
		}
		if !publishedAt.After(atTime) {
			if latestVersion == "" || publishedAt.After(latestTime) {
				latestVersion = v.Number
				latestTime = publishedAt
			}
		}
	}

	return latestVersion
}

func ecosystemToRegistry(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npmjs.org"
	case "gem", "rubygems":
		return "rubygems.org"
	case "pypi":
		return "pypi.org"
	case "cargo":
		return "crates.io"
	case "go", "golang":
		return "proxy.golang.org"
	case "maven":
		return "repo1.maven.org"
	case "nuget":
		return "nuget.org"
	case "composer", "packagist":
		return "packagist.org"
	case "hex":
		return "hex.pm"
	case "pub":
		return "pub.dev"
	case "cocoapods":
		return "cocoapods.org"
	default:
		return ""
	}
}

func outputOutdatedJSON(cmd *cobra.Command, outdated []OutdatedPackage) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(outdated)
}

func outputOutdatedText(cmd *cobra.Command, outdated []OutdatedPackage) error {
	// Group by update type
	var major, minor, patch []OutdatedPackage
	for _, o := range outdated {
		switch o.UpdateType {
		case "major":
			major = append(major, o)
		case "minor":
			minor = append(minor, o)
		case "patch":
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

	return nil
}
