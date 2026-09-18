package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/changelog"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	gogit "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/spf13/cobra"
)

func addChangelogCmd(parent *cobra.Command) {
	changelogCmd := &cobra.Command{
		Use:   "changelog <package>",
		Short: "Show changelog entries for a package",
		Long: `Fetch and display changelog entries for a package between two versions.

Uses the ecosyste.ms API to locate the package's repository and changelog file,
then parses entries between the specified versions.
If --from is omitted, the version in a PURL argument or the unique installed
version at HEAD supplies the lower bound. Use --from to resolve multiple
installed versions, or --from= to request an open lower bound.

Examples:
  git-pkgs changelog lodash -e npm --from 4.17.20 --to 4.17.21
  git-pkgs changelog pkg:cargo/serde --from 1.0.0 --to 1.0.200
  git-pkgs changelog express -e npm`,
		Args: cobra.ExactArgs(1),
		RunE: runChangelog,
	}

	changelogCmd.Flags().String("from", "", "Current/old version (defaults to PURL or installed version)")
	changelogCmd.Flags().String("to", "", "Target/new version (defaults to latest)")
	changelogCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	changelogCmd.Flags().StringP("manager", "m", "", "Override package manager (for ecosystem detection)")
	changelogCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(changelogCmd)
}

type ChangelogEntry struct {
	Version string `json:"version"`
	Content string `json:"content"`
}

type ChangelogResult struct {
	Package           string           `json:"package"`
	Ecosystem         string           `json:"ecosystem"`
	From              string           `json:"from"`
	To                string           `json:"to"`
	Repository        string           `json:"repository"`
	ChangelogFilename string           `json:"changelog_filename"`
	Entries           []ChangelogEntry `json:"entries"`
}

func runChangelog(cmd *cobra.Command, args []string) error {
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")
	fromVersion, _ := cmd.Flags().GetString("from")
	toVersion, _ := cmd.Flags().GetString("to")
	managerFlag, _ := cmd.Flags().GetString("manager")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	ecosystem, pkg, packageVersion, err := ParsePackageArg(args[0], ecosystemFlag)
	if err != nil {
		return err
	}

	// Detect ecosystem from working directory if not provided
	if ecosystem == "" {
		ecosystem, err = detectEcosystem(managerFlag)
		if err != nil {
			return fmt.Errorf("could not determine ecosystem: %w\n\nUse -e to specify the ecosystem or pass a PURL", err)
		}
	}

	if !cmd.Flags().Changed("from") {
		fromVersion = packageVersion
		if fromVersion == "" {
			fromVersion, err = installedChangelogVersion(ecosystem, pkg)
			if err != nil {
				return err
			}
		}
	}

	purlStr := purl.MakePURLString(ecosystem, pkg, "")
	if purlStr == "" {
		return fmt.Errorf("could not build PURL for %s/%s", ecosystem, pkg)
	}

	const changelogTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), changelogTimeout)
	defer cancel()

	client, err := newEnrichmentClient()
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	packages, err := client.BulkLookup(ctx, []string{purlStr})
	if err != nil {
		return fmt.Errorf("looking up package: %w", wrapEcosystemsError(err))
	}
	pkgInfo := packages[purlStr]
	if pkgInfo == nil {
		return fmt.Errorf("package not found: %s", purlStr)
	}

	if toVersion == "" && pkgInfo.LatestVersion != "" {
		toVersion = pkgInfo.LatestVersion
	}

	if pkgInfo.ChangelogFilename == "" {
		return fmt.Errorf("no changelog found for %s", pkg)
	}

	if pkgInfo.Repository == "" {
		return fmt.Errorf("no repository URL found for %s", pkg)
	}

	parser, err := changelog.FetchAndParse(ctx, pkgInfo.Repository, pkgInfo.ChangelogFilename)
	if err != nil {
		return fmt.Errorf("fetching changelog: %w", err)
	}

	if format == formatJSON {
		result := buildChangelogResult(
			parser,
			pkg,
			ecosystem,
			fromVersion,
			toVersion,
			pkgInfo.Repository,
			pkgInfo.ChangelogFilename,
		)
		return outputChangelogJSON(cmd, result)
	}

	if fromVersion != "" || toVersion != "" {
		between, ok := parser.Between(fromVersion, toVersion)
		if !ok {
			return fmt.Errorf("no changelog entries found between %s and %s", fromVersion, toVersion)
		}
		_, _ = fmt.Fprint(cmd.OutOrStdout(), Sanitize(between))
		if !strings.HasSuffix(between, "\n") {
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
		return nil
	}

	// No version range specified: print all versions and their entries
	versions := parser.Versions()
	if len(versions) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No changelog entries found.")
		return nil
	}

	for _, v := range versions {
		entry, ok := parser.Entry(v)
		if !ok {
			continue
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "## %s\n", Sanitize(v))
		if entry.Content != "" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), Sanitize(entry.Content))
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

func buildChangelogResult(
	parser *changelog.Parser,
	packageName string,
	ecosystem string,
	fromVersion string,
	toVersion string,
	repository string,
	changelogFilename string,
) *ChangelogResult {
	result := &ChangelogResult{
		Package:           packageName,
		Ecosystem:         ecosystem,
		From:              fromVersion,
		To:                toVersion,
		Repository:        repository,
		ChangelogFilename: changelogFilename,
		Entries:           []ChangelogEntry{},
	}

	versions := parser.Versions()
	if fromVersion != "" || toVersion != "" {
		versions = parser.VersionsBetween(fromVersion, toVersion)
	}

	for _, version := range versions {
		entry, ok := parser.Entry(version)
		if !ok {
			continue
		}
		result.Entries = append(result.Entries, ChangelogEntry{
			Version: version,
			Content: entry.Content,
		})
	}

	return result
}

func outputChangelogJSON(cmd *cobra.Command, result *ChangelogResult) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func detectEcosystem(managerFlag string) (string, error) {
	dir, err := getWorkingDir()
	if err != nil {
		return "", err
	}

	detected, err := DetectManagers(dir)
	if err != nil {
		return "", err
	}

	if managerFlag != "" {
		for _, d := range detected {
			if d.Name == managerFlag {
				return d.Ecosystem, nil
			}
		}
		// Manager flag didn't match any detected manager, check config
		for _, eco := range ecosystemConfigs {
			if eco.Default == managerFlag {
				return eco.Ecosystem, nil
			}
			for _, lf := range eco.Lockfiles {
				if lf.Manager == managerFlag {
					return eco.Ecosystem, nil
				}
			}
		}
		return "", fmt.Errorf("unknown manager: %s", managerFlag)
	}

	if len(detected) == 0 {
		return "", fmt.Errorf("no package manager detected in %s", dir)
	}

	return detected[0].Ecosystem, nil
}

// installedChangelogVersion only infers exact versions represented in dependency
// PURLs; manifest requirements such as ^1.0 are not installed versions.
func installedChangelogVersion(ecosystem, name string) (string, error) {
	repo, err := git.OpenRepository(".")
	if errors.Is(err, gogit.ErrRepositoryNotExists) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("finding installed version: %w", err)
	}
	deps, err := repo.GetDependencies("HEAD", "")
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("finding installed version: %w", err)
	}
	versions := make(map[string]map[string]bool)
	for _, dep := range deps {
		if !strings.EqualFold(dep.Ecosystem, ecosystem) || dep.Name != name {
			continue
		}
		parsed, err := purl.Parse(dep.PURL)
		if err != nil || parsed.Version == "" {
			continue
		}
		if versions[parsed.Version] == nil {
			versions[parsed.Version] = make(map[string]bool)
		}
		versions[parsed.Version][dep.ManifestPath] = true
	}
	if len(versions) == 0 {
		return "", nil
	}
	if len(versions) == 1 {
		for version := range versions {
			return version, nil
		}
	}
	var choices []string
	for version, manifests := range versions {
		var paths []string
		for manifest := range manifests {
			paths = append(paths, manifest)
		}
		sort.Strings(paths)
		choices = append(choices, fmt.Sprintf("%s (%s)", version, strings.Join(paths, ", ")))
	}
	sort.Strings(choices)
	return "", fmt.Errorf("multiple installed versions of %s: %s; specify --from", name, strings.Join(choices, "; "))
}
