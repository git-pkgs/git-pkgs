package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/git-pkgs/changelog"
	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/purl"
	"github.com/spf13/cobra"
)

func addChangelogCmd(parent *cobra.Command) {
	changelogCmd := &cobra.Command{
		Use:   "changelog <package>",
		Short: "Show changelog entries for a package",
		Long: `Fetch and display changelog entries for a package between two versions.

Uses the ecosyste.ms API to locate the package's repository and changelog file,
then parses entries between the specified versions.

Examples:
  git-pkgs changelog lodash -e npm --from 4.17.20 --to 4.17.21
  git-pkgs changelog pkg:cargo/serde --from 1.0.0 --to 1.0.200
  git-pkgs changelog express -e npm`,
		Args: cobra.ExactArgs(1),
		RunE: runChangelog,
	}

	changelogCmd.Flags().String("from", "", "Current/old version")
	changelogCmd.Flags().String("to", "", "Target/new version (defaults to latest)")
	changelogCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	changelogCmd.Flags().StringP("manager", "m", "", "Override package manager (for ecosystem detection)")
	parent.AddCommand(changelogCmd)
}

func runChangelog(cmd *cobra.Command, args []string) error {
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")
	fromVersion, _ := cmd.Flags().GetString("from")
	toVersion, _ := cmd.Flags().GetString("to")
	managerFlag, _ := cmd.Flags().GetString("manager")

	ecosystem, pkg, _, err := ParsePackageArg(args[0], ecosystemFlag)
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

	purlStr := purl.MakePURLString(ecosystem, pkg, "")
	if purlStr == "" {
		return fmt.Errorf("could not build PURL for %s/%s", ecosystem, pkg)
	}

	const changelogTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), changelogTimeout)
	defer cancel()

	client, err := enrichment.NewClient(enrichment.WithUserAgent("git-pkgs/" + version))
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	packages, err := client.BulkLookup(ctx, []string{purlStr})
	if err != nil {
		return fmt.Errorf("looking up package: %w", err)
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
