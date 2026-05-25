package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/spf13/cobra"
)

func addUrlsCmd(parent *cobra.Command) {
	urlsCmd := &cobra.Command{
		Use:   "urls <package>",
		Short: "Show registry URLs for a package",
		Long: `Display all known URLs for a package: registry page, download, documentation, and PURL.

The package can be specified as a PURL (pkg:cargo/serde@1.0.0) or as a plain
package name. When using a plain name, the database is searched for a matching
dependency and the ecosystem and version are inferred from it.

Examples:
  git-pkgs urls pkg:cargo/serde@1.0.0
  git-pkgs urls lodash --ecosystem npm
  git-pkgs urls pkg:npm/express@4.19.0 --format json`,
		Args: cobra.ExactArgs(1),
		RunE: runUrls,
	}

	urlsCmd.Flags().StringP("ecosystem", "e", "", "Filter/specify ecosystem (used for name lookups)")
	urlsCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(urlsCmd)
}

func runUrls(cmd *cobra.Command, args []string) error {
	pkg := args[0]
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")

	var purlType, name, version string

	if IsPURL(pkg) {
		p, err := purl.Parse(pkg)
		if err != nil {
			return fmt.Errorf("parsing purl: %w", err)
		}
		purlType = p.Type
		name = p.FullName()
		version = p.Version
	} else {
		var err error
		purlType, name, version, err = lookupPackage(pkg, ecosystem)
		if err != nil {
			return err
		}
	}

	reg, err := registries.New(purlType, "", nil)
	if err != nil {
		return fmt.Errorf("unsupported ecosystem %q: %w", purlType, err)
	}

	urls := registries.BuildURLs(reg.URLs(), name, version)

	switch format {
	case formatJSON:
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(urls)
	default:
		return outputUrlsText(cmd, urls)
	}
}

func outputUrlsText(cmd *cobra.Command, urls map[string]string) error {
	keys := make([]string, 0, len(urls))
	for k := range urls {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s\n", k, urls[k])
	}
	return nil
}

func lookupPackage(name, ecosystem string) (purlType, pkgName, version string, err error) {
	_, db, err := openDatabase()
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return "", "", "", fmt.Errorf("getting branch: %w", err)
	}

	results, err := db.SearchDependencies(branchInfo.ID, name, ecosystem, false)
	if err != nil {
		return "", "", "", fmt.Errorf("searching dependencies: %w", err)
	}

	if len(results) == 0 {
		if ecosystem != "" {
			return "", "", "", fmt.Errorf("no %s dependency matching %q found", ecosystem, name)
		}
		return "", "", "", fmt.Errorf("no dependency matching %q found", name)
	}

	// Filter to exact name matches if any exist
	var exact []struct{ eco, req string }
	for _, r := range results {
		if strings.EqualFold(r.Name, name) {
			exact = append(exact, struct{ eco, req string }{r.Ecosystem, r.Requirement})
		}
	}

	if len(exact) == 0 {
		// No exact match, use the first result
		exact = append(exact, struct{ eco, req string }{results[0].Ecosystem, results[0].Requirement})
	}

	// Deduplicate by ecosystem
	seen := make(map[string]bool)
	var unique []struct{ eco, req string }
	for _, e := range exact {
		if !seen[e.eco] {
			seen[e.eco] = true
			unique = append(unique, e)
		}
	}

	if len(unique) > 1 && ecosystem == "" {
		ecos := make([]string, len(unique))
		for i, u := range unique {
			ecos[i] = u.eco
		}
		return "", "", "", fmt.Errorf("ambiguous: %q found in multiple ecosystems (%s). Use --ecosystem to specify", name, strings.Join(ecos, ", "))
	}

	match := unique[0]
	pt := purl.EcosystemToPURLType(match.eco)
	return pt, name, match.req, nil
}
