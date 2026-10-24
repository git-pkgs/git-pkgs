package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/manifests"
	"github.com/spf13/cobra"
)

func addDiffFileCmd(parent *cobra.Command) {
	diffFileCmd := &cobra.Command{
		Use:   "diff-file [from] [to]",
		Short: "Compare dependencies and declared licenses between two files",
		Args:  cobra.ExactArgs(2),
		RunE:  runDiffFile,
	}

	diffFileCmd.Flags().String("filename", "", "Filename used to determine the manifest type.")
	diffFileCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(diffFileCmd)
}

func runDiffFile(cmd *cobra.Command, args []string) error {
	defaultFilename, _ := cmd.Flags().GetString("filename")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	fromFile, err := parseFile(args[0], defaultFilename)
	if err != nil {
		return err
	}
	toFile, err := parseFile(args[1], defaultFilename)
	if err != nil {
		return err
	}

	result := computeDiff(fromFile.Dependencies, toFile.Dependencies)
	fromLicenses := sortedUniqueLicenses(fromFile.Licenses)
	toLicenses := sortedUniqueLicenses(toFile.Licenses)
	if !slices.Equal(fromLicenses, toLicenses) {
		result.LicenseChanges = []DeclaredLicenseChange{{
			ManifestPath: toFile.ManifestPath,
			FromLicenses: fromLicenses,
			ToLicenses:   toLicenses,
		}}
	}

	switch format {
	case formatJSON:
		return outputDiffJSON(cmd, result)
	default:
		return outputDiffText(cmd, result)
	}
}

type parsedDiffFile struct {
	Dependencies []database.Dependency
	Licenses     []string
	ManifestPath string
}

func parseFile(filename, defaultFilename string) (parsedDiffFile, error) {
	name := defaultFilename
	if name == "" {
		name = filepath.Base(filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return parsedDiffFile{}, err
	}
	if len(data) == 0 {
		return parsedDiffFile{ManifestPath: name}, nil
	}

	// Use defaultFilename as-is if provided (preserves path for manifest identification)
	// Otherwise use base name of the actual file
	result, err := manifests.Parse(name, data)
	if err != nil {
		return parsedDiffFile{}, err
	}

	var deps []database.Dependency
	for _, dep := range result.Dependencies {
		deps = append(deps, database.Dependency{
			Name:           dep.Name,
			Ecosystem:      dep.Ecosystem,
			Requirement:    dep.Version,
			ManifestPath:   name,
			DependencyType: string(dep.Scope),
		})
	}
	return parsedDiffFile{
		Dependencies: deps,
		Licenses:     result.Licenses,
		ManifestPath: name,
	}, nil
}

func sortedUniqueLicenses(licenses []string) []string {
	result := make([]string, 0, len(licenses))
	seen := make(map[string]bool, len(licenses))
	for _, license := range licenses {
		license = normalizeLicenseString(license)
		if license == "" || seen[license] {
			continue
		}
		seen[license] = true
		result = append(result, license)
	}
	sort.Strings(result)
	return result
}
