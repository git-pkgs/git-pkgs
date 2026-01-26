package cmd

import (
	"cmp"
	"os"
	"path/filepath"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/manifests"
	"github.com/spf13/cobra"
)

func addDiffFileCmd(parent *cobra.Command) {
	diffFileCmd := &cobra.Command{
		Use:   "diff-file [from] [to]",
		Short: "Compare dependencies between two files",
		Args:  cobra.ExactArgs(2),
		RunE:  runDiffFile,
	}

	diffFileCmd.Flags().String("filename", "", "Filename used to determine the manifest type.")
	diffFileCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(diffFileCmd)
}

func runDiffFile(cmd *cobra.Command, args []string) error {
	defaultFilename, _ := cmd.Flags().GetString("filename")
	format, _ := cmd.Flags().GetString("format")

	fromDeps, err := parseFile(args[0], defaultFilename)
	if err != nil {
		return err
	}
	toDeps, err := parseFile(args[1], defaultFilename)
	if err != nil {
		return err
	}

	result := computeDiff(fromDeps, toDeps)

	switch format {
	case "json":
		return outputDiffJSON(cmd, result)
	default:
		return outputDiffText(cmd, result)
	}
}

func parseFile(filename, defaultFilename string) ([]database.Dependency, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	name := filepath.Base(cmp.Or(defaultFilename, filename))
	result, err := manifests.Parse(name, data)
	if err != nil {
		return nil, err
	}

	var deps []database.Dependency
	for _, dep := range result.Dependencies {
		deps = append(deps, database.Dependency{
			Name:           dep.Name,
			Ecosystem:      result.Ecosystem,
			Requirement:    dep.Version,
			ManifestPath:   name,
			DependencyType: string(dep.Scope),
		})
	}
	return deps, nil
}
