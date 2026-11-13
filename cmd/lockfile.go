package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/manifests"
	"github.com/spf13/cobra"
)

// addLockfileFlag registers --lockfile, which reads dependencies from a local
// file instead of the repository.
func addLockfileFlag(cmd *cobra.Command) {
	cmd.Flags().String("lockfile", "", "Read dependencies from a local lockfile instead of the repository")
	cmd.MarkFlagsMutuallyExclusive("lockfile", "commit")
	cmd.MarkFlagsMutuallyExclusive("lockfile", "branch")
}

// loadDependencies returns the dependencies named by --lockfile when it is
// set, or the repository's dependencies at commit on branchName. The database
// is nil for a lockfile.
func loadDependencies(cmd *cobra.Command, commit, branchName string) ([]database.Dependency, *database.DB, error) {
	if path, _ := cmd.Flags().GetString("lockfile"); path != "" {
		deps, err := parseLockfile(path)
		return deps, nil, err
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return nil, nil, fmt.Errorf("not in a git repository: %w", err)
	}
	deps, db, err := repo.GetDependenciesWithDB(commit, branchName)
	if err != nil {
		return nil, db, fmt.Errorf("loading dependencies: %w", err)
	}
	return deps, db, nil
}

// parseLockfile reads the dependencies of a lockfile on disk. The file is
// identified by its base name, so it must keep its standard name.
func parseLockfile(path string) ([]database.Dependency, error) {
	name := filepath.Base(path)
	ecosystem, kind, ok := manifests.Identify(name)
	if !ok {
		return nil, fmt.Errorf("unrecognized lockfile %s", path)
	}
	if kind == manifests.Supplement || !hasResolvedRequirement(ecosystem, string(kind)) {
		return nil, fmt.Errorf("%s does not list resolved versions; pass a lockfile such as poetry.lock or package-lock.json", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	result, err := manifests.Parse(name, data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if result.Kind != manifests.Lockfile && result.Ecosystem == "maven" {
		for _, dep := range result.Dependencies {
			if isMavenVersionRange(dep.Version) {
				return nil, fmt.Errorf("%s declares version %q for %s rather than a resolved version; pass a lockfile such as gradle.lockfile",
					path, dep.Version, dep.Name)
			}
		}
	}

	deps := make([]database.Dependency, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		deps = append(deps, database.Dependency{
			Name:           dep.Name,
			Ecosystem:      result.Ecosystem,
			PURL:           dep.PURL,
			Requirement:    dep.Version,
			DependencyType: string(dep.Scope),
			Integrity:      dep.Integrity,
			ManifestPath:   path,
			ManifestKind:   string(result.Kind),
			Direct:         dep.Direct,
		})
	}
	return deps, nil
}

// isMavenVersionRange reports whether v is a Maven version range, a Gradle
// dynamic version or an unresolved property rather than one version.
func isMavenVersionRange(v string) bool {
	return strings.ContainsAny(v, "[](),+$") || strings.HasPrefix(v, "latest.")
}
