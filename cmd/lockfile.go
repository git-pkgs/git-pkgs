package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
		deps, unresolved, err := parseLockfile(path)
		if err != nil {
			return nil, nil, err
		}
		reportUnresolvedLockfileDependencies(cmd.ErrOrStderr(), unresolved)
		return deps, nil, nil
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
// identified by its base name, so it must keep its standard name. Maven build
// files may leave versions unresolved; those dependencies are returned
// separately.
func parseLockfile(path string) (deps, unresolved []database.Dependency, err error) {
	name := filepath.Base(path)
	ecosystem, kind, ok := manifests.Identify(name)
	if !ok {
		return nil, nil, fmt.Errorf("unrecognized lockfile %s", path)
	}
	if kind == manifests.Supplement || !hasResolvedRequirement(ecosystem, string(kind)) {
		return nil, nil, fmt.Errorf("%s does not list resolved versions; pass a lockfile such as poetry.lock or package-lock.json", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading lockfile: %w", err)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%s is empty", path)
	}
	result, err := manifests.Parse(name, data)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	checkVersions := result.Kind != manifests.Lockfile && result.Ecosystem == "maven"
	deps = make([]database.Dependency, 0, len(result.Dependencies))
	for _, dep := range result.Dependencies {
		d := database.Dependency{
			Name:           dep.Name,
			Ecosystem:      result.Ecosystem,
			PURL:           dep.PURL,
			Requirement:    dep.Version,
			DependencyType: string(dep.Scope),
			Integrity:      dep.Integrity,
			ManifestPath:   path,
			ManifestKind:   string(result.Kind),
			Direct:         dep.Direct,
		}
		if checkVersions && isUnresolvedMavenVersion(dep.Version) {
			unresolved = append(unresolved, d)
			continue
		}
		deps = append(deps, d)
	}
	if len(deps) == 0 && len(unresolved) > 0 {
		return nil, nil, fmt.Errorf("%s has no dependencies with resolved versions; pass %s", path, mavenLockfileHint(name))
	}
	return deps, unresolved, nil
}

// isUnresolvedMavenVersion reports whether v is not a single version: empty,
// a Maven range, a Gradle dynamic version or an unresolved property.
func isUnresolvedMavenVersion(v string) bool {
	return v == "" || strings.ContainsAny(v, "[](),+$") || strings.HasPrefix(v, "latest.")
}

// mavenLockfileHint names the file that lists resolved versions for a Maven
// build file.
func mavenLockfileHint(name string) string {
	switch name {
	case "pom.xml":
		return "maven-resolved-dependencies.txt (mvn dependency:list output)"
	case "build.gradle", "build.gradle.kts":
		return "gradle.lockfile"
	default:
		return "a lockfile that lists resolved versions"
	}
}

// reportUnresolvedLockfileDependencies lists dependencies skipped because the
// lockfile does not give them a single version.
func reportUnresolvedLockfileDependencies(w io.Writer, skipped []database.Dependency) {
	if len(skipped) == 0 {
		return
	}
	labels := make([]string, 0, len(skipped))
	for _, dep := range skipped {
		version := "with no version"
		if dep.Requirement != "" {
			version = fmt.Sprintf("at %q", dep.Requirement)
		}
		labels = append(labels, fmt.Sprintf("%s package %q %s (%s)", dep.Ecosystem, dep.Name, version, dep.ManifestPath))
	}
	sort.Strings(labels)

	dependencyLabel := "dependency"
	if len(skipped) != 1 {
		dependencyLabel = "dependencies"
	}
	_, _ = fmt.Fprintf(w, "Skipping %d %s without a resolved version: %s.\n",
		len(skipped), dependencyLabel, strings.Join(labels, ", "))
}
