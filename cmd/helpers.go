package cmd

import (
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
)

const (
	shortSHALen       = 7  // characters to show for abbreviated SHA
	shaHashLen        = 40 // full SHA-1 hash length
	hashDisplayLen    = 50 // truncation length for hash display
	datePrefixLen     = 10 // "YYYY-MM-DD" length
	subjectTruncLen   = 60 // truncation length for commit subjects and messages
	summaryTruncLen   = 80 // truncation length for vulnerability summaries
	authorTruncLen    = 24 // truncation length for author names
	separatorShortLen = 18 // short separator line length
	separatorLongLen  = 70 // long separator line length
	allSeverities     = 4  // severity level that includes all severities
)

func openDatabase() (*git.Repository, *database.DB, error) {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return nil, nil, fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return nil, nil, fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}

	return repo, db, nil
}

func resolveBranch(db *database.DB, branchName string) (*database.BranchInfo, error) {
	if branchName != "" {
		branch, err := db.GetBranch(branchName)
		if err != nil {
			return nil, fmt.Errorf("branch %q not found: %w", branchName, err)
		}
		return branch, nil
	}
	branch, err := db.GetDefaultBranch()
	if err != nil {
		return nil, fmt.Errorf("getting branch: %w", err)
	}
	return branch, nil
}

func shortSHA(sha string) string {
	if len(sha) > shortSHALen {
		return sha[:shortSHALen]
	}
	return sha
}

func isResolvedDependency(d database.Dependency) bool {
	return d.Requirement != "" && hasResolvedRequirement(d.Ecosystem, d.ManifestKind)
}

// hasResolvedRequirement reports whether a dependency row from the given
// ecosystem and manifest kind carries an exact version in its requirement
// field rather than a range constraint. Lockfiles always do; go.mod and
// Maven poms pin exact versions despite being manifests.
func hasResolvedRequirement(ecosystem, manifestKind string) bool {
	return manifestKind == manifestKindLockfile || ecosystem == "golang" || ecosystem == "maven"
}

func IsPURL(s string) bool {
	return strings.HasPrefix(s, "pkg:")
}

func ParsePackageArg(arg, ecosystemFlag string) (ecosystem, name, version string, err error) {
	if IsPURL(arg) {
		p, err := purl.Parse(arg)
		if err != nil {
			return "", "", "", fmt.Errorf("parsing purl: %w", err)
		}
		ecosystem = purl.PURLTypeToEcosystem(p.Type)
		name = p.FullName()
		version = p.Version
		return ecosystem, name, version, nil
	}
	return ecosystemFlag, arg, "", nil
}

func filterByEcosystem(deps []database.Dependency, ecosystem string) []database.Dependency {
	if ecosystem == "" {
		return deps
	}
	var filtered []database.Dependency
	for _, d := range deps {
		if strings.EqualFold(d.Ecosystem, ecosystem) {
			filtered = append(filtered, d)
		}
	}
	return filtered
}
