package git

import (
	"fmt"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

// GetDependencies returns dependencies at the specified commit, indexing on demand if needed.
// The database is closed before returning.
func (r *Repository) GetDependencies(commitRef, branchName string) ([]database.Dependency, error) {
	deps, db, err := r.GetDependenciesWithDB(commitRef, branchName)
	if db != nil {
		_ = db.Close()
	}
	return deps, err
}

// GetDependenciesWithDB returns dependencies at the specified commit along with an open
// database handle. The caller is responsible for closing the database.
// This is useful for commands that need to cache enrichment data.
func (r *Repository) GetDependenciesWithDB(commitRef, branchName string) ([]database.Dependency, *database.DB, error) {
	if commitRef == "" {
		commitRef = "HEAD"
	}

	// Resolve the commit
	hash, err := r.ResolveRevision(commitRef)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving %q: %w", commitRef, err)
	}
	sha := hash.String()

	// Open or create database
	dbPath := r.DatabasePath()
	db, existed, err := database.OpenOrCreate(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening database: %w", err)
	}

	// Determine branch name
	if branchName == "" {
		if existed {
			// Try to use existing default branch
			if branchInfo, err := db.GetDefaultBranch(); err == nil {
				branchName = branchInfo.Name
			}
		}
		if branchName == "" {
			// Fall back to current git branch
			branchName, err = r.CurrentBranch()
			if err != nil {
				branchName = "main" // Last resort default
			}
		}
	}

	// Get or create the branch
	branchInfo, err := db.GetOrCreateBranch(branchName)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("getting branch: %w", err)
	}

	// Check if we have a snapshot for this commit
	hasSnapshot, err := db.HasSnapshotForCommit(sha)
	if err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("checking snapshot: %w", err)
	}

	if !hasSnapshot {
		// Index this commit on demand
		if err := r.IndexCommitSnapshot(db, branchInfo.ID, sha); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("indexing commit: %w", err)
		}
	}

	// Get dependencies from the database
	deps, err := db.GetDependenciesAtRef(sha, branchInfo.ID)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	return deps, db, nil
}

// IndexCommitSnapshot analyzes a single commit and stores its snapshot.
func (r *Repository) IndexCommitSnapshot(db *database.DB, branchID int64, sha string) error {
	hash, err := r.ResolveRevision(sha)
	if err != nil {
		return fmt.Errorf("resolving %q: %w", sha, err)
	}

	commit, err := r.CommitObject(*hash)
	if err != nil {
		return fmt.Errorf("getting commit: %w", err)
	}

	// Load mailmap if not already loaded
	if r.mailmap == nil {
		if err := r.LoadMailmap(); err != nil {
			return fmt.Errorf("loading mailmap: %w", err)
		}
	}

	a := analyzer.New()
	changes, err := a.DependenciesAtCommit(commit)
	if err != nil {
		return fmt.Errorf("analyzing commit: %w", err)
	}

	// Convert to snapshot info
	snapshots := make([]database.SnapshotInfo, 0, len(changes))
	for _, c := range changes {
		snapshots = append(snapshots, database.SnapshotInfo{
			ManifestPath:   c.ManifestPath,
			Name:           c.Name,
			Ecosystem:      c.Ecosystem,
			PURL:           c.PURL,
			Requirement:    c.Requirement,
			DependencyType: c.DependencyType,
			Integrity:      c.Integrity,
		})
	}

	// Resolve author identity via .mailmap
	authorName, authorEmail := r.ResolveAuthor(commit.Author.Name, commit.Author.Email)

	commitInfo := database.CommitInfo{
		SHA:         sha,
		Message:     commit.Message,
		AuthorName:  authorName,
		AuthorEmail: authorEmail,
		CommittedAt: commit.Committer.When,
	}

	return db.StoreSnapshot(branchID, commitInfo, snapshots)
}
