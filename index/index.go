// Package index is the public, embeddable surface over git-pkgs' per-repo
// dependency index. It wraps internal/{database,analyzer} so external
// consumers (notably silo, the forge server) can open and reindex a bare or
// non-bare repository without depending on internal/.
//
// The package is the issue-#116 extraction: the CLI's own subcommands wire
// through these calls so the surface is exactly the one downstream needs.
package index

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

// Re-exported read types so callers don't import internal/database.
type (
	Dependency        = database.Dependency
	Change            = database.Change
	BlameEntry        = database.BlameEntry
	BlameOptions      = database.BlameOptions
	HistoryEntry      = database.HistoryEntry
	HistoryOptions    = database.HistoryOptions
	Stats             = database.Stats
	StatsOptions      = database.StatsOptions
	CommitWithChanges = database.CommitWithChanges
	BranchInfo        = database.BranchInfo
)

// Options configures Open and Reindex behaviour.
type Options struct {
	// MaxManifestBytes caps the size of any single manifest blob passed to
	// the parser. 0 uses the manifests package default (10 MiB).
	MaxManifestBytes int

	// MaxDepsPerManifest caps the number of Change rows written per
	// manifest per commit. 0 means unlimited. The cap is applied after
	// AnalyzeCommit so reindex of a hostile lockfile cannot blow memory
	// at write time.
	MaxDepsPerManifest int

	// MaxManifestsPerCommit caps the number of manifests stored per
	// commit. 0 means unlimited.
	MaxManifestsPerCommit int

	// Progress, if non-nil, is called once per commit during Reindex with
	// (done, total). Invoked synchronously on the reindex goroutine.
	Progress func(done, total int)
}

// Index is a per-repo dependency index. Open returns one; Close releases its
// db handle. Concurrent Open of distinct repos is safe; Reindex on a single
// Index serialises through an internal mutex.
type Index struct {
	repo   *git.Repository
	db     *database.DB
	opts   Options
	gitDir string

	mu sync.Mutex
}

// Open opens a repository at gitDir and creates or opens the sqlite database
// at dbPath. gitDir may be a non-bare working tree, a `.git` directory, or a
// bare repo path. When gitDir ends in `.git` DetectDotGit is disabled; this
// matches the bare-repo layout silo writes into. The db is opened in WAL mode
// with busy_timeout=5000 so a reader hitting the db during a write does not
// SQLITE_BUSY.
func Open(gitDir, dbPath string, opts Options) (*Index, error) {
	detect := !strings.HasSuffix(gitDir, ".git")
	repo, err := git.PlainOpenWithOptions(gitDir, &git.PlainOpenOptions{DetectDotGit: detect})
	if err != nil {
		return nil, fmt.Errorf("index: open repo %q: %w", gitDir, err)
	}

	db, _, err := database.OpenOrCreate(dbPath)
	if err != nil {
		return nil, fmt.Errorf("index: open db %q: %w", dbPath, err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("index: set pragmas: %w", err)
	}

	return &Index{repo: repo, db: db, opts: opts, gitDir: gitDir}, nil
}

// Close releases the underlying db handle.
func (i *Index) Close() error {
	return i.db.Close()
}

// DB returns the underlying database handle. Exported so the CLI can lift
// existing queries that have not yet been wrapped; new code should prefer the
// typed methods on *Index.
func (i *Index) DB() *database.DB {
	return i.db
}

// Repo returns the underlying go-git repository.
func (i *Index) Repo() *git.Repository {
	return i.repo
}

// HasIndexed reports whether a snapshot exists for the given commit SHA.
func (i *Index) HasIndexed(sha string) (bool, error) {
	return i.db.HasSnapshotForCommit(sha)
}

// List returns the dependency snapshot at the given ref on the given branch.
// branch is resolved via the index's branch table; the ref must already be
// present on that branch in the index.
func (i *Index) List(branch, ref string) ([]Dependency, error) {
	info, err := i.db.GetBranch(branch)
	if err != nil {
		return nil, err
	}
	if ref == "" {
		return i.db.GetLatestDependencies(info.ID)
	}
	return i.db.GetDependenciesAtRef(ref, info.ID)
}

// Show returns the dependency changes introduced by the commit.
func (i *Index) Show(sha string) ([]Change, error) {
	return i.db.GetChangesForCommit(sha)
}

// Blame returns blame entries for the current snapshot on the branch in opts.
func (i *Index) Blame(opts BlameOptions) ([]BlameEntry, error) {
	return i.db.GetBlame(opts)
}

// History returns the change history for a package.
func (i *Index) History(opts HistoryOptions) ([]HistoryEntry, error) {
	return i.db.GetPackageHistory(opts)
}

// Stats returns aggregated statistics for the branch in opts.
func (i *Index) StatsFor(opts StatsOptions) (*Stats, error) {
	return i.db.GetStats(opts)
}

// Branch returns the branch record, or ErrBranchNotIndexed if it has not been
// seen by any Reindex yet.
func (i *Index) Branch(name string) (*BranchInfo, error) {
	info, err := i.db.GetBranch(name)
	if err != nil {
		if errors.Is(err, sqlErrNoRows) {
			return nil, ErrBranchNotIndexed
		}
		return nil, err
	}
	return info, nil
}

// ErrBranchNotIndexed is returned when a query names a branch that has never
// been reindexed.
var ErrBranchNotIndexed = errors.New("index: branch not indexed")

// Reindex walks newTip back to oldTip (or to the branch's last indexed SHA if
// oldTip is zero, or to the root if no previous run) and records every commit
// touching a manifest into the db. Honours ctx cancellation between commits.
// Panics inside the loop are recovered and returned as errors.
func (i *Index) Reindex(ctx context.Context, branch string, oldTip, newTip plumbing.Hash) (rerr error) {
	defer func() {
		if r := recover(); r != nil {
			rerr = fmt.Errorf("index: reindex panic: %v", r)
		}
	}()

	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.db.OptimizeForBulkWrites(); err != nil {
		return fmt.Errorf("index: optimize: %w", err)
	}

	info, err := i.db.GetOrCreateBranch(branch)
	if err != nil {
		return fmt.Errorf("index: branch %q: %w", branch, err)
	}

	writer := database.NewBatchWriter(i.db)
	if err := writer.UseBranch(info.ID); err != nil {
		return fmt.Errorf("index: use branch: %w", err)
	}

	commits, snapshot, err := i.collect(branch, oldTip, newTip, info)
	if err != nil {
		return fmt.Errorf("index: collect commits: %w", err)
	}
	if len(commits) == 0 {
		return i.db.OptimizeForReads()
	}

	az := analyzer.New()
	// Leave Analyzer.repoPath = "" so PrefetchDiffs is a no-op (no exec).

	var (
		lastSHAWithChanges    string
		firstSnapshotStored   bool
		manifestsPerCommitCap = i.opts.MaxManifestsPerCommit
		depsPerManifestCap    = i.opts.MaxDepsPerManifest
	)

	for idx, hash := range commits {
		if err := ctx.Err(); err != nil {
			return err
		}

		commit, err := i.repo.CommitObject(hash)
		if err != nil {
			continue
		}

		result, err := az.AnalyzeCommit(commit, snapshot)
		if err != nil {
			continue
		}

		hasChanges := result != nil && len(result.Changes) > 0
		sha := commit.Hash.String()

		writer.AddCommit(database.CommitInfo{
			SHA:         sha,
			Message:     truncate(commit.Message, 8192),
			AuthorName:  commit.Author.Name,
			AuthorEmail: commit.Author.Email,
			CommittedAt: commit.Committer.When,
		}, hasChanges)

		if hasChanges {
			changes := result.Changes
			if depsPerManifestCap > 0 || manifestsPerCommitCap > 0 {
				changes = applyCaps(changes, manifestsPerCommitCap, depsPerManifestCap)
			}
			snapshot = result.Snapshot
			lastSHAWithChanges = sha
			writer.IncrementDepCommitCount()

			for _, change := range changes {
				writer.AddChange(sha,
					database.ManifestInfo{Path: change.ManifestPath, Ecosystem: change.Ecosystem, Kind: change.Kind},
					database.ChangeInfo{
						ManifestPath:           change.ManifestPath,
						Name:                   change.Name,
						Ecosystem:              change.Ecosystem,
						PURL:                   change.PURL,
						ChangeType:             change.ChangeType,
						Requirement:            change.Requirement,
						PreviousRequirement:    change.PreviousRequirement,
						DependencyType:         change.DependencyType,
						PreviousDependencyType: change.PreviousDependencyType,
					})
			}

			if !firstSnapshotStored || writer.ShouldStoreSnapshot() {
				firstSnapshotStored = true
				addSnapshot(writer, sha, result.Snapshot, manifestsPerCommitCap, depsPerManifestCap)
			}
		}

		if i.opts.Progress != nil {
			i.opts.Progress(idx+1, len(commits))
		}

		if writer.ShouldFlush() {
			if err := writer.WaitForFlush(); err != nil {
				return fmt.Errorf("index: flush: %w", err)
			}
			writer.FlushAsync()
			az.ClearBlobCache()
		}
	}

	if lastSHAWithChanges != "" && !writer.HasPendingSnapshots(lastSHAWithChanges) {
		addSnapshot(writer, lastSHAWithChanges, snapshot, manifestsPerCommitCap, depsPerManifestCap)
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("index: final flush: %w", err)
	}
	if err := writer.UpdateBranchLastSHA(commits[len(commits)-1].String()); err != nil {
		return fmt.Errorf("index: update branch SHA: %w", err)
	}

	return i.db.OptimizeForReads()
}

// collect walks from newTip back via go-git. If oldTip is zero, uses the
// branch's LastAnalyzedSHA as the stop point; if that is empty too, walks the
// full history. Returns commits oldest-first and the snapshot to start from.
func (i *Index) collect(_ string, oldTip, newTip plumbing.Hash, info *BranchInfo) ([]plumbing.Hash, analyzer.Snapshot, error) {
	stopAt := info.LastAnalyzedSHA
	if !oldTip.IsZero() {
		stopAt = oldTip.String()
	}

	iter, err := i.repo.Log(&git.LogOptions{From: newTip, Order: git.LogOrderCommitterTime})
	if err != nil {
		return nil, nil, err
	}
	defer iter.Close()

	var commits []plumbing.Hash
	err = iter.ForEach(func(c *object.Commit) error {
		if stopAt != "" && c.Hash.String() == stopAt {
			return storer.ErrStop
		}
		commits = append(commits, c.Hash)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	for l, r := 0, len(commits)-1; l < r; l, r = l+1, r-1 {
		commits[l], commits[r] = commits[r], commits[l]
	}

	snap := make(analyzer.Snapshot)
	if info.LastAnalyzedSHA != "" {
		dbSnap, err := i.db.GetLastSnapshot(info.ID)
		if err == nil {
			for _, e := range dbSnap {
				snap[analyzer.SnapshotKey{
					ManifestPath: e.ManifestPath,
					Name:         e.Name,
					Requirement:  e.Requirement,
				}] = analyzer.SnapshotEntry{
					Ecosystem:      e.Ecosystem,
					PURL:           e.PURL,
					Requirement:    e.Requirement,
					DependencyType: e.DependencyType,
					Integrity:      e.Integrity,
				}
			}
		}
	}

	return commits, snap, nil
}

func addSnapshot(w *database.BatchWriter, sha string, snap analyzer.Snapshot, manifestCap, depsPerManifestCap int) {
	if len(snap) == 0 {
		w.AddEmptySnapshot(sha)
		return
	}
	manifestSeen := map[string]int{} // manifestPath -> deps recorded so far
	manifests := map[string]bool{}
	for key, entry := range snap {
		if manifestCap > 0 {
			if _, ok := manifests[key.ManifestPath]; !ok {
				if len(manifests) >= manifestCap {
					continue
				}
				manifests[key.ManifestPath] = true
			}
		}
		if depsPerManifestCap > 0 {
			if manifestSeen[key.ManifestPath] >= depsPerManifestCap {
				continue
			}
			manifestSeen[key.ManifestPath]++
		}
		w.AddSnapshot(sha,
			database.ManifestInfo{Path: key.ManifestPath, Ecosystem: entry.Ecosystem, Kind: entry.Kind},
			database.SnapshotInfo{
				ManifestPath:   key.ManifestPath,
				Name:           key.Name,
				Ecosystem:      entry.Ecosystem,
				PURL:           entry.PURL,
				Requirement:    entry.Requirement,
				DependencyType: entry.DependencyType,
				Integrity:      entry.Integrity,
			})
	}
}

func applyCaps(changes []analyzer.Change, manifestCap, depsPerManifestCap int) []analyzer.Change {
	if manifestCap <= 0 && depsPerManifestCap <= 0 {
		return changes
	}
	manifests := map[string]int{} // manifest -> deps kept
	var out []analyzer.Change
	for _, c := range changes {
		if manifestCap > 0 {
			if _, ok := manifests[c.ManifestPath]; !ok {
				if len(manifests) >= manifestCap {
					continue
				}
				manifests[c.ManifestPath] = 0
			}
		}
		if depsPerManifestCap > 0 && manifests[c.ManifestPath] >= depsPerManifestCap {
			continue
		}
		manifests[c.ManifestPath]++
		out = append(out, c)
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// sqlErrNoRows mirrors database/sql.ErrNoRows without importing it at the
// public surface (callers should not need to handle a stdlib error from a
// wrapper package). database.GetBranch returns sql.ErrNoRows directly today.
var sqlErrNoRows = errNoRows{}

type errNoRows struct{}

func (errNoRows) Error() string { return "sql: no rows in result set" }
func (errNoRows) Is(target error) bool {
	return target != nil && target.Error() == "sql: no rows in result set"
}
