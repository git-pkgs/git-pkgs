package indexer

import (
	"fmt"
	"io"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type Options struct {
	Branch           string
	Since            string
	Output           io.Writer
	Quiet            bool
	Incremental      bool // Use existing branch and continue from last SHA
	BatchSize        int  // Commits to buffer before flushing (default 500)
	SnapshotInterval int  // Store snapshot every N commits with changes (default 50)
}

type Result struct {
	CommitsAnalyzed int
	CommitsWithChanges int
	TotalChanges int
}

type Indexer struct {
	repo     *git.Repository
	db       *database.DB
	analyzer *analyzer.Analyzer
	opts     Options
}

func New(repo *git.Repository, db *database.DB, opts Options) *Indexer {
	return &Indexer{
		repo:     repo,
		db:       db,
		analyzer: analyzer.New(),
		opts:     opts,
	}
}

func (idx *Indexer) Run() (*Result, error) {
	branch := idx.opts.Branch
	if branch == "" {
		var err error
		branch, err = idx.repo.CurrentBranch()
		if err != nil {
			return nil, fmt.Errorf("getting current branch: %w", err)
		}
	}

	if err := idx.db.OptimizeForBulkWrites(); err != nil {
		return nil, fmt.Errorf("optimizing database: %w", err)
	}

	writer := database.NewBatchWriter(idx.db)
	if idx.opts.BatchSize > 0 {
		writer.SetBatchSize(idx.opts.BatchSize)
	}
	if idx.opts.SnapshotInterval > 0 {
		writer.SetSnapshotInterval(idx.opts.SnapshotInterval)
	}

	var snapshot analyzer.Snapshot
	var sinceSHA string

	if idx.opts.Incremental {
		branchInfo, err := idx.db.GetBranch(branch)
		if err != nil {
			return nil, fmt.Errorf("getting branch %q: %w", branch, err)
		}

		if err := writer.UseBranch(branchInfo.ID); err != nil {
			return nil, fmt.Errorf("using branch: %w", err)
		}

		sinceSHA = branchInfo.LastAnalyzedSHA

		// Load the existing snapshot
		dbSnapshot, err := idx.db.GetLastSnapshot(branchInfo.ID)
		if err != nil {
			return nil, fmt.Errorf("getting last snapshot: %w", err)
		}
		snapshot = convertDBSnapshot(dbSnapshot)
	} else {
		if err := writer.CreateBranch(branch); err != nil {
			return nil, fmt.Errorf("creating branch: %w", err)
		}
		snapshot = make(analyzer.Snapshot)
		sinceSHA = idx.opts.Since
	}

	commits, err := idx.collectCommits(branch, sinceSHA)
	if err != nil {
		return nil, fmt.Errorf("collecting commits: %w", err)
	}

	if !idx.opts.Quiet && idx.opts.Output != nil {
		_, _ = fmt.Fprintf(idx.opts.Output, "Analyzing %d commits on %s...\n", len(commits), branch)
	}

	// Prefetch diffs in parallel using git shell commands (thread-safe unlike go-git)
	idx.analyzer.SetRepoPath(idx.repo.WorkDir())
	idx.analyzer.PrefetchDiffs(commits, 8)

	result := &Result{}
	var lastSHAWithChanges string

	for i, commit := range commits {
		if !idx.opts.Quiet && idx.opts.Output != nil && (i+1)%100 == 0 {
			_, _ = fmt.Fprintf(idx.opts.Output, "  %d/%d commits processed\n", i+1, len(commits))
		}

		analysisResult, err := idx.analyzer.AnalyzeCommit(commit, snapshot)
		if err != nil {
			continue
		}

		hasChanges := analysisResult != nil && len(analysisResult.Changes) > 0
		sha := commit.Hash.String()

		commitInfo := database.CommitInfo{
			SHA:         sha,
			Message:     commit.Message,
			AuthorName:  commit.Author.Name,
			AuthorEmail: commit.Author.Email,
			CommittedAt: commit.Committer.When,
		}

		writer.AddCommit(commitInfo, hasChanges)
		result.CommitsAnalyzed++

		if hasChanges {
			result.CommitsWithChanges++
			result.TotalChanges += len(analysisResult.Changes)
			snapshot = analysisResult.Snapshot
			lastSHAWithChanges = sha

			writer.IncrementDepCommitCount()

			for _, change := range analysisResult.Changes {
				manifest := database.ManifestInfo{
					Path:      change.ManifestPath,
					Ecosystem: change.Ecosystem,
					Kind:      change.Kind,
				}
				changeInfo := database.ChangeInfo{
					ManifestPath:        change.ManifestPath,
					Name:                change.Name,
					Ecosystem:           change.Ecosystem,
					PURL:                change.PURL,
					ChangeType:          change.ChangeType,
					Requirement:         change.Requirement,
					PreviousRequirement: change.PreviousRequirement,
					DependencyType:      change.DependencyType,
				}
				writer.AddChange(sha, manifest, changeInfo)
			}

			// Store snapshot at intervals
			if writer.ShouldStoreSnapshot() {
				for key, entry := range analysisResult.Snapshot {
					manifest := database.ManifestInfo{
						Path:      key.ManifestPath,
						Ecosystem: entry.Ecosystem,
						Kind:      entry.Kind,
					}
					snapshotInfo := database.SnapshotInfo{
						ManifestPath:   key.ManifestPath,
						Name:           key.Name,
						Ecosystem:      entry.Ecosystem,
						PURL:           entry.PURL,
						Requirement:    entry.Requirement,
						DependencyType: entry.DependencyType,
						Integrity:      entry.Integrity,
					}
					writer.AddSnapshot(sha, manifest, snapshotInfo)
				}
			}
		}

		if writer.ShouldFlush() {
			if err := writer.Flush(); err != nil {
				return nil, fmt.Errorf("flushing batch: %w", err)
			}
		}
	}

	// Always store final snapshot for the last commit with changes
	if lastSHAWithChanges != "" && len(snapshot) > 0 && !writer.HasPendingSnapshots(lastSHAWithChanges) {
		for key, entry := range snapshot {
			manifest := database.ManifestInfo{
				Path:      key.ManifestPath,
				Ecosystem: entry.Ecosystem,
				Kind:      entry.Kind,
			}
			snapshotInfo := database.SnapshotInfo{
				ManifestPath:   key.ManifestPath,
				Name:           key.Name,
				Ecosystem:      entry.Ecosystem,
				PURL:           entry.PURL,
				Requirement:    entry.Requirement,
				DependencyType: entry.DependencyType,
				Integrity:      entry.Integrity,
			}
			writer.AddSnapshot(lastSHAWithChanges, manifest, snapshotInfo)
		}
	}

	// Final flush
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing final batch: %w", err)
	}

	if len(commits) > 0 {
		lastSHA := commits[len(commits)-1].Hash.String()
		if err := writer.UpdateBranchLastSHA(lastSHA); err != nil {
			return nil, fmt.Errorf("updating branch last SHA: %w", err)
		}
	}

	if err := idx.db.OptimizeForReads(); err != nil {
		return nil, fmt.Errorf("optimizing database for reads: %w", err)
	}

	return result, nil
}

func convertDBSnapshot(dbSnapshot map[string]database.SnapshotInfo) analyzer.Snapshot {
	result := make(analyzer.Snapshot)
	for _, info := range dbSnapshot {
		key := analyzer.SnapshotKey{
			ManifestPath: info.ManifestPath,
			Name:         info.Name,
		}
		result[key] = analyzer.SnapshotEntry{
			Ecosystem:      info.Ecosystem,
			PURL:           info.PURL,
			Requirement:    info.Requirement,
			DependencyType: info.DependencyType,
			Integrity:      info.Integrity,
		}
	}
	return result
}

func (idx *Indexer) collectCommits(branch string, sinceSHA string) ([]*object.Commit, error) {
	hash, err := idx.repo.ResolveRevision(branch)
	if err != nil {
		return nil, fmt.Errorf("resolving branch %q: %w", branch, err)
	}

	iter, err := idx.repo.Log(*hash)
	if err != nil {
		return nil, fmt.Errorf("getting log: %w", err)
	}

	var commits []*object.Commit
	err = iter.ForEach(func(c *object.Commit) error {
		// If we have a sinceSHA, stop when we reach it (don't include it)
		if sinceSHA != "" && c.Hash.String() == sinceSHA {
			return errStopIteration
		}
		commits = append(commits, c)
		return nil
	})
	if err != nil && err != errStopIteration {
		return nil, err
	}

	// Reverse to process oldest first
	for i, j := 0, len(commits)-1; i < j; i, j = i+1, j-1 {
		commits[i], commits[j] = commits[j], commits[i]
	}

	return commits, nil
}

var errStopIteration = fmt.Errorf("stop iteration")
