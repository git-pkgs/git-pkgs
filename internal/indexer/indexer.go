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
	Branch      string
	Since       string
	Output      io.Writer
	Quiet       bool
	Incremental bool // Use existing branch and continue from last SHA
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

	writer, err := database.NewWriter(idx.db)
	if err != nil {
		return nil, fmt.Errorf("creating writer: %w", err)
	}
	defer func() { _ = writer.Close() }()

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

	result := &Result{}

	for i, commit := range commits {
		if !idx.opts.Quiet && idx.opts.Output != nil && (i+1)%100 == 0 {
			_, _ = fmt.Fprintf(idx.opts.Output, "  %d/%d commits processed\n", i+1, len(commits))
		}

		analysisResult, err := idx.analyzer.AnalyzeCommit(commit, snapshot)
		if err != nil {
			continue
		}

		hasChanges := analysisResult != nil && len(analysisResult.Changes) > 0

		commitInfo := database.CommitInfo{
			SHA:         commit.Hash.String(),
			Message:     commit.Message,
			AuthorName:  commit.Author.Name,
			AuthorEmail: commit.Author.Email,
			CommittedAt: commit.Committer.When,
		}

		commitID, wasNew, err := writer.InsertCommit(commitInfo, hasChanges)
		if err != nil {
			return nil, fmt.Errorf("inserting commit %s: %w", commit.Hash.String()[:7], err)
		}

		result.CommitsAnalyzed++

		// If commit already existed (from another branch), we still need to update
		// our snapshot state but don't need to re-store the changes
		if !wasNew {
			if hasChanges {
				snapshot = analysisResult.Snapshot
			}
			continue
		}

		if hasChanges {
			result.CommitsWithChanges++
			result.TotalChanges += len(analysisResult.Changes)
			snapshot = analysisResult.Snapshot

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
				if err := writer.InsertChange(commitID, manifest, changeInfo); err != nil {
					return nil, fmt.Errorf("inserting change: %w", err)
				}
			}

			// Store snapshot at commits with changes
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
				if err := writer.InsertSnapshot(commitID, manifest, snapshotInfo); err != nil {
					return nil, fmt.Errorf("inserting snapshot: %w", err)
				}
			}
		}
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
