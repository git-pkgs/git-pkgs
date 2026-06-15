package indexer

import (
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/analyzer"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/progress"
	"github.com/go-git/go-git/v5/plumbing"
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
	CommitsAnalyzed    int
	CommitsWithChanges int
	TotalChanges       int
	TagSnapshots       int
	BranchSnapshots    int
}

type Indexer struct {
	repo     *git.Repository
	db       *database.DB
	analyzer *analyzer.Analyzer
	opts     Options
	progress *progress.Reporter
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

	// Load .mailmap for author identity resolution
	if err := idx.repo.LoadMailmap(); err != nil {
		return nil, fmt.Errorf("loading mailmap: %w", err)
	}

	if err := idx.db.OptimizeForBulkWrites(); err != nil {
		return nil, fmt.Errorf("optimizing database: %w", err)
	}

	// Collect tags and branches concurrently with commit collection
	type refResult struct {
		tags     map[string][]string
		branches map[string][]string
	}
	refCh := make(chan refResult, 1)
	go func() {
		var r refResult
		r.tags = make(map[string][]string)
		r.branches = make(map[string][]string)
		defer func() {
			// go-git iterates attacker-controlled refs/packfiles here when
			// embedded server-side; a panic in that path must not take the
			// host process down or leave the receiver blocked on refCh.
			_ = recover()
			refCh <- r
		}()
		if tags, err := idx.repo.Tags(); err == nil {
			r.tags = tags
		}
		if branches, err := idx.repo.LocalBranches(); err == nil {
			r.branches = branches
		}
	}()

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

	if !idx.opts.Quiet {
		idx.progress = progress.New(idx.opts.Output)
	}
	idx.progress.Println("Analyzing %d commits on %s...", len(commits), branch)

	idx.analyzer.SetRepoPath(idx.repo.WorkDir())

	refs := <-refCh
	tagsBySHA := refs.tags
	branchesBySHA := refs.branches

	result := &Result{}
	var lastSHAWithChanges string
	var firstSnapshotStored bool

	batchSize := database.DefaultBatchSize
	if idx.opts.BatchSize > 0 {
		batchSize = idx.opts.BatchSize
	}

	for batchStart := 0; batchStart < len(commits); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(commits) {
			batchEnd = len(commits)
		}

		const prefetchWorkers = 8
		idx.analyzer.PrefetchDiffs(commits[batchStart:batchEnd], prefetchWorkers)

		for i := batchStart; i < batchEnd; i++ {
			hash := commits[i]

			if (i+1)%100 == 0 {
				idx.progress.Update("  %d/%d commits processed", i+1, len(commits))
			}

			commit, err := idx.repo.CommitObject(hash)
			if err != nil {
				continue
			}

			analysisResult, err := idx.analyzer.AnalyzeCommit(commit, snapshot)
			if err != nil {
				continue
			}

			hasChanges := analysisResult != nil && len(analysisResult.Changes) > 0
			sha := commit.Hash.String()

			// Resolve author identity via .mailmap
			authorName, authorEmail := idx.repo.ResolveAuthor(commit.Author.Name, commit.Author.Email)

			commitInfo := database.CommitInfo{
				SHA:         sha,
				Message:     commit.Message,
				AuthorName:  authorName,
				AuthorEmail: authorEmail,
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
						ManifestPath:           change.ManifestPath,
						Name:                   change.Name,
						Ecosystem:              change.Ecosystem,
						PURL:                   change.PURL,
						ChangeType:             change.ChangeType,
						Requirement:            change.Requirement,
						PreviousRequirement:    change.PreviousRequirement,
						DependencyType:         change.DependencyType,
						PreviousDependencyType: change.PreviousDependencyType,
					}
					writer.AddChange(sha, manifest, changeInfo)
				}

				// Store snapshot at first commit, at intervals, or for important commits (tags, branch heads)
				isImportant := len(tagsBySHA[sha]) > 0 || len(branchesBySHA[sha]) > 0
				shouldStore := !firstSnapshotStored || writer.ShouldStoreSnapshot() || isImportant
				if shouldStore {
					firstSnapshotStored = true
					if len(analysisResult.Snapshot) == 0 {
						writer.AddEmptySnapshot(sha)
					} else {
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
					if isImportant {
						idx.logImportantSnapshot(sha, tagsBySHA[sha], branchesBySHA[sha])
						result.TagSnapshots += len(tagsBySHA[sha])
						result.BranchSnapshots += len(branchesBySHA[sha])
					}
				}
			} else if len(snapshot) > 0 && (len(tagsBySHA[sha]) > 0 || len(branchesBySHA[sha]) > 0) {
				// Store snapshot for important commits (tags, branch heads) even without changes
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
					writer.AddSnapshot(sha, manifest, snapshotInfo)
				}
				idx.logImportantSnapshot(sha, tagsBySHA[sha], branchesBySHA[sha])
				result.TagSnapshots += len(tagsBySHA[sha])
				result.BranchSnapshots += len(branchesBySHA[sha])
			}

			if writer.ShouldFlush() {
				if err := writer.WaitForFlush(); err != nil {
					return nil, fmt.Errorf("flushing batch: %w", err)
				}
				writer.FlushAsync()
				idx.analyzer.ClearBlobCache()
			}
		}

		idx.analyzer.ClearDiffCache()
	}

	idx.progress.Clear()

	// Always store final snapshot for the last commit with changes
	if lastSHAWithChanges != "" && !writer.HasPendingSnapshots(lastSHAWithChanges) {
		if len(snapshot) == 0 {
			// Store empty snapshot marker
			writer.AddEmptySnapshot(lastSHAWithChanges)
		} else {
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
	}

	// Wait for any in-flight async flush, then flush remaining items
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("flushing final batch: %w", err)
	}

	if len(commits) > 0 {
		lastSHA := commits[len(commits)-1].String()
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
			Requirement:  info.Requirement,
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

func (idx *Indexer) collectCommits(branch string, sinceSHA string) ([]plumbing.Hash, error) {
	var revRange string
	if sinceSHA != "" {
		revRange = sinceSHA + ".." + branch
	} else {
		revRange = branch
	}

	cmd := exec.Command("git", "rev-list", "--reverse", revRange)
	cmd.Dir = idx.repo.WorkDir()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running git rev-list: %w", err)
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return nil, nil
	}

	lines := strings.Split(trimmed, "\n")
	hashes := make([]plumbing.Hash, len(lines))
	for i, line := range lines {
		hashes[i] = plumbing.NewHash(line)
	}

	return hashes, nil
}

func (idx *Indexer) logImportantSnapshot(sha string, tags, branches []string) {
	shortSHA := sha[:7]
	for _, tag := range tags {
		idx.progress.Println("  Snapshot at tag %s (%s)", tag, shortSHA)
	}
	for _, branch := range branches {
		idx.progress.Println("  Snapshot at branch %s (%s)", branch, shortSHA)
	}
}
