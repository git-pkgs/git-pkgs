package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultBatchSize        = 500
	DefaultSnapshotInterval = 100
	MaxSQLVariables         = 999 // SQLite default limit
)

type CommitInfo struct {
	SHA         string
	Message     string
	AuthorName  string
	AuthorEmail string
	CommittedAt time.Time
}

type ManifestInfo struct {
	Path      string
	Ecosystem string
	Kind      string
}

type ChangeInfo struct {
	ManifestPath           string
	Name                   string
	Ecosystem              string
	PURL                   string
	ChangeType             string
	Requirement            string
	PreviousRequirement    string
	DependencyType         string
	PreviousDependencyType string
}

type SnapshotInfo struct {
	ManifestPath   string
	Name           string
	Ecosystem      string
	PURL           string
	Requirement    string
	DependencyType string
	Integrity      string
}

type pendingCommit struct {
	info       CommitInfo
	hasChanges bool
	position   int
}

type pendingChange struct {
	sha      string
	manifest ManifestInfo
	change   ChangeInfo
}

type pendingSnapshot struct {
	sha      string
	manifest ManifestInfo
	snapshot SnapshotInfo
}

type BatchWriter struct {
	db            *DB
	branchID      int64
	position      int
	manifestCache map[string]int64

	pendingCommits   []pendingCommit
	pendingChanges   []pendingChange
	pendingSnapshots []pendingSnapshot

	batchSize        int
	snapshotInterval int
	depCommitCount   int
	lastSHA          string

	flushDone chan error
}

func NewBatchWriter(db *DB) *BatchWriter {
	return &BatchWriter{
		db:               db,
		manifestCache:    make(map[string]int64),
		batchSize:        DefaultBatchSize,
		snapshotInterval: DefaultSnapshotInterval,
	}
}

func (w *BatchWriter) SetBatchSize(size int) {
	w.batchSize = size
}

func (w *BatchWriter) SetSnapshotInterval(interval int) {
	w.snapshotInterval = interval
}

func (w *BatchWriter) CreateBranch(name string) error {
	now := time.Now()
	result, err := w.db.Exec(
		"INSERT INTO branches (name, created_at, updated_at) VALUES (?, ?, ?)",
		name, now, now,
	)
	if err != nil {
		return err
	}
	w.branchID, err = result.LastInsertId()
	return err
}

func (w *BatchWriter) UseBranch(branchID int64) error {
	w.branchID = branchID
	pos, err := w.db.GetMaxPosition(branchID)
	if err != nil {
		return err
	}
	w.position = pos
	return nil
}

func (w *BatchWriter) AddCommit(info CommitInfo, hasChanges bool) {
	w.position++
	w.pendingCommits = append(w.pendingCommits, pendingCommit{
		info:       info,
		hasChanges: hasChanges,
		position:   w.position,
	})
	w.lastSHA = info.SHA
}

func (w *BatchWriter) AddChange(sha string, manifest ManifestInfo, change ChangeInfo) {
	w.pendingChanges = append(w.pendingChanges, pendingChange{
		sha:      sha,
		manifest: manifest,
		change:   change,
	})
}

// ShouldStoreSnapshot returns true if a snapshot should be stored at this commit.
// Call this after incrementing the dependency commit count.
func (w *BatchWriter) ShouldStoreSnapshot() bool {
	return w.depCommitCount%w.snapshotInterval == 0
}

func (w *BatchWriter) IncrementDepCommitCount() {
	w.depCommitCount++
}

func (w *BatchWriter) AddSnapshot(sha string, manifest ManifestInfo, snapshot SnapshotInfo) {
	w.pendingSnapshots = append(w.pendingSnapshots, pendingSnapshot{
		sha:      sha,
		manifest: manifest,
		snapshot: snapshot,
	})
}

// AddEmptySnapshot stores a marker to indicate this commit has no dependencies.
// This allows GetDependenciesAtRef to distinguish "no snapshot taken" from "empty snapshot".
func (w *BatchWriter) AddEmptySnapshot(sha string) {
	w.pendingSnapshots = append(w.pendingSnapshots, pendingSnapshot{
		sha: sha,
		manifest: ManifestInfo{
			Path:      "_EMPTY_",
			Ecosystem: "",
			Kind:      "",
		},
		snapshot: SnapshotInfo{
			Name: "_EMPTY_MARKER_",
		},
	})
}

func (w *BatchWriter) ShouldFlush() bool {
	return len(w.pendingCommits) >= w.batchSize
}

func (w *BatchWriter) Flush() error {
	if err := w.WaitForFlush(); err != nil {
		return err
	}
	return w.flushPending(w.takePending())
}

// FlushAsync swaps the pending slices into a background goroutine that
// performs the DB transaction. The caller gets fresh empty slices immediately.
// Call WaitForFlush before the next FlushAsync or Flush to collect the result.
func (w *BatchWriter) FlushAsync() {
	commits, changes, snapshots := w.takePending()
	w.flushDone = make(chan error, 1)
	ch := w.flushDone
	go func() {
		ch <- w.flushPending(commits, changes, snapshots)
	}()
}

// WaitForFlush blocks until a previous FlushAsync completes and returns its error.
// Safe to call when no async flush is in flight (returns nil).
func (w *BatchWriter) WaitForFlush() error {
	if w.flushDone == nil {
		return nil
	}
	err := <-w.flushDone
	w.flushDone = nil
	return err
}

// takePending returns the current pending slices and replaces them with fresh empties.
func (w *BatchWriter) takePending() ([]pendingCommit, []pendingChange, []pendingSnapshot) {
	commits := w.pendingCommits
	changes := w.pendingChanges
	snapshots := w.pendingSnapshots
	w.pendingCommits = nil
	w.pendingChanges = nil
	w.pendingSnapshots = nil
	return commits, changes, snapshots
}

func (w *BatchWriter) flushPending(commits []pendingCommit, changes []pendingChange, snapshots []pendingSnapshot) error {
	if len(commits) == 0 {
		return nil
	}

	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	// 1. Find commits that already exist so we can skip re-inserting their data
	existingCommits, err := w.getCommitIDs(tx, commits)
	if err != nil {
		return fmt.Errorf("getting existing commit IDs: %w", err)
	}

	// 2. Batch insert commits (OR IGNORE skips existing ones)
	if err := w.insertCommits(tx, now, commits); err != nil {
		return fmt.Errorf("inserting commits: %w", err)
	}

	// 3. Get commit IDs by SHA (now includes newly inserted ones)
	commitIDs, err := w.getCommitIDs(tx, commits)
	if err != nil {
		return fmt.Errorf("getting commit IDs: %w", err)
	}

	// 4. Batch insert branch_commits
	if err := w.insertBranchCommits(tx, commitIDs, commits); err != nil {
		return fmt.Errorf("inserting branch commits: %w", err)
	}

	// 5. Filter out changes and snapshots for commits that already existed,
	// since their data is already stored from another branch.
	if len(existingCommits) > 0 {
		newChanges := changes[:0]
		for _, c := range changes {
			if _, exists := existingCommits[c.sha]; !exists {
				newChanges = append(newChanges, c)
			}
		}
		changes = newChanges

		newSnapshots := snapshots[:0]
		for _, s := range snapshots {
			if _, exists := existingCommits[s.sha]; !exists {
				newSnapshots = append(newSnapshots, s)
			}
		}
		snapshots = newSnapshots
	}

	// 6. Ensure manifests exist and get their IDs
	if err := w.ensureManifests(tx, now, changes, snapshots); err != nil {
		return fmt.Errorf("ensuring manifests: %w", err)
	}

	// 7. Batch insert changes
	if err := w.insertChanges(tx, commitIDs, now, changes); err != nil {
		return fmt.Errorf("inserting changes: %w", err)
	}

	// 8. Batch insert snapshots
	if err := w.insertSnapshots(tx, commitIDs, now, snapshots); err != nil {
		return fmt.Errorf("inserting snapshots: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	return nil
}

func (w *BatchWriter) insertCommits(tx *sql.Tx, now time.Time, pending []pendingCommit) error {
	if len(pending) == 0 {
		return nil
	}

	const columnsPerRow = 8
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(pending); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT OR IGNORE INTO commits (sha, message, author_name, author_email, committed_at, has_dependency_changes, created_at, updated_at) VALUES ")

		args := make([]any, 0, len(batch)*columnsPerRow)
		for i, pc := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?)")

			hasChanges := 0
			if pc.hasChanges {
				hasChanges = 1
			}
			args = append(args, pc.info.SHA, pc.info.Message, pc.info.AuthorName, pc.info.AuthorEmail, pc.info.CommittedAt.UTC().Format("2006-01-02 15:04:05"), hasChanges, now, now)
		}

		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}

	return nil
}

func (w *BatchWriter) getCommitIDs(tx *sql.Tx, pending []pendingCommit) (map[string]int64, error) {
	if len(pending) == 0 {
		return make(map[string]int64), nil
	}

	result := make(map[string]int64)

	for start := 0; start < len(pending); start += MaxSQLVariables {
		end := start + MaxSQLVariables
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]

		shas := make([]any, len(batch))
		placeholders := make([]string, len(batch))
		for i, pc := range batch {
			shas[i] = pc.info.SHA
			placeholders[i] = "?"
		}

		query := "SELECT sha, id FROM commits WHERE sha IN (" + strings.Join(placeholders, ",") + ")"
		rows, err := tx.Query(query, shas...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var sha string
			var id int64
			if err := rows.Scan(&sha, &id); err != nil {
				_ = rows.Close()
				return nil, err
			}
			result[sha] = id
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close()
	}

	return result, nil
}

func (w *BatchWriter) insertBranchCommits(tx *sql.Tx, commitIDs map[string]int64, pending []pendingCommit) error {
	if len(pending) == 0 {
		return nil
	}

	const columnsPerRow = 3
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(pending); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT OR IGNORE INTO branch_commits (branch_id, commit_id, position) VALUES ")

		args := make([]any, 0, len(batch)*columnsPerRow)
		for i, pc := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?)")
			args = append(args, w.branchID, commitIDs[pc.info.SHA], pc.position)
		}

		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}

	return nil
}

func (w *BatchWriter) ensureManifests(tx *sql.Tx, now time.Time, changes []pendingChange, snapshots []pendingSnapshot) error {
	// Collect unique manifests from changes and snapshots
	manifests := make(map[string]ManifestInfo)
	for _, pc := range changes {
		manifests[pc.manifest.Path] = pc.manifest
	}
	for _, ps := range snapshots {
		manifests[ps.manifest.Path] = ps.manifest
	}

	// Filter out already cached
	var toInsert []ManifestInfo
	for path, m := range manifests {
		if _, ok := w.manifestCache[path]; !ok {
			toInsert = append(toInsert, m)
		}
	}

	if len(toInsert) == 0 {
		return nil
	}

	// Insert new manifests
	var sb strings.Builder
	sb.WriteString("INSERT OR IGNORE INTO manifests (path, ecosystem, kind, created_at, updated_at) VALUES ")

	const manifestColumns = 5 // path, ecosystem, kind, created_at, updated_at
	args := make([]any, 0, len(toInsert)*manifestColumns)
	for i, m := range toInsert {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?)")
		args = append(args, m.Path, m.Ecosystem, m.Kind, now, now)
	}

	if _, err := tx.Exec(sb.String(), args...); err != nil {
		return err
	}

	// Query all manifest IDs we need
	paths := make([]any, len(manifests))
	placeholders := make([]string, len(manifests))
	i := 0
	for path := range manifests {
		paths[i] = path
		placeholders[i] = "?"
		i++
	}

	query := "SELECT path, id FROM manifests WHERE path IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := tx.Query(query, paths...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var path string
		var id int64
		if err := rows.Scan(&path, &id); err != nil {
			return err
		}
		w.manifestCache[path] = id
	}
	return rows.Err()
}

func (w *BatchWriter) insertChanges(tx *sql.Tx, commitIDs map[string]int64, now time.Time, pending []pendingChange) error {
	if len(pending) == 0 {
		return nil
	}

	// Changes have 12 columns, so max rows per batch = MaxSQLVariables / 12
	const columnsPerRow = 12
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(pending); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT INTO dependency_changes (commit_id, manifest_id, name, ecosystem, purl, change_type, requirement, previous_requirement, dependency_type, previous_dependency_type, created_at, updated_at) VALUES ")

		args := make([]any, 0, len(batch)*columnsPerRow)
		for i, pc := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?,?)")
			args = append(args,
				commitIDs[pc.sha],
				w.manifestCache[pc.manifest.Path],
				pc.change.Name,
				pc.change.Ecosystem,
				pc.change.PURL,
				pc.change.ChangeType,
				pc.change.Requirement,
				pc.change.PreviousRequirement,
				pc.change.DependencyType,
				pc.change.PreviousDependencyType,
				now,
				now,
			)
		}

		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}

	return nil
}

func (w *BatchWriter) insertSnapshots(tx *sql.Tx, commitIDs map[string]int64, now time.Time, pending []pendingSnapshot) error {
	if len(pending) == 0 {
		return nil
	}

	// Snapshots have 10 columns, so max rows per batch = MaxSQLVariables / 10
	const columnsPerRow = 10
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(pending); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(pending) {
			end = len(pending)
		}
		batch := pending[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT OR IGNORE INTO dependency_snapshots (commit_id, manifest_id, name, ecosystem, purl, requirement, dependency_type, integrity, created_at, updated_at) VALUES ")

		args := make([]any, 0, len(batch)*columnsPerRow)
		for i, ps := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?)")
			args = append(args,
				commitIDs[ps.sha],
				w.manifestCache[ps.manifest.Path],
				ps.snapshot.Name,
				ps.snapshot.Ecosystem,
				ps.snapshot.PURL,
				ps.snapshot.Requirement,
				ps.snapshot.DependencyType,
				ps.snapshot.Integrity,
				now,
				now,
			)
		}

		if _, err := tx.Exec(sb.String(), args...); err != nil {
			return err
		}
	}

	return nil
}

func (w *BatchWriter) UpdateBranchLastSHA(sha string) error {
	_, err := w.db.Exec(
		"UPDATE branches SET last_analyzed_sha = ?, updated_at = ? WHERE id = ?",
		sha, time.Now(), w.branchID,
	)
	return err
}

func (w *BatchWriter) HasPendingSnapshots(sha string) bool {
	for _, ps := range w.pendingSnapshots {
		if ps.sha == sha {
			return true
		}
	}
	return false
}
