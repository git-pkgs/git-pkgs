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

func (w *BatchWriter) ShouldFlush() bool {
	return len(w.pendingCommits) >= w.batchSize
}

func (w *BatchWriter) Flush() error {
	if len(w.pendingCommits) == 0 {
		return nil
	}

	tx, err := w.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	// 1. Batch insert commits
	if err := w.insertCommits(tx, now); err != nil {
		return fmt.Errorf("inserting commits: %w", err)
	}

	// 2. Get commit IDs by SHA
	commitIDs, err := w.getCommitIDs(tx)
	if err != nil {
		return fmt.Errorf("getting commit IDs: %w", err)
	}

	// 3. Batch insert branch_commits
	if err := w.insertBranchCommits(tx, commitIDs); err != nil {
		return fmt.Errorf("inserting branch commits: %w", err)
	}

	// 4. Ensure manifests exist and get their IDs
	if err := w.ensureManifests(tx, now); err != nil {
		return fmt.Errorf("ensuring manifests: %w", err)
	}

	// 5. Batch insert changes
	if err := w.insertChanges(tx, commitIDs, now); err != nil {
		return fmt.Errorf("inserting changes: %w", err)
	}

	// 6. Batch insert snapshots
	if err := w.insertSnapshots(tx, commitIDs, now); err != nil {
		return fmt.Errorf("inserting snapshots: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	// Clear pending buffers
	w.pendingCommits = w.pendingCommits[:0]
	w.pendingChanges = w.pendingChanges[:0]
	w.pendingSnapshots = w.pendingSnapshots[:0]

	return nil
}

func (w *BatchWriter) insertCommits(tx *sql.Tx, now time.Time) error {
	if len(w.pendingCommits) == 0 {
		return nil
	}

	// Build multi-value INSERT
	var sb strings.Builder
	sb.WriteString("INSERT INTO commits (sha, message, author_name, author_email, committed_at, has_dependency_changes, created_at, updated_at) VALUES ")

	args := make([]any, 0, len(w.pendingCommits)*8)
	for i, pc := range w.pendingCommits {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?,?,?,?,?,?)")

		hasChanges := 0
		if pc.hasChanges {
			hasChanges = 1
		}
		args = append(args, pc.info.SHA, pc.info.Message, pc.info.AuthorName, pc.info.AuthorEmail, pc.info.CommittedAt, hasChanges, now, now)
	}

	_, err := tx.Exec(sb.String(), args...)
	return err
}

func (w *BatchWriter) getCommitIDs(tx *sql.Tx) (map[string]int64, error) {
	if len(w.pendingCommits) == 0 {
		return make(map[string]int64), nil
	}

	// Build IN clause
	shas := make([]any, len(w.pendingCommits))
	placeholders := make([]string, len(w.pendingCommits))
	for i, pc := range w.pendingCommits {
		shas[i] = pc.info.SHA
		placeholders[i] = "?"
	}

	query := "SELECT sha, id FROM commits WHERE sha IN (" + strings.Join(placeholders, ",") + ")"
	rows, err := tx.Query(query, shas...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]int64)
	for rows.Next() {
		var sha string
		var id int64
		if err := rows.Scan(&sha, &id); err != nil {
			return nil, err
		}
		result[sha] = id
	}
	return result, rows.Err()
}

func (w *BatchWriter) insertBranchCommits(tx *sql.Tx, commitIDs map[string]int64) error {
	if len(w.pendingCommits) == 0 {
		return nil
	}

	var sb strings.Builder
	sb.WriteString("INSERT INTO branch_commits (branch_id, commit_id, position) VALUES ")

	args := make([]any, 0, len(w.pendingCommits)*3)
	for i, pc := range w.pendingCommits {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("(?,?,?)")
		args = append(args, w.branchID, commitIDs[pc.info.SHA], pc.position)
	}

	_, err := tx.Exec(sb.String(), args...)
	return err
}

func (w *BatchWriter) ensureManifests(tx *sql.Tx, now time.Time) error {
	// Collect unique manifests from changes and snapshots
	manifests := make(map[string]ManifestInfo)
	for _, pc := range w.pendingChanges {
		manifests[pc.manifest.Path] = pc.manifest
	}
	for _, ps := range w.pendingSnapshots {
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

	args := make([]any, 0, len(toInsert)*5)
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
	defer rows.Close()

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

func (w *BatchWriter) insertChanges(tx *sql.Tx, commitIDs map[string]int64, now time.Time) error {
	if len(w.pendingChanges) == 0 {
		return nil
	}

	// Changes have 11 columns, so max rows per batch = MaxSQLVariables / 11
	const columnsPerRow = 11
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(w.pendingChanges); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(w.pendingChanges) {
			end = len(w.pendingChanges)
		}
		batch := w.pendingChanges[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT INTO dependency_changes (commit_id, manifest_id, name, ecosystem, purl, change_type, requirement, previous_requirement, dependency_type, created_at, updated_at) VALUES ")

		args := make([]any, 0, len(batch)*columnsPerRow)
		for i, pc := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?,?,?,?,?,?,?)")
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

func (w *BatchWriter) insertSnapshots(tx *sql.Tx, commitIDs map[string]int64, now time.Time) error {
	if len(w.pendingSnapshots) == 0 {
		return nil
	}

	// Snapshots have 10 columns, so max rows per batch = MaxSQLVariables / 10
	const columnsPerRow = 10
	maxRowsPerBatch := MaxSQLVariables / columnsPerRow

	for start := 0; start < len(w.pendingSnapshots); start += maxRowsPerBatch {
		end := start + maxRowsPerBatch
		if end > len(w.pendingSnapshots) {
			end = len(w.pendingSnapshots)
		}
		batch := w.pendingSnapshots[start:end]

		var sb strings.Builder
		sb.WriteString("INSERT INTO dependency_snapshots (commit_id, manifest_id, name, ecosystem, purl, requirement, dependency_type, integrity, created_at, updated_at) VALUES ")

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

func (w *BatchWriter) LastSHA() string {
	return w.lastSHA
}

func (w *BatchWriter) HasPendingSnapshots(sha string) bool {
	for _, ps := range w.pendingSnapshots {
		if ps.sha == sha {
			return true
		}
	}
	return false
}
