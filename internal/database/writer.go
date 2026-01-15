package database

import (
	"database/sql"
	"time"
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
	ManifestPath        string
	Name                string
	Ecosystem           string
	PURL                string
	ChangeType          string
	Requirement         string
	PreviousRequirement string
	DependencyType      string
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

type Writer struct {
	db              *DB
	branchID        int64
	commitStmt      *sql.Stmt
	branchCommitStmt *sql.Stmt
	manifestStmt    *sql.Stmt
	changeStmt      *sql.Stmt
	snapshotStmt    *sql.Stmt
	manifestCache   map[string]int64
	position        int
}

func NewWriter(db *DB) (*Writer, error) {
	commitStmt, err := db.Prepare(`
		INSERT INTO commits (sha, message, author_name, author_email, committed_at, has_dependency_changes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}

	branchCommitStmt, err := db.Prepare(`
		INSERT INTO branch_commits (branch_id, commit_id, position)
		VALUES (?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}

	manifestStmt, err := db.Prepare(`
		INSERT INTO manifests (path, ecosystem, kind, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}

	changeStmt, err := db.Prepare(`
		INSERT INTO dependency_changes (commit_id, manifest_id, name, ecosystem, purl, change_type, requirement, previous_requirement, dependency_type, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}

	snapshotStmt, err := db.Prepare(`
		INSERT INTO dependency_snapshots (commit_id, manifest_id, name, ecosystem, purl, requirement, dependency_type, integrity, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return nil, err
	}

	return &Writer{
		db:              db,
		commitStmt:      commitStmt,
		branchCommitStmt: branchCommitStmt,
		manifestStmt:    manifestStmt,
		changeStmt:      changeStmt,
		snapshotStmt:    snapshotStmt,
		manifestCache:   make(map[string]int64),
	}, nil
}

func (w *Writer) Close() error {
	var firstErr error
	for _, stmt := range []*sql.Stmt{w.commitStmt, w.branchCommitStmt, w.manifestStmt, w.changeStmt, w.snapshotStmt} {
		if stmt != nil {
			if err := stmt.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (w *Writer) CreateBranch(name string) error {
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

func (w *Writer) UseBranch(branchID int64) error {
	w.branchID = branchID

	// Load the max position for this branch
	pos, err := w.db.GetMaxPosition(branchID)
	if err != nil {
		return err
	}
	w.position = pos

	return nil
}

func (w *Writer) UpdateBranchLastSHA(sha string) error {
	_, err := w.db.Exec(
		"UPDATE branches SET last_analyzed_sha = ?, updated_at = ? WHERE id = ?",
		sha, time.Now(), w.branchID,
	)
	return err
}

// InsertCommit inserts a commit and links it to the current branch.
// Returns (commitID, wasNew, error) where wasNew indicates if this was a newly inserted commit.
// If the commit already exists (from another branch), it returns wasNew=false.
func (w *Writer) InsertCommit(info CommitInfo, hasChanges bool) (int64, bool, error) {
	now := time.Now()
	hasChangesInt := 0
	if hasChanges {
		hasChangesInt = 1
	}

	// Check if commit already exists (from another branch)
	var existingID int64
	err := w.db.QueryRow("SELECT id FROM commits WHERE sha = ?", info.SHA).Scan(&existingID)
	if err == nil {
		// Commit exists, just link it to this branch
		w.position++
		_, err = w.branchCommitStmt.Exec(w.branchID, existingID, w.position)
		if err != nil {
			return 0, false, err
		}
		return existingID, false, nil
	}

	// Commit doesn't exist, insert it
	result, err := w.commitStmt.Exec(
		info.SHA,
		info.Message,
		info.AuthorName,
		info.AuthorEmail,
		info.CommittedAt,
		hasChangesInt,
		now,
		now,
	)
	if err != nil {
		return 0, false, err
	}

	commitID, err := result.LastInsertId()
	if err != nil {
		return 0, false, err
	}

	w.position++
	_, err = w.branchCommitStmt.Exec(w.branchID, commitID, w.position)
	if err != nil {
		return 0, false, err
	}

	return commitID, true, nil
}

func (w *Writer) getOrCreateManifest(info ManifestInfo) (int64, error) {
	if id, ok := w.manifestCache[info.Path]; ok {
		return id, nil
	}

	now := time.Now()
	result, err := w.manifestStmt.Exec(info.Path, info.Ecosystem, info.Kind, now, now)
	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}

	w.manifestCache[info.Path] = id
	return id, nil
}

func (w *Writer) InsertChange(commitID int64, manifest ManifestInfo, change ChangeInfo) error {
	manifestID, err := w.getOrCreateManifest(manifest)
	if err != nil {
		return err
	}

	now := time.Now()
	_, err = w.changeStmt.Exec(
		commitID,
		manifestID,
		change.Name,
		change.Ecosystem,
		change.PURL,
		change.ChangeType,
		change.Requirement,
		change.PreviousRequirement,
		change.DependencyType,
		now,
		now,
	)
	return err
}

func (w *Writer) InsertSnapshot(commitID int64, manifest ManifestInfo, snapshot SnapshotInfo) error {
	manifestID, err := w.getOrCreateManifest(manifest)
	if err != nil {
		return err
	}

	now := time.Now()
	_, err = w.snapshotStmt.Exec(
		commitID,
		manifestID,
		snapshot.Name,
		snapshot.Ecosystem,
		snapshot.PURL,
		snapshot.Requirement,
		snapshot.DependencyType,
		snapshot.Integrity,
		now,
		now,
	)
	return err
}

func (w *Writer) BeginTransaction() (*sql.Tx, error) {
	return w.db.Begin()
}
