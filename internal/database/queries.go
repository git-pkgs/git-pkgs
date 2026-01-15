package database

import (
	"database/sql"
	"fmt"
)

type BranchInfo struct {
	ID              int64
	Name            string
	LastAnalyzedSHA string
	LastSHA         string // Alias for LastAnalyzedSHA
	CommitCount     int
}

func (db *DB) GetBranch(name string) (*BranchInfo, error) {
	var info BranchInfo
	var lastSHA sql.NullString

	err := db.QueryRow(
		"SELECT id, name, last_analyzed_sha FROM branches WHERE name = ?",
		name,
	).Scan(&info.ID, &info.Name, &lastSHA)
	if err != nil {
		return nil, err
	}

	if lastSHA.Valid {
		info.LastAnalyzedSHA = lastSHA.String
	}

	return &info, nil
}

func (db *DB) GetDefaultBranch() (*BranchInfo, error) {
	var info BranchInfo
	var lastSHA sql.NullString

	err := db.QueryRow(
		"SELECT id, name, last_analyzed_sha FROM branches ORDER BY id LIMIT 1",
	).Scan(&info.ID, &info.Name, &lastSHA)
	if err != nil {
		return nil, err
	}

	if lastSHA.Valid {
		info.LastAnalyzedSHA = lastSHA.String
		info.LastSHA = lastSHA.String
	}

	return &info, nil
}

func (db *DB) GetBranches() ([]BranchInfo, error) {
	rows, err := db.Query(`
		SELECT b.id, b.name, b.last_analyzed_sha, COUNT(bc.id) as commit_count
		FROM branches b
		LEFT JOIN branch_commits bc ON bc.branch_id = b.id
		GROUP BY b.id, b.name, b.last_analyzed_sha
		ORDER BY b.name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var branches []BranchInfo
	for rows.Next() {
		var info BranchInfo
		var lastSHA sql.NullString

		if err := rows.Scan(&info.ID, &info.Name, &lastSHA, &info.CommitCount); err != nil {
			return nil, err
		}

		if lastSHA.Valid {
			info.LastAnalyzedSHA = lastSHA.String
			info.LastSHA = lastSHA.String
		}

		branches = append(branches, info)
	}

	return branches, rows.Err()
}

func (db *DB) RemoveBranch(name string) error {
	// Get branch ID
	var branchID int64
	err := db.QueryRow("SELECT id FROM branches WHERE name = ?", name).Scan(&branchID)
	if err == sql.ErrNoRows {
		return fmt.Errorf("branch %q not found", name)
	}
	if err != nil {
		return err
	}

	// Delete branch_commits entries (this doesn't delete the commits themselves,
	// as they may be shared with other branches)
	_, err = db.Exec("DELETE FROM branch_commits WHERE branch_id = ?", branchID)
	if err != nil {
		return fmt.Errorf("deleting branch commits: %w", err)
	}

	// Delete the branch record
	_, err = db.Exec("DELETE FROM branches WHERE id = ?", branchID)
	if err != nil {
		return fmt.Errorf("deleting branch: %w", err)
	}

	return nil
}

func (db *DB) GetLastSnapshot(branchID int64) (map[string]SnapshotInfo, error) {
	// Get the most recent commit with snapshots for this branch
	var commitID int64
	err := db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		WHERE bc.branch_id = ?
		ORDER BY bc.position DESC
		LIMIT 1
	`, branchID).Scan(&commitID)
	if err == sql.ErrNoRows {
		return make(map[string]SnapshotInfo), nil
	}
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(`
		SELECT m.path, ds.name, ds.ecosystem, ds.purl, ds.requirement, ds.dependency_type, ds.integrity
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE ds.commit_id = ?
	`, commitID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]SnapshotInfo)
	for rows.Next() {
		var path, name string
		var info SnapshotInfo
		var ecosystem, purl, requirement, depType, integrity sql.NullString

		if err := rows.Scan(&path, &name, &ecosystem, &purl, &requirement, &depType, &integrity); err != nil {
			return nil, err
		}

		info.ManifestPath = path
		info.Name = name
		if ecosystem.Valid {
			info.Ecosystem = ecosystem.String
		}
		if purl.Valid {
			info.PURL = purl.String
		}
		if requirement.Valid {
			info.Requirement = requirement.String
		}
		if depType.Valid {
			info.DependencyType = depType.String
		}
		if integrity.Valid {
			info.Integrity = integrity.String
		}

		key := path + ":" + name
		result[key] = info
	}

	return result, rows.Err()
}

func (db *DB) GetMaxPosition(branchID int64) (int, error) {
	var position sql.NullInt64
	err := db.QueryRow(
		"SELECT MAX(position) FROM branch_commits WHERE branch_id = ?",
		branchID,
	).Scan(&position)
	if err != nil {
		return 0, err
	}
	if position.Valid {
		return int(position.Int64), nil
	}
	return 0, nil
}

type Dependency struct {
	Name           string
	Ecosystem      string
	PURL           string
	Requirement    string
	DependencyType string
	Integrity      string
	ManifestPath   string
	ManifestKind   string
}

func (db *DB) GetDependenciesAtCommit(sha string) ([]Dependency, error) {
	// Find the most recent snapshot at or before this commit
	var commitID int64
	err := db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN commits c ON c.id = ds.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha <= ?
		ORDER BY bc.position DESC
		LIMIT 1
	`, sha).Scan(&commitID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return db.getDependenciesForCommitID(commitID)
}

func (db *DB) GetDependenciesAtRef(ref string, branchID int64) ([]Dependency, error) {
	// Find the commit ID for this ref on this branch
	var commitID int64
	err := db.QueryRow(`
		SELECT c.id
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha = ? AND bc.branch_id = ?
	`, ref, branchID).Scan(&commitID)
	if err == sql.ErrNoRows {
		// Ref not found, try to find closest snapshot
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Get the snapshot for this commit, or the most recent one before it
	var snapshotCommitID int64
	err = db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		JOIN branch_commits target_bc ON target_bc.commit_id = ?
		WHERE bc.branch_id = ? AND bc.position <= target_bc.position
		GROUP BY ds.commit_id
		ORDER BY bc.position DESC
		LIMIT 1
	`, commitID, branchID).Scan(&snapshotCommitID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return db.getDependenciesForCommitID(snapshotCommitID)
}

func (db *DB) GetLatestDependencies(branchID int64) ([]Dependency, error) {
	// Get the most recent snapshot for this branch
	var commitID int64
	err := db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		WHERE bc.branch_id = ?
		ORDER BY bc.position DESC
		LIMIT 1
	`, branchID).Scan(&commitID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return db.getDependenciesForCommitID(commitID)
}

func (db *DB) getDependenciesForCommitID(commitID int64) ([]Dependency, error) {
	rows, err := db.Query(`
		SELECT ds.name, ds.ecosystem, ds.purl, ds.requirement, ds.dependency_type, ds.integrity, m.path, m.kind
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE ds.commit_id = ?
		ORDER BY m.path, ds.name
	`, commitID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var deps []Dependency
	for rows.Next() {
		var d Dependency
		var ecosystem, purl, requirement, depType, integrity, kind sql.NullString

		if err := rows.Scan(&d.Name, &ecosystem, &purl, &requirement, &depType, &integrity, &d.ManifestPath, &kind); err != nil {
			return nil, err
		}

		if ecosystem.Valid {
			d.Ecosystem = ecosystem.String
		}
		if purl.Valid {
			d.PURL = purl.String
		}
		if requirement.Valid {
			d.Requirement = requirement.String
		}
		if depType.Valid {
			d.DependencyType = depType.String
		}
		if integrity.Valid {
			d.Integrity = integrity.String
		}
		if kind.Valid {
			d.ManifestKind = kind.String
		}

		deps = append(deps, d)
	}

	return deps, rows.Err()
}

func (db *DB) GetCommitID(sha string) (int64, error) {
	var id int64
	err := db.QueryRow("SELECT id FROM commits WHERE sha = ?", sha).Scan(&id)
	return id, err
}

type Change struct {
	Name                string
	Ecosystem           string
	PURL                string
	ChangeType          string
	Requirement         string
	PreviousRequirement string
	DependencyType      string
	ManifestPath        string
}

type CommitWithChanges struct {
	SHA         string
	Message     string
	AuthorName  string
	AuthorEmail string
	CommittedAt string
	Changes     []Change
}

type LogOptions struct {
	BranchID  int64
	Ecosystem string
	Author    string
	Since     string
	Until     string
	Limit     int
}

func (db *DB) GetCommitsWithChanges(opts LogOptions) ([]CommitWithChanges, error) {
	query := `
		SELECT DISTINCT c.sha, c.message, c.author_name, c.author_email, c.committed_at
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN dependency_changes dc ON dc.commit_id = c.id
		WHERE bc.branch_id = ?
	`
	args := []any{opts.BranchID}

	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Author != "" {
		query += " AND (c.author_name LIKE ? OR c.author_email LIKE ?)"
		pattern := "%" + opts.Author + "%"
		args = append(args, pattern, pattern)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}

	query += " ORDER BY bc.position DESC"

	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var commits []CommitWithChanges
	for rows.Next() {
		var c CommitWithChanges
		var message, authorName, authorEmail sql.NullString

		if err := rows.Scan(&c.SHA, &message, &authorName, &authorEmail, &c.CommittedAt); err != nil {
			return nil, err
		}

		if message.Valid {
			c.Message = message.String
		}
		if authorName.Valid {
			c.AuthorName = authorName.String
		}
		if authorEmail.Valid {
			c.AuthorEmail = authorEmail.String
		}

		commits = append(commits, c)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load changes for each commit
	for i := range commits {
		changes, err := db.GetChangesForCommit(commits[i].SHA)
		if err != nil {
			return nil, err
		}

		// Filter by ecosystem if needed
		if opts.Ecosystem != "" {
			var filtered []Change
			for _, ch := range changes {
				if ch.Ecosystem == opts.Ecosystem {
					filtered = append(filtered, ch)
				}
			}
			changes = filtered
		}

		commits[i].Changes = changes
	}

	return commits, nil
}

type HistoryEntry struct {
	SHA                 string
	Message             string
	AuthorName          string
	AuthorEmail         string
	CommittedAt         string
	Name                string
	Ecosystem           string
	ChangeType          string
	Requirement         string
	PreviousRequirement string
	ManifestPath        string
}

type HistoryOptions struct {
	BranchID    int64
	PackageName string
	Ecosystem   string
	Author      string
	Since       string
	Until       string
}

type BlameEntry struct {
	Name         string
	Ecosystem    string
	Requirement  string
	ManifestPath string
	SHA          string
	AuthorName   string
	AuthorEmail  string
	CommittedAt  string
}

type WhyResult struct {
	Name         string
	Ecosystem    string
	ManifestPath string
	SHA          string
	Message      string
	AuthorName   string
	AuthorEmail  string
	CommittedAt  string
}

type SearchResult struct {
	Name        string
	Ecosystem   string
	Requirement string
	FirstSeen   string
	LastChanged string
	AddedIn     string
	ManifestKind string
}

type Stats struct {
	Branch             string
	CommitsAnalyzed    int
	CommitsWithChanges int
	CurrentDeps        int
	DepsByEcosystem    map[string]int
	TotalChanges       int
	ChangesByType      map[string]int
	TopChanged         []NameCount
	TopAuthors         []NameCount
}

type NameCount struct {
	Name  string
	Count int
}

type AuthorStats struct {
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Commits  int            `json:"commits"`
	Changes  int            `json:"changes"`
	ByType   map[string]int `json:"by_type"`
}

type StatsOptions struct {
	BranchID  int64
	Ecosystem string
	Since     string
	Until     string
	Limit     int
}

type StaleEntry struct {
	Name         string
	Ecosystem    string
	Requirement  string
	ManifestPath string
	LastChanged  string
	DaysSince    int
}

type DatabaseInfo struct {
	Path               string
	SizeBytes          int64
	SchemaVersion      int
	BranchName         string
	LastAnalyzedSHA    string
	RowCounts          map[string]int
	Ecosystems         []string
}

func (db *DB) GetDatabaseInfo() (*DatabaseInfo, error) {
	info := &DatabaseInfo{
		Path:      db.path,
		RowCounts: make(map[string]int),
	}

	// Schema version
	version, err := db.SchemaVersion()
	if err != nil {
		return nil, err
	}
	info.SchemaVersion = version

	// Get branch info
	branchInfo, err := db.GetDefaultBranch()
	if err == nil {
		info.BranchName = branchInfo.Name
		info.LastAnalyzedSHA = branchInfo.LastAnalyzedSHA
	}

	// Row counts for main tables
	tables := []string{"branches", "commits", "branch_commits", "manifests", "dependency_changes", "dependency_snapshots"}
	for _, table := range tables {
		var count int
		err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			continue
		}
		info.RowCounts[table] = count
	}

	// Ecosystems
	rows, err := db.Query(`
		SELECT DISTINCT ecosystem FROM dependency_changes WHERE ecosystem IS NOT NULL AND ecosystem != ''
		UNION
		SELECT DISTINCT ecosystem FROM dependency_snapshots WHERE ecosystem IS NOT NULL AND ecosystem != ''
	`)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var eco string
			if rows.Scan(&eco) == nil && eco != "" {
				info.Ecosystems = append(info.Ecosystems, eco)
			}
		}
	}

	return info, nil
}

func (db *DB) GetStaleDependencies(branchID int64, ecosystem string, days int) ([]StaleEntry, error) {
	query := `
		WITH current_deps AS (
			SELECT DISTINCT ds.name, ds.ecosystem, ds.requirement, m.path, m.kind
			FROM dependency_snapshots ds
			JOIN manifests m ON m.id = ds.manifest_id
			JOIN branch_commits bc ON bc.commit_id = ds.commit_id
			WHERE bc.branch_id = ?
			AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
			AND m.kind = 'lockfile'
		),
		last_changed AS (
			SELECT dc.name, m.path, MAX(c.committed_at) as last_changed
			FROM dependency_changes dc
			JOIN commits c ON c.id = dc.commit_id
			JOIN branch_commits bc ON bc.commit_id = c.id
			JOIN manifests m ON m.id = dc.manifest_id
			WHERE bc.branch_id = ?
			GROUP BY dc.name, m.path
		)
		SELECT cd.name, cd.ecosystem, cd.requirement, cd.path,
		       COALESCE(lc.last_changed, '') as last_changed,
		       CAST(julianday('now') - julianday(COALESCE(lc.last_changed, '2000-01-01')) AS INTEGER) as days_since
		FROM current_deps cd
		LEFT JOIN last_changed lc ON lc.name = cd.name AND lc.path = cd.path
	`
	args := []any{branchID, branchID, branchID}

	if ecosystem != "" {
		query += " WHERE cd.ecosystem = ?"
		args = append(args, ecosystem)
	}

	if days > 0 {
		if ecosystem != "" {
			query += " AND"
		} else {
			query += " WHERE"
		}
		query += " CAST(julianday('now') - julianday(COALESCE(lc.last_changed, '2000-01-01')) AS INTEGER) >= ?"
		args = append(args, days)
	}

	query += " ORDER BY days_since DESC, cd.name"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []StaleEntry
	for rows.Next() {
		var e StaleEntry
		var eco, req sql.NullString

		if err := rows.Scan(&e.Name, &eco, &req, &e.ManifestPath, &e.LastChanged, &e.DaysSince); err != nil {
			return nil, err
		}

		if eco.Valid {
			e.Ecosystem = eco.String
		}
		if req.Valid {
			e.Requirement = req.String
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}

func (db *DB) GetStats(opts StatsOptions) (*Stats, error) {
	stats := &Stats{
		DepsByEcosystem: make(map[string]int),
		ChangesByType:   make(map[string]int),
	}

	// Get branch name
	var branchName sql.NullString
	err := db.QueryRow("SELECT name FROM branches WHERE id = ?", opts.BranchID).Scan(&branchName)
	if err != nil {
		return nil, err
	}
	if branchName.Valid {
		stats.Branch = branchName.String
	}

	// Commits analyzed
	err = db.QueryRow(`
		SELECT COUNT(*) FROM branch_commits WHERE branch_id = ?
	`, opts.BranchID).Scan(&stats.CommitsAnalyzed)
	if err != nil {
		return nil, err
	}

	// Commits with changes
	query := `
		SELECT COUNT(DISTINCT c.id)
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN dependency_changes dc ON dc.commit_id = c.id
		WHERE bc.branch_id = ?
	`
	args := []any{opts.BranchID}
	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}
	err = db.QueryRow(query, args...).Scan(&stats.CommitsWithChanges)
	if err != nil {
		return nil, err
	}

	// Current deps count
	err = db.QueryRow(`
		SELECT COUNT(DISTINCT ds.name || '|' || m.path)
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		WHERE bc.branch_id = ?
		AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
	`, opts.BranchID, opts.BranchID).Scan(&stats.CurrentDeps)
	if err != nil {
		return nil, err
	}

	// Deps by ecosystem
	rows, err := db.Query(`
		SELECT ds.ecosystem, COUNT(DISTINCT ds.name || '|' || m.path)
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		WHERE bc.branch_id = ?
		AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
		GROUP BY ds.ecosystem
	`, opts.BranchID, opts.BranchID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var eco sql.NullString
		var count int
		if err := rows.Scan(&eco, &count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if eco.Valid && eco.String != "" {
			stats.DepsByEcosystem[eco.String] = count
		}
	}
	_ = rows.Close()

	// Total changes and changes by type
	query = `
		SELECT dc.change_type, COUNT(*)
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE bc.branch_id = ?
	`
	args = []any{opts.BranchID}
	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}
	query += " GROUP BY dc.change_type"

	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var changeType string
		var count int
		if err := rows.Scan(&changeType, &count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		stats.ChangesByType[changeType] = count
		stats.TotalChanges += count
	}
	_ = rows.Close()

	// Top changed dependencies
	limit := opts.Limit
	if limit == 0 {
		limit = 10
	}

	query = `
		SELECT dc.name, COUNT(*) as cnt
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE bc.branch_id = ?
	`
	args = []any{opts.BranchID}
	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}
	query += " GROUP BY dc.name ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)

	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var nc NameCount
		if err := rows.Scan(&nc.Name, &nc.Count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		stats.TopChanged = append(stats.TopChanged, nc)
	}
	_ = rows.Close()

	// Top authors
	query = `
		SELECT c.author_name, COUNT(DISTINCT dc.id) as cnt
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE bc.branch_id = ?
	`
	args = []any{opts.BranchID}
	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}
	query += " GROUP BY c.author_name ORDER BY cnt DESC LIMIT ?"
	args = append(args, limit)

	rows, err = db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var nc NameCount
		var name sql.NullString
		if err := rows.Scan(&name, &nc.Count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if name.Valid {
			nc.Name = name.String
		}
		stats.TopAuthors = append(stats.TopAuthors, nc)
	}
	_ = rows.Close()

	return stats, nil
}

func (db *DB) GetAuthorStats(opts StatsOptions) ([]AuthorStats, error) {
	query := `
		SELECT c.author_name, c.author_email,
		       COUNT(DISTINCT c.id) as commits,
		       COUNT(dc.id) as changes,
		       SUM(CASE WHEN dc.change_type = 'added' THEN 1 ELSE 0 END) as added,
		       SUM(CASE WHEN dc.change_type = 'modified' THEN 1 ELSE 0 END) as modified,
		       SUM(CASE WHEN dc.change_type = 'removed' THEN 1 ELSE 0 END) as removed
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN dependency_changes dc ON dc.commit_id = c.id
	`
	args := []any{opts.BranchID}
	query += " WHERE bc.branch_id = ?"

	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}

	query += " GROUP BY c.author_name, c.author_email ORDER BY changes DESC"
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []AuthorStats
	for rows.Next() {
		var as AuthorStats
		var name, email sql.NullString
		var added, modified, removed int
		if err := rows.Scan(&name, &email, &as.Commits, &as.Changes, &added, &modified, &removed); err != nil {
			return nil, err
		}
		if name.Valid {
			as.Name = name.String
		}
		if email.Valid {
			as.Email = email.String
		}
		as.ByType = map[string]int{
			"added":    added,
			"modified": modified,
			"removed":  removed,
		}
		results = append(results, as)
	}

	return results, rows.Err()
}

func (db *DB) SearchDependencies(branchID int64, pattern, ecosystem string, directOnly bool) ([]SearchResult, error) {
	// Get current dependencies matching pattern, with first seen and last changed dates
	query := `
		WITH current_deps AS (
			SELECT DISTINCT ds.name, ds.ecosystem, ds.requirement, m.kind
			FROM dependency_snapshots ds
			JOIN manifests m ON m.id = ds.manifest_id
			JOIN branch_commits bc ON bc.commit_id = ds.commit_id
			WHERE bc.branch_id = ?
			AND bc.position = (
				SELECT MAX(bc2.position)
				FROM branch_commits bc2
				JOIN dependency_snapshots ds2 ON ds2.commit_id = bc2.commit_id
				WHERE bc2.branch_id = ?
			)
			AND ds.name LIKE ?
	`
	args := []any{branchID, branchID, "%" + pattern + "%"}

	if ecosystem != "" {
		query += " AND ds.ecosystem = ?"
		args = append(args, ecosystem)
	}

	if directOnly {
		query += " AND m.kind = 'manifest'"
	}

	query += `
		),
		first_added AS (
			SELECT dc.name, MIN(c.committed_at) as first_seen, MIN(c.sha) as added_in
			FROM dependency_changes dc
			JOIN commits c ON c.id = dc.commit_id
			JOIN branch_commits bc ON bc.commit_id = c.id
			WHERE bc.branch_id = ? AND dc.change_type = 'added'
			GROUP BY dc.name
		),
		last_changed AS (
			SELECT dc.name, MAX(c.committed_at) as last_changed
			FROM dependency_changes dc
			JOIN commits c ON c.id = dc.commit_id
			JOIN branch_commits bc ON bc.commit_id = c.id
			WHERE bc.branch_id = ?
			GROUP BY dc.name
		)
		SELECT cd.name, cd.ecosystem, cd.requirement, cd.kind,
		       COALESCE(fa.first_seen, ''), COALESCE(lc.last_changed, ''), COALESCE(fa.added_in, '')
		FROM current_deps cd
		LEFT JOIN first_added fa ON fa.name = cd.name
		LEFT JOIN last_changed lc ON lc.name = cd.name
		ORDER BY cd.name
	`
	args = append(args, branchID, branchID)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var eco, req, kind sql.NullString

		if err := rows.Scan(&r.Name, &eco, &req, &kind, &r.FirstSeen, &r.LastChanged, &r.AddedIn); err != nil {
			return nil, err
		}

		if eco.Valid {
			r.Ecosystem = eco.String
		}
		if req.Valid {
			r.Requirement = req.String
		}
		if kind.Valid {
			r.ManifestKind = kind.String
		}

		results = append(results, r)
	}

	return results, rows.Err()
}

func (db *DB) GetWhy(branchID int64, packageName, ecosystem string) (*WhyResult, error) {
	query := `
		SELECT dc.name, dc.ecosystem, m.path, c.sha, c.message, c.author_name, c.author_email, c.committed_at
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN manifests m ON m.id = dc.manifest_id
		WHERE bc.branch_id = ? AND dc.change_type = 'added' AND dc.name = ?
	`
	args := []any{branchID, packageName}

	if ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, ecosystem)
	}

	query += " ORDER BY bc.position ASC LIMIT 1"

	var r WhyResult
	var eco, message, authorName, authorEmail sql.NullString

	err := db.QueryRow(query, args...).Scan(
		&r.Name, &eco, &r.ManifestPath, &r.SHA,
		&message, &authorName, &authorEmail, &r.CommittedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if eco.Valid {
		r.Ecosystem = eco.String
	}
	if message.Valid {
		r.Message = message.String
	}
	if authorName.Valid {
		r.AuthorName = authorName.String
	}
	if authorEmail.Valid {
		r.AuthorEmail = authorEmail.String
	}

	return &r, nil
}

func (db *DB) GetBlame(branchID int64, ecosystem string) ([]BlameEntry, error) {
	// For each current dependency, find the commit that added it
	query := `
		WITH current_deps AS (
			SELECT DISTINCT ds.name, ds.ecosystem, ds.requirement, m.path as manifest_path
			FROM dependency_snapshots ds
			JOIN manifests m ON m.id = ds.manifest_id
			JOIN branch_commits bc ON bc.commit_id = ds.commit_id
			WHERE bc.branch_id = ?
			AND bc.position = (
				SELECT MAX(bc2.position)
				FROM branch_commits bc2
				JOIN dependency_snapshots ds2 ON ds2.commit_id = bc2.commit_id
				WHERE bc2.branch_id = ?
			)
		),
		first_added AS (
			SELECT dc.name, m.path as manifest_path, MIN(bc.position) as first_pos
			FROM dependency_changes dc
			JOIN commits c ON c.id = dc.commit_id
			JOIN branch_commits bc ON bc.commit_id = c.id
			JOIN manifests m ON m.id = dc.manifest_id
			WHERE bc.branch_id = ? AND dc.change_type = 'added'
			GROUP BY dc.name, m.path
		)
		SELECT cd.name, cd.ecosystem, cd.requirement, cd.manifest_path,
		       c.sha, c.author_name, c.author_email, c.committed_at
		FROM current_deps cd
		JOIN first_added fa ON fa.name = cd.name AND fa.manifest_path = cd.manifest_path
		JOIN branch_commits bc ON bc.branch_id = ? AND bc.position = fa.first_pos
		JOIN commits c ON c.id = bc.commit_id
	`
	args := []any{branchID, branchID, branchID, branchID}

	if ecosystem != "" {
		query += " WHERE cd.ecosystem = ?"
		args = append(args, ecosystem)
	}

	query += " ORDER BY cd.manifest_path, cd.name"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []BlameEntry
	for rows.Next() {
		var e BlameEntry
		var ecosystem, requirement, authorName, authorEmail sql.NullString

		if err := rows.Scan(&e.Name, &ecosystem, &requirement, &e.ManifestPath,
			&e.SHA, &authorName, &authorEmail, &e.CommittedAt); err != nil {
			return nil, err
		}

		if ecosystem.Valid {
			e.Ecosystem = ecosystem.String
		}
		if requirement.Valid {
			e.Requirement = requirement.String
		}
		if authorName.Valid {
			e.AuthorName = authorName.String
		}
		if authorEmail.Valid {
			e.AuthorEmail = authorEmail.String
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}

func (db *DB) GetPackageHistory(opts HistoryOptions) ([]HistoryEntry, error) {
	query := `
		SELECT c.sha, c.message, c.author_name, c.author_email, c.committed_at,
		       dc.name, dc.ecosystem, dc.change_type, dc.requirement, dc.previous_requirement, m.path
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN manifests m ON m.id = dc.manifest_id
		WHERE bc.branch_id = ?
	`
	args := []any{opts.BranchID}

	if opts.PackageName != "" {
		query += " AND dc.name LIKE ?"
		args = append(args, "%"+opts.PackageName+"%")
	}
	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.Author != "" {
		query += " AND (c.author_name LIKE ? OR c.author_email LIKE ?)"
		pattern := "%" + opts.Author + "%"
		args = append(args, pattern, pattern)
	}
	if opts.Since != "" {
		query += " AND c.committed_at >= ?"
		args = append(args, opts.Since)
	}
	if opts.Until != "" {
		query += " AND c.committed_at <= ?"
		args = append(args, opts.Until)
	}

	query += " ORDER BY bc.position ASC, dc.name"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var message, authorName, authorEmail, ecosystem, requirement, prevReq sql.NullString

		if err := rows.Scan(&e.SHA, &message, &authorName, &authorEmail, &e.CommittedAt,
			&e.Name, &ecosystem, &e.ChangeType, &requirement, &prevReq, &e.ManifestPath); err != nil {
			return nil, err
		}

		if message.Valid {
			e.Message = message.String
		}
		if authorName.Valid {
			e.AuthorName = authorName.String
		}
		if authorEmail.Valid {
			e.AuthorEmail = authorEmail.String
		}
		if ecosystem.Valid {
			e.Ecosystem = ecosystem.String
		}
		if requirement.Valid {
			e.Requirement = requirement.String
		}
		if prevReq.Valid {
			e.PreviousRequirement = prevReq.String
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}

func (db *DB) GetChangesForCommit(sha string) ([]Change, error) {
	rows, err := db.Query(`
		SELECT dc.name, dc.ecosystem, dc.purl, dc.change_type, dc.requirement, dc.previous_requirement, dc.dependency_type, m.path
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN manifests m ON m.id = dc.manifest_id
		WHERE c.sha = ?
		ORDER BY m.path, dc.name
	`, sha)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var changes []Change
	for rows.Next() {
		var c Change
		var ecosystem, purl, requirement, prevReq, depType sql.NullString

		if err := rows.Scan(&c.Name, &ecosystem, &purl, &c.ChangeType, &requirement, &prevReq, &depType, &c.ManifestPath); err != nil {
			return nil, err
		}

		if ecosystem.Valid {
			c.Ecosystem = ecosystem.String
		}
		if purl.Valid {
			c.PURL = purl.String
		}
		if requirement.Valid {
			c.Requirement = requirement.String
		}
		if prevReq.Valid {
			c.PreviousRequirement = prevReq.String
		}
		if depType.Valid {
			c.DependencyType = depType.String
		}

		changes = append(changes, c)
	}

	return changes, rows.Err()
}

// Vulnerability represents a stored vulnerability record.
type Vulnerability struct {
	ID           string
	Aliases      []string
	Severity     string
	CVSSScore    float64
	CVSSVector   string
	References   []string
	Summary      string
	Details      string
	PublishedAt  string
	WithdrawnAt  string
	ModifiedAt   string
	FetchedAt    string
}

// VulnerabilityPackage represents a package affected by a vulnerability.
type VulnerabilityPackage struct {
	VulnerabilityID  string
	Ecosystem        string
	PackageName      string
	AffectedVersions string // vers range string
	FixedVersions    string // comma-separated list
}

// VulnSyncStatus tracks when vulnerabilities were last synced for a package.
type VulnSyncStatus struct {
	Ecosystem   string
	PackageName string
	SyncedAt    string
	VulnCount   int
}

// GetVulnerabilitiesForPackage returns all vulnerabilities affecting a specific package.
func (db *DB) GetVulnerabilitiesForPackage(ecosystem, packageName string) ([]Vulnerability, error) {
	rows, err := db.Query(`
		SELECT v.id, v.aliases, v.severity, v.cvss_score, v.cvss_vector, v.refs,
		       v.summary, v.details, v.published_at, v.withdrawn_at, v.modified_at, v.fetched_at
		FROM vulnerabilities v
		JOIN vulnerability_packages vp ON vp.vulnerability_id = v.id
		WHERE vp.ecosystem = ? AND vp.package_name = ?
		ORDER BY v.cvss_score DESC, v.id
	`, ecosystem, packageName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var vulns []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var aliases, refs sql.NullString
		var severity, cvssVector, summary, details sql.NullString
		var publishedAt, withdrawnAt, modifiedAt sql.NullString
		var cvssScore sql.NullFloat64

		if err := rows.Scan(&v.ID, &aliases, &severity, &cvssScore, &cvssVector, &refs,
			&summary, &details, &publishedAt, &withdrawnAt, &modifiedAt, &v.FetchedAt); err != nil {
			return nil, err
		}

		if aliases.Valid && aliases.String != "" {
			v.Aliases = splitCommaList(aliases.String)
		}
		if refs.Valid && refs.String != "" {
			v.References = splitCommaList(refs.String)
		}
		if severity.Valid {
			v.Severity = severity.String
		}
		if cvssScore.Valid {
			v.CVSSScore = cvssScore.Float64
		}
		if cvssVector.Valid {
			v.CVSSVector = cvssVector.String
		}
		if summary.Valid {
			v.Summary = summary.String
		}
		if details.Valid {
			v.Details = details.String
		}
		if publishedAt.Valid {
			v.PublishedAt = publishedAt.String
		}
		if withdrawnAt.Valid {
			v.WithdrawnAt = withdrawnAt.String
		}
		if modifiedAt.Valid {
			v.ModifiedAt = modifiedAt.String
		}

		vulns = append(vulns, v)
	}

	return vulns, rows.Err()
}

// GetVulnerabilityPackageInfo returns the affected package info for a vulnerability.
func (db *DB) GetVulnerabilityPackageInfo(vulnID, ecosystem, packageName string) (*VulnerabilityPackage, error) {
	var vp VulnerabilityPackage
	var affectedVersions, fixedVersions sql.NullString

	err := db.QueryRow(`
		SELECT vulnerability_id, ecosystem, package_name, affected_versions, fixed_versions
		FROM vulnerability_packages
		WHERE vulnerability_id = ? AND ecosystem = ? AND package_name = ?
	`, vulnID, ecosystem, packageName).Scan(&vp.VulnerabilityID, &vp.Ecosystem, &vp.PackageName,
		&affectedVersions, &fixedVersions)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if affectedVersions.Valid {
		vp.AffectedVersions = affectedVersions.String
	}
	if fixedVersions.Valid {
		vp.FixedVersions = fixedVersions.String
	}

	return &vp, nil
}

// GetVulnSyncStatus returns packages that need vulnerability syncing.
func (db *DB) GetVulnSyncStatus(branchID int64) ([]VulnSyncStatus, error) {
	rows, err := db.Query(`
		SELECT DISTINCT ds.ecosystem, ds.name
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE bc.branch_id = ?
		AND m.kind = 'lockfile'
		AND ds.ecosystem IS NOT NULL AND ds.ecosystem != ''
		ORDER BY ds.ecosystem, ds.name
	`, branchID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var statuses []VulnSyncStatus
	for rows.Next() {
		var s VulnSyncStatus
		if err := rows.Scan(&s.Ecosystem, &s.PackageName); err != nil {
			return nil, err
		}
		statuses = append(statuses, s)
	}

	return statuses, rows.Err()
}

// GetStoredVulnCount returns the number of vulnerabilities stored for a package.
func (db *DB) GetStoredVulnCount(ecosystem, packageName string) (int, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*)
		FROM vulnerability_packages
		WHERE ecosystem = ? AND package_name = ?
	`, ecosystem, packageName).Scan(&count)
	return count, err
}

// InsertVulnerability inserts or updates a vulnerability record.
func (db *DB) InsertVulnerability(v Vulnerability) error {
	aliases := joinCommaList(v.Aliases)
	refs := joinCommaList(v.References)

	_, err := db.Exec(`
		INSERT INTO vulnerabilities (id, aliases, severity, cvss_score, cvss_vector, refs,
			summary, details, published_at, withdrawn_at, modified_at, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			aliases = excluded.aliases,
			severity = excluded.severity,
			cvss_score = excluded.cvss_score,
			cvss_vector = excluded.cvss_vector,
			refs = excluded.refs,
			summary = excluded.summary,
			details = excluded.details,
			published_at = excluded.published_at,
			withdrawn_at = excluded.withdrawn_at,
			modified_at = excluded.modified_at,
			fetched_at = excluded.fetched_at
	`, v.ID, aliases, v.Severity, v.CVSSScore, v.CVSSVector, refs,
		v.Summary, v.Details, v.PublishedAt, v.WithdrawnAt, v.ModifiedAt, v.FetchedAt)
	return err
}

// InsertVulnerabilityPackage inserts or updates a vulnerability-package mapping.
func (db *DB) InsertVulnerabilityPackage(vp VulnerabilityPackage) error {
	_, err := db.Exec(`
		INSERT INTO vulnerability_packages (vulnerability_id, ecosystem, package_name, affected_versions, fixed_versions)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(vulnerability_id, ecosystem, package_name) DO UPDATE SET
			affected_versions = excluded.affected_versions,
			fixed_versions = excluded.fixed_versions
	`, vp.VulnerabilityID, vp.Ecosystem, vp.PackageName, vp.AffectedVersions, vp.FixedVersions)
	return err
}

// DeleteVulnerabilitiesForPackage removes all vulnerability mappings for a package.
// This is used before re-syncing to handle withdrawn vulnerabilities.
func (db *DB) DeleteVulnerabilitiesForPackage(ecosystem, packageName string) error {
	_, err := db.Exec(`
		DELETE FROM vulnerability_packages
		WHERE ecosystem = ? AND package_name = ?
	`, ecosystem, packageName)
	return err
}

// GetVulnerabilityStats returns vulnerability counts by severity for current dependencies.
func (db *DB) GetVulnerabilityStats(branchID int64) (map[string]int, error) {
	rows, err := db.Query(`
		SELECT v.severity, COUNT(DISTINCT v.id)
		FROM vulnerabilities v
		JOIN vulnerability_packages vp ON vp.vulnerability_id = v.id
		JOIN dependency_snapshots ds ON ds.ecosystem = vp.ecosystem AND ds.name = vp.package_name
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE bc.branch_id = ?
		AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
		AND m.kind = 'lockfile'
		GROUP BY v.severity
	`, branchID, branchID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[string]int)
	for rows.Next() {
		var severity sql.NullString
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		sev := "unknown"
		if severity.Valid && severity.String != "" {
			sev = severity.String
		}
		stats[sev] = count
	}

	return stats, rows.Err()
}

func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0)
	for _, p := range splitString(s, ",") {
		p = trimSpace(p)
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func joinCommaList(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "," + parts[i]
	}
	return result
}

func splitString(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
