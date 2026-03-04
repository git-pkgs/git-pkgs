package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// GetBranch returns information about a branch by name.
func (db *DB) GetBranch(name string) (*BranchInfo, error) {
	var info BranchInfo
	var lastSHA sql.NullString

	err := db.db.QueryRow(
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

// GetDefaultBranch returns the first branch (by ID), which is typically the default.
func (db *DB) GetDefaultBranch() (*BranchInfo, error) {
	var info BranchInfo
	var lastSHA sql.NullString

	err := db.db.QueryRow(
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

// GetBranches returns all branches with their commit counts.
func (db *DB) GetBranches() ([]BranchInfo, error) {
	rows, err := db.db.Query(`
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

// HasSnapshotForCommit checks if snapshot data exists for a specific commit.
func (db *DB) HasSnapshotForCommit(sha string) (bool, error) {
	var count int
	err := db.db.QueryRow(`
		SELECT COUNT(*) FROM dependency_snapshots ds
		JOIN commits c ON c.id = ds.commit_id
		WHERE c.sha = ?
	`, sha).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetDependenciesAtCommit returns dependencies at the most recent snapshot at or before the given commit.
func (db *DB) GetDependenciesAtCommit(sha string) ([]Dependency, error) {
	var commitID int64
	err := db.db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN branch_commits snap_bc ON snap_bc.commit_id = ds.commit_id
		JOIN commits c ON c.sha = ?
		JOIN branch_commits target_bc ON target_bc.commit_id = c.id
			AND target_bc.branch_id = snap_bc.branch_id
		WHERE snap_bc.position <= target_bc.position
		ORDER BY snap_bc.position DESC
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

// GetDependenciesAtRef returns dependencies at a specific ref on a branch.
func (db *DB) GetDependenciesAtRef(ref string, branchID int64) ([]Dependency, error) {
	var commitID int64
	err := db.db.QueryRow(`
		SELECT c.id
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha = ? AND bc.branch_id = ?
	`, ref, branchID).Scan(&commitID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var snapshotCommitID int64
	err = db.db.QueryRow(`
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

// GetLatestDependencies returns dependencies from the most recent snapshot on a branch.
func (db *DB) GetLatestDependencies(branchID int64) ([]Dependency, error) {
	var commitID int64
	err := db.db.QueryRow(`
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
	rows, err := db.db.Query(`
		SELECT ds.name, ds.ecosystem, ds.purl, ds.requirement, ds.dependency_type, ds.integrity, m.path, m.kind
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE ds.commit_id = ? AND ds.name != '_EMPTY_MARKER_'
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

// GetCommitsWithChanges returns commits that have dependency changes, with their changes eager-loaded.
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

	rows, err := db.db.Query(query, args...)
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

	shas := make([]string, len(commits))
	for i, c := range commits {
		shas[i] = c.SHA
	}

	allChanges, err := db.GetChangesForCommits(shas)
	if err != nil {
		return nil, err
	}

	for i := range commits {
		changes := allChanges[commits[i].SHA]

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

// GetChangesForCommit returns dependency changes for a single commit.
func (db *DB) GetChangesForCommit(sha string) ([]Change, error) {
	rows, err := db.db.Query(`
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

// GetChangesForCommits fetches changes for multiple commits in one query.
func (db *DB) GetChangesForCommits(shas []string) (map[string][]Change, error) {
	if len(shas) == 0 {
		return make(map[string][]Change), nil
	}

	placeholders := make([]string, len(shas))
	args := make([]any, len(shas))
	for i, sha := range shas {
		placeholders[i] = "?"
		args[i] = sha
	}

	query := fmt.Sprintf(`
		SELECT c.sha, dc.name, dc.ecosystem, dc.purl, dc.change_type, dc.requirement, dc.previous_requirement, dc.dependency_type, m.path
		FROM dependency_changes dc
		JOIN commits c ON c.id = dc.commit_id
		JOIN manifests m ON m.id = dc.manifest_id
		WHERE c.sha IN (%s)
		ORDER BY c.sha, m.path, dc.name
	`, strings.Join(placeholders, ","))

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string][]Change)
	for rows.Next() {
		var sha string
		var ch Change
		var ecosystem, purl, requirement, prevReq, depType sql.NullString

		if err := rows.Scan(&sha, &ch.Name, &ecosystem, &purl, &ch.ChangeType, &requirement, &prevReq, &depType, &ch.ManifestPath); err != nil {
			return nil, err
		}

		if ecosystem.Valid {
			ch.Ecosystem = ecosystem.String
		}
		if purl.Valid {
			ch.PURL = purl.String
		}
		if requirement.Valid {
			ch.Requirement = requirement.String
		}
		if prevReq.Valid {
			ch.PreviousRequirement = prevReq.String
		}
		if depType.Valid {
			ch.DependencyType = depType.String
		}

		result[sha] = append(result[sha], ch)
	}

	return result, rows.Err()
}

// GetPackageHistory returns the change history for a package.
func (db *DB) GetPackageHistory(opts HistoryOptions) ([]HistoryEntry, error) {
	query := `
		SELECT c.sha, c.message, c.author_name, c.author_email, c.committed_at,
		       dc.name, dc.ecosystem, dc.change_type, dc.requirement, dc.previous_requirement, m.path, m.kind
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

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		var message, authorName, authorEmail, ecosystem, requirement, prevReq, manifestKind sql.NullString

		if err := rows.Scan(&e.SHA, &message, &authorName, &authorEmail, &e.CommittedAt,
			&e.Name, &ecosystem, &e.ChangeType, &requirement, &prevReq, &e.ManifestPath, &manifestKind); err != nil {
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
		if manifestKind.Valid {
			e.ManifestKind = manifestKind.String
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// GetStats returns aggregate statistics for a branch.
func (db *DB) GetStats(opts StatsOptions) (*Stats, error) {
	stats := &Stats{
		DepsByEcosystem: make(map[string]int),
		ChangesByType:   make(map[string]int),
	}

	var branchName sql.NullString
	var latestCommitID sql.NullInt64
	err := db.db.QueryRow(`
		SELECT b.name, bc.commit_id
		FROM branches b
		LEFT JOIN branch_commits bc ON bc.branch_id = b.id
		WHERE b.id = ?
		ORDER BY bc.position DESC
		LIMIT 1
	`, opts.BranchID).Scan(&branchName, &latestCommitID)
	if err != nil {
		return nil, err
	}
	if branchName.Valid {
		stats.Branch = branchName.String
	}

	err = db.db.QueryRow(`
		SELECT COUNT(*) FROM branch_commits WHERE branch_id = ?
	`, opts.BranchID).Scan(&stats.CommitsAnalyzed)
	if err != nil {
		return nil, err
	}

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
	err = db.db.QueryRow(query, args...).Scan(&stats.CommitsWithChanges)
	if err != nil {
		return nil, err
	}

	var snapshotCommitID sql.NullInt64
	if latestCommitID.Valid {
		_ = db.db.QueryRow(`
			SELECT ds.commit_id
			FROM dependency_snapshots ds
			JOIN branch_commits bc ON bc.commit_id = ds.commit_id
			WHERE bc.branch_id = ?
			ORDER BY bc.position DESC
			LIMIT 1
		`, opts.BranchID).Scan(&snapshotCommitID)
	}
	if snapshotCommitID.Valid {
		err = db.db.QueryRow(`
			SELECT COUNT(*) FROM dependency_snapshots WHERE commit_id = ?
		`, snapshotCommitID.Int64).Scan(&stats.CurrentDeps)
		if err != nil {
			return nil, err
		}

		rows, err := db.db.Query(`
			SELECT ecosystem, COUNT(*)
			FROM dependency_snapshots
			WHERE commit_id = ?
			GROUP BY ecosystem
		`, snapshotCommitID.Int64)
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
	}

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

	rows, err := db.db.Query(query, args...)
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

	rows, err = db.db.Query(query, args...)
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

	rows, err = db.db.Query(query, args...)
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

// GetAuthorStats returns per-author dependency change statistics.
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

	rows, err := db.db.Query(query, args...)
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

// SearchDependencies searches current dependencies matching a pattern.
func (db *DB) SearchDependencies(branchID int64, pattern, ecosystem string, directOnly bool) ([]SearchResult, error) {
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

	rows, err := db.db.Query(query, args...)
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

// GetWhy returns the commit that first added a package.
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

	err := db.db.QueryRow(query, args...).Scan(
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

// GetBlame returns the commit that first added each current dependency.
func (db *DB) GetBlame(branchID int64, ecosystem string) ([]BlameEntry, error) {
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
		JOIN commits c ON c.id = (
			SELECT bc.commit_id FROM branch_commits bc
			WHERE bc.branch_id = ? AND bc.position = fa.first_pos
		)
	`
	args := []any{branchID, branchID, branchID, branchID}

	if ecosystem != "" {
		query += " WHERE cd.ecosystem = ?"
		args = append(args, ecosystem)
	}

	query += " ORDER BY cd.manifest_path, cd.name"

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []BlameEntry
	for rows.Next() {
		var e BlameEntry
		var eco, requirement, authorName, authorEmail sql.NullString

		if err := rows.Scan(&e.Name, &eco, &requirement, &e.ManifestPath,
			&e.SHA, &authorName, &authorEmail, &e.CommittedAt); err != nil {
			return nil, err
		}

		if eco.Valid {
			e.Ecosystem = eco.String
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

// GetStaleDependencies returns dependencies that haven't been updated recently.
func (db *DB) GetStaleDependencies(branchID int64, ecosystem string, days int) ([]StaleEntry, error) {
	query := `
		WITH current_deps AS (
			SELECT DISTINCT ds.name, ds.ecosystem, ds.requirement, m.path, m.kind
			FROM dependency_snapshots ds
			JOIN manifests m ON m.id = ds.manifest_id
			JOIN branch_commits bc ON bc.commit_id = ds.commit_id
			WHERE bc.branch_id = ?
			AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
			AND (m.kind = 'lockfile' OR (m.kind = 'manifest' AND m.ecosystem = 'golang'))
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
		       CAST(julianday('now') - julianday(substr(COALESCE(lc.last_changed, '2000-01-01'), 1, 19)) AS INTEGER) as days_since
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
		query += " CAST(julianday('now') - julianday(substr(COALESCE(lc.last_changed, '2000-01-01'), 1, 19)) AS INTEGER) >= ?"
		args = append(args, days)
	}

	query += " ORDER BY days_since DESC, cd.name"

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []StaleEntry
	for rows.Next() {
		var e StaleEntry
		var eco, req, lastChanged sql.NullString
		var daysSince sql.NullInt64

		if err := rows.Scan(&e.Name, &eco, &req, &e.ManifestPath, &lastChanged, &daysSince); err != nil {
			return nil, err
		}

		if eco.Valid {
			e.Ecosystem = eco.String
		}
		if req.Valid {
			e.Requirement = req.String
		}
		if lastChanged.Valid {
			e.LastChanged = lastChanged.String
		}
		if daysSince.Valid {
			e.DaysSince = int(daysSince.Int64)
		}

		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// GetDatabaseInfo returns metadata about the database.
func (db *DB) GetDatabaseInfo() (*DatabaseInfo, error) {
	info := &DatabaseInfo{
		Path:      db.path,
		RowCounts: make(map[string]int),
	}

	version, err := db.SchemaVersion()
	if err != nil {
		return nil, err
	}
	info.SchemaVersion = version

	branchInfo, err := db.GetDefaultBranch()
	if err == nil {
		info.BranchName = branchInfo.Name
		info.LastAnalyzedSHA = branchInfo.LastAnalyzedSHA
	}

	tables := []string{"branches", "commits", "branch_commits", "manifests", "dependency_changes", "dependency_snapshots", "packages", "versions"}
	for _, table := range tables {
		var count int
		err := db.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			continue
		}
		info.RowCounts[table] = count
	}

	rows, err := db.db.Query(`
		SELECT ecosystem, COUNT(*) FROM dependency_snapshots
		WHERE ecosystem IS NOT NULL AND ecosystem != ''
		GROUP BY ecosystem
		ORDER BY ecosystem
	`)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var eco string
			var count int
			if rows.Scan(&eco, &count) == nil && eco != "" {
				info.Ecosystems = append(info.Ecosystems, EcosystemCount{Name: eco, Count: count})
			}
		}
	}

	return info, nil
}

// GetVulnerabilitiesForPackage returns all vulnerabilities affecting a specific package.
func (db *DB) GetVulnerabilitiesForPackage(ecosystem, packageName string) ([]Vulnerability, error) {
	rows, err := db.db.Query(`
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

	err := db.db.QueryRow(`
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

// GetVulnSyncStatus returns packages that have vulnerability data.
func (db *DB) GetVulnSyncStatus(branchID int64) ([]VulnSyncStatus, error) {
	rows, err := db.db.Query(`
		SELECT DISTINCT ds.ecosystem, ds.name
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE bc.branch_id = ?
		AND (m.kind = 'lockfile' OR (m.kind = 'manifest' AND m.ecosystem = 'golang'))
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
	err := db.db.QueryRow(`
		SELECT COUNT(*)
		FROM vulnerability_packages
		WHERE ecosystem = ? AND package_name = ?
	`, ecosystem, packageName).Scan(&count)
	return count, err
}

// GetVulnerabilityStats returns vulnerability counts by severity for current dependencies.
func (db *DB) GetVulnerabilityStats(branchID int64) (map[string]int, error) {
	rows, err := db.db.Query(`
		SELECT v.severity, COUNT(DISTINCT v.id)
		FROM vulnerabilities v
		JOIN vulnerability_packages vp ON vp.vulnerability_id = v.id
		JOIN dependency_snapshots ds ON ds.ecosystem = vp.ecosystem AND ds.name = vp.package_name
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE bc.branch_id = ?
		AND bc.position = (SELECT MAX(position) FROM branch_commits WHERE branch_id = ?)
		AND (m.kind = 'lockfile' OR (m.kind = 'manifest' AND m.ecosystem = 'golang'))
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

// GetVulnsSyncedAt returns when vulnerabilities were last synced for a package.
func (db *DB) GetVulnsSyncedAt(purlStr string) (time.Time, error) {
	var syncedAt sql.NullString
	err := db.db.QueryRow(`
		SELECT vulns_synced_at FROM packages
		WHERE purl = ?
		LIMIT 1
	`, purlStr).Scan(&syncedAt)
	if err == sql.ErrNoRows || !syncedAt.Valid {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339, syncedAt.String)
	return t, nil
}

// GetCachedPackages returns cached package data for the given PURLs that aren't stale.
func (db *DB) GetCachedPackages(purls []string, staleDuration time.Duration) (map[string]*CachedPackage, error) {
	if len(purls) == 0 {
		return make(map[string]*CachedPackage), nil
	}

	staleThreshold := time.Now().Add(-staleDuration)
	result := make(map[string]*CachedPackage)

	const batchSize = 500
	for i := 0; i < len(purls); i += batchSize {
		end := i + batchSize
		if end > len(purls) {
			end = len(purls)
		}
		batch := purls[i:end]

		placeholders := make([]string, len(batch))
		args := make([]any, len(batch)+1)
		args[0] = staleThreshold.Format(time.RFC3339)
		for j, purl := range batch {
			placeholders[j] = "?"
			args[j+1] = purl
		}

		query := `SELECT purl, ecosystem, name, latest_version, license, enriched_at
			FROM packages
			WHERE enriched_at >= ? AND purl IN (` + strings.Join(placeholders, ",") + `)`

		rows, err := db.db.Query(query, args...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var cp CachedPackage
			var latestVersion, license sql.NullString
			var enrichedAt string
			if err := rows.Scan(&cp.PURL, &cp.Ecosystem, &cp.Name, &latestVersion, &license, &enrichedAt); err != nil {
				_ = rows.Close()
				return nil, err
			}
			if latestVersion.Valid {
				cp.LatestVersion = latestVersion.String
			}
			if license.Valid {
				cp.License = license.String
			}
			cp.EnrichedAt, _ = time.Parse(time.RFC3339, enrichedAt)
			result[cp.PURL] = &cp
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		_ = rows.Close()
	}

	return result, nil
}

// GetCachedVersions returns cached version data for a package that isn't stale.
func (db *DB) GetCachedVersions(packagePurl string, staleDuration time.Duration) ([]CachedVersion, error) {
	staleThreshold := time.Now().Add(-staleDuration)

	rows, err := db.db.Query(`
		SELECT purl, package_purl, license, published_at
		FROM versions
		WHERE package_purl = ? AND enriched_at >= ?
		ORDER BY published_at DESC`,
		packagePurl, staleThreshold.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []CachedVersion
	for rows.Next() {
		var cv CachedVersion
		var license sql.NullString
		var publishedAt string
		if err := rows.Scan(&cv.PURL, &cv.PackagePURL, &license, &publishedAt); err != nil {
			return nil, err
		}
		if license.Valid {
			cv.License = license.String
		}
		cv.PublishedAt, _ = time.Parse(time.RFC3339, publishedAt)
		result = append(result, cv)
	}
	return result, rows.Err()
}

// GetNote returns a note by PURL and namespace.
func (db *DB) GetNote(purl, namespace string) (*Note, error) {
	var n Note
	var message, metadata sql.NullString
	err := db.db.QueryRow(`
		SELECT id, purl, namespace, origin, message, metadata, created_at, updated_at
		FROM notes WHERE purl = ? AND namespace = ?
	`, purl, namespace).Scan(&n.ID, &n.PURL, &n.Namespace, &n.Origin, &message, &metadata, &n.CreatedAt, &n.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if message.Valid {
		n.Message = message.String
	}
	if metadata.Valid {
		n.Metadata = decodeMetadata(metadata.String)
	}
	return &n, nil
}

// ListNotes returns notes filtered by namespace and/or PURL pattern.
func (db *DB) ListNotes(namespace, purlFilter string) ([]Note, error) {
	query := "SELECT id, purl, namespace, origin, message, metadata, created_at, updated_at FROM notes WHERE 1=1"
	var args []any

	if namespace != "" {
		query += " AND namespace = ?"
		args = append(args, namespace)
	}
	if purlFilter != "" {
		query += " AND purl LIKE ?"
		args = append(args, "%"+purlFilter+"%")
	}

	query += " ORDER BY purl, namespace"

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var notes []Note
	for rows.Next() {
		var n Note
		var message, metadata sql.NullString
		if err := rows.Scan(&n.ID, &n.PURL, &n.Namespace, &n.Origin, &message, &metadata, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		if message.Valid {
			n.Message = message.String
		}
		if metadata.Valid {
			n.Metadata = decodeMetadata(metadata.String)
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

// ListNoteNamespaces returns namespaces with their note counts.
func (db *DB) ListNoteNamespaces(purlFilter string) ([]NamespaceCount, error) {
	query := "SELECT namespace, COUNT(*) as count FROM notes"
	var args []any
	if purlFilter != "" {
		query += " WHERE purl LIKE ?"
		args = append(args, "%"+purlFilter+"%")
	}
	query += " GROUP BY namespace ORDER BY count DESC, namespace"
	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []NamespaceCount
	for rows.Next() {
		var nc NamespaceCount
		if err := rows.Scan(&nc.Namespace, &nc.Count); err != nil {
			return nil, err
		}
		results = append(results, nc)
	}
	return results, rows.Err()
}

// GetMaxPosition returns the maximum position in branch_commits for a branch.
func (db *DB) GetMaxPosition(branchID int64) (int, error) {
	var position sql.NullInt64
	err := db.db.QueryRow(
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

// GetCommitID returns the internal ID for a commit by SHA.
func (db *DB) GetCommitID(sha string) (int64, error) {
	var id int64
	err := db.db.QueryRow("SELECT id FROM commits WHERE sha = ?", sha).Scan(&id)
	return id, err
}

// GetCommitPosition returns the position of a commit in a branch.
func (db *DB) GetCommitPosition(sha string, branchID int64) (int, error) {
	var pos int
	err := db.db.QueryRow(`
		SELECT bc.position
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha = ? AND bc.branch_id = ?
	`, sha, branchID).Scan(&pos)
	return pos, err
}

// GetCommitAtPosition returns the SHA of the commit at a given position.
func (db *DB) GetCommitAtPosition(position int, branchID int64) (string, error) {
	var sha string
	err := db.db.QueryRow(`
		SELECT c.sha
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE bc.position = ? AND bc.branch_id = ?
	`, position, branchID).Scan(&sha)
	return sha, err
}

// GetLastSnapshot returns the most recent snapshot data for a branch.
func (db *DB) GetLastSnapshot(branchID int64) (map[string]Dependency, error) {
	var commitID int64
	err := db.db.QueryRow(`
		SELECT ds.commit_id
		FROM dependency_snapshots ds
		JOIN branch_commits bc ON bc.commit_id = ds.commit_id
		WHERE bc.branch_id = ?
		ORDER BY bc.position DESC
		LIMIT 1
	`, branchID).Scan(&commitID)
	if err == sql.ErrNoRows {
		return make(map[string]Dependency), nil
	}
	if err != nil {
		return nil, err
	}

	rows, err := db.db.Query(`
		SELECT m.path, ds.name, ds.ecosystem, ds.purl, ds.requirement, ds.dependency_type, ds.integrity
		FROM dependency_snapshots ds
		JOIN manifests m ON m.id = ds.manifest_id
		WHERE ds.commit_id = ?
	`, commitID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string]Dependency)
	for rows.Next() {
		var path, name string
		var d Dependency
		var ecosystem, purl, requirement, depType, integrity sql.NullString

		if err := rows.Scan(&path, &name, &ecosystem, &purl, &requirement, &depType, &integrity); err != nil {
			return nil, err
		}

		d.ManifestPath = path
		d.Name = name
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

		key := path + ":" + name + ":" + d.Requirement
		result[key] = d
	}

	return result, rows.Err()
}

// GetBisectCandidates returns commits with dependency changes between two commits.
func (db *DB) GetBisectCandidates(opts BisectOptions) ([]BisectCandidate, error) {
	var startPos, endPos int
	err := db.db.QueryRow(`
		SELECT bc.position
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha = ? AND bc.branch_id = ?
	`, opts.StartSHA, opts.BranchID).Scan(&startPos)
	if err != nil {
		return nil, fmt.Errorf("finding start commit position: %w", err)
	}

	err = db.db.QueryRow(`
		SELECT bc.position
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		WHERE c.sha = ? AND bc.branch_id = ?
	`, opts.EndSHA, opts.BranchID).Scan(&endPos)
	if err != nil {
		return nil, fmt.Errorf("finding end commit position: %w", err)
	}

	query := `
		SELECT DISTINCT c.sha, c.message, bc.position
		FROM commits c
		JOIN branch_commits bc ON bc.commit_id = c.id
		JOIN dependency_changes dc ON dc.commit_id = c.id
		JOIN manifests m ON m.id = dc.manifest_id
		WHERE bc.branch_id = ?
		AND bc.position > ?
		AND bc.position <= ?
	`
	args := []any{opts.BranchID, startPos, endPos}

	if opts.Ecosystem != "" {
		query += " AND dc.ecosystem = ?"
		args = append(args, opts.Ecosystem)
	}
	if opts.PackageName != "" {
		query += " AND dc.name = ?"
		args = append(args, opts.PackageName)
	}
	if opts.ManifestPath != "" {
		query += " AND m.path = ?"
		args = append(args, opts.ManifestPath)
	}

	query += " ORDER BY bc.position ASC"

	rows, err := db.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var candidates []BisectCandidate
	for rows.Next() {
		var c BisectCandidate
		var message sql.NullString
		if err := rows.Scan(&c.SHA, &message, &c.Position); err != nil {
			return nil, err
		}
		if message.Valid {
			c.Message = message.String
		}
		candidates = append(candidates, c)
	}

	return candidates, rows.Err()
}
