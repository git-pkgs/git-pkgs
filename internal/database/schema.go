package database

import "fmt"

func (db *DB) CreateSchema() error {
	if err := db.OptimizeForBulkWrites(); err != nil {
		return err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS schema_info (
		version INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS branches (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		last_analyzed_sha TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_branches_name ON branches(name);

	CREATE TABLE IF NOT EXISTS commits (
		id INTEGER PRIMARY KEY,
		sha TEXT NOT NULL,
		message TEXT,
		author_name TEXT,
		author_email TEXT,
		committed_at DATETIME,
		has_dependency_changes INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_commits_sha ON commits(sha);

	CREATE TABLE IF NOT EXISTS branch_commits (
		id INTEGER PRIMARY KEY,
		branch_id INTEGER REFERENCES branches(id),
		commit_id INTEGER REFERENCES commits(id),
		position INTEGER
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_branch_commits_unique ON branch_commits(branch_id, commit_id);
	CREATE INDEX IF NOT EXISTS idx_branch_commits_position ON branch_commits(branch_id, position DESC);

	CREATE TABLE IF NOT EXISTS manifests (
		id INTEGER PRIMARY KEY,
		path TEXT NOT NULL,
		ecosystem TEXT,
		kind TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_manifests_path ON manifests(path);

	CREATE TABLE IF NOT EXISTS dependency_changes (
		id INTEGER PRIMARY KEY,
		commit_id INTEGER REFERENCES commits(id),
		manifest_id INTEGER REFERENCES manifests(id),
		name TEXT NOT NULL,
		ecosystem TEXT,
		purl TEXT,
		change_type TEXT NOT NULL,
		requirement TEXT,
		previous_requirement TEXT,
		dependency_type TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_dependency_changes_name ON dependency_changes(name);
	CREATE INDEX IF NOT EXISTS idx_dependency_changes_ecosystem ON dependency_changes(ecosystem);
	CREATE INDEX IF NOT EXISTS idx_dependency_changes_purl ON dependency_changes(purl);
	CREATE INDEX IF NOT EXISTS idx_dependency_changes_commit_name ON dependency_changes(commit_id, name);

	CREATE TABLE IF NOT EXISTS dependency_snapshots (
		id INTEGER PRIMARY KEY,
		commit_id INTEGER REFERENCES commits(id),
		manifest_id INTEGER REFERENCES manifests(id),
		name TEXT NOT NULL,
		ecosystem TEXT,
		purl TEXT,
		requirement TEXT,
		dependency_type TEXT,
		integrity TEXT,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshots_unique ON dependency_snapshots(commit_id, manifest_id, name);
	CREATE INDEX IF NOT EXISTS idx_dependency_snapshots_name ON dependency_snapshots(name);
	CREATE INDEX IF NOT EXISTS idx_dependency_snapshots_ecosystem ON dependency_snapshots(ecosystem);
	CREATE INDEX IF NOT EXISTS idx_dependency_snapshots_purl ON dependency_snapshots(purl);

	CREATE TABLE IF NOT EXISTS packages (
		id INTEGER PRIMARY KEY,
		purl TEXT NOT NULL,
		ecosystem TEXT NOT NULL,
		name TEXT NOT NULL,
		latest_version TEXT,
		license TEXT,
		description TEXT,
		homepage TEXT,
		repository_url TEXT,
		supplier_name TEXT,
		supplier_type TEXT,
		source TEXT,
		enriched_at DATETIME,
		vulns_synced_at DATETIME,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_packages_purl ON packages(purl);
	CREATE INDEX IF NOT EXISTS idx_packages_ecosystem_name ON packages(ecosystem, name);

	CREATE TABLE IF NOT EXISTS versions (
		id INTEGER PRIMARY KEY,
		purl TEXT NOT NULL,
		package_purl TEXT NOT NULL,
		license TEXT,
		published_at DATETIME,
		integrity TEXT,
		source TEXT,
		enriched_at DATETIME,
		created_at DATETIME,
		updated_at DATETIME
	);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_versions_purl ON versions(purl);
	CREATE INDEX IF NOT EXISTS idx_versions_package_purl ON versions(package_purl);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		aliases TEXT,
		severity TEXT,
		cvss_score REAL,
		cvss_vector TEXT,
		refs TEXT,
		summary TEXT,
		details TEXT,
		published_at DATETIME,
		withdrawn_at DATETIME,
		modified_at DATETIME,
		fetched_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS vulnerability_packages (
		id INTEGER PRIMARY KEY,
		vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(id),
		ecosystem TEXT NOT NULL,
		package_name TEXT NOT NULL,
		affected_versions TEXT,
		fixed_versions TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_vuln_packages_ecosystem_name ON vulnerability_packages(ecosystem, package_name);
	CREATE INDEX IF NOT EXISTS idx_vuln_packages_vuln_id ON vulnerability_packages(vulnerability_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_packages_unique ON vulnerability_packages(vulnerability_id, ecosystem, package_name);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("executing schema: %w", err)
	}

	if _, err := db.Exec("INSERT INTO schema_info (version) VALUES (?)", SchemaVersion); err != nil {
		return fmt.Errorf("setting schema version: %w", err)
	}

	return db.OptimizeForReads()
}

func (db *DB) SchemaVersion() (int, error) {
	var version int
	err := db.QueryRow("SELECT version FROM schema_info LIMIT 1").Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}
