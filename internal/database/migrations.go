package database

import (
	"context"
	"database/sql"
	"fmt"
)

const (
	oldestSchemaVersion            = 5
	indexVersionIntroducedAtSchema = 15
	initialIndexVersion            = 1
	rebuildRequiredIndexVersion    = 2_147_483_647
	migrationBusyTimeoutMS         = 60_000
	migrationTypeText              = "TEXT"
	migrationTypeInteger           = "INTEGER"
)

// UpgradeResult describes schema and indexed-data changes made while opening a database.
type UpgradeResult struct {
	FromSchemaVersion int
	ToSchemaVersion   int
	FromIndexVersion  int
	ToIndexVersion    int
	Rebuilt           bool
}

// Upgraded reports whether the schema changed or the index was rebuilt.
func (r UpgradeResult) Upgraded() bool {
	return r.FromSchemaVersion != r.ToSchemaVersion || r.Rebuilt
}

// RequiresRebuild reports whether Git history must be indexed again.
func (r UpgradeResult) RequiresRebuild() bool {
	return r.ToIndexVersion != IndexVersion
}

type schemaMigration func(context.Context, *sql.Conn) error

var schemaMigrations = map[int]schemaMigration{
	5:  migrateSchema5To6,
	6:  migrateSchema6To7,
	7:  migrateSchema7To8,
	8:  migrateSchema8To9,
	9:  migrateSchema9To10,
	10: migrateSchema10To11,
	11: migrateSchema11To12,
	12: migrateSchema12To13,
	13: migrateSchema13To14,
	14: migrateSchema14To15,
}

// UpgradeSchema applies all pending schema migrations in one transaction.
func (db *DB) UpgradeSchema() (result UpgradeResult, err error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return result, fmt.Errorf("getting database connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", migrationBusyTimeoutMS)); err != nil {
		return result, fmt.Errorf("setting migration lock timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return result, fmt.Errorf("locking database for schema upgrade: %w", err)
	}
	defer func() {
		if err != nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	currentVersion, err := schemaVersion(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("reading schema version: %w", err)
	}
	startingVersion := currentVersion
	currentIndexVersion, err := indexVersion(ctx, conn)
	if err != nil {
		return result, fmt.Errorf("reading index version: %w", err)
	}
	result = UpgradeResult{
		FromSchemaVersion: currentVersion,
		ToSchemaVersion:   currentVersion,
		FromIndexVersion:  currentIndexVersion,
		ToIndexVersion:    currentIndexVersion,
	}

	if currentVersion > SchemaVersion {
		return result, fmt.Errorf(
			"database schema version %d is newer than supported version %d; upgrade git-pkgs",
			currentVersion,
			SchemaVersion,
		)
	}
	if currentVersion < oldestSchemaVersion {
		return result, fmt.Errorf(
			"database schema version %d is too old to upgrade automatically; run 'git pkgs init --force'",
			currentVersion,
		)
	}
	if currentIndexVersion > IndexVersion && currentIndexVersion != rebuildRequiredIndexVersion {
		return result, fmt.Errorf(
			"database index version %d is newer than supported version %d; upgrade git-pkgs",
			currentIndexVersion,
			IndexVersion,
		)
	}

	for currentVersion < SchemaVersion {
		migration, ok := schemaMigrations[currentVersion]
		if !ok {
			return result, fmt.Errorf("no schema migration from version %d", currentVersion)
		}
		if err := migration(ctx, conn); err != nil {
			return result, fmt.Errorf("upgrading database schema from version %d: %w", currentVersion, err)
		}
		currentVersion++
		if _, err := conn.ExecContext(ctx, "UPDATE schema_info SET version = ?", currentVersion); err != nil {
			return result, fmt.Errorf("setting schema version to %d: %w", currentVersion, err)
		}
		result.ToSchemaVersion = currentVersion
	}

	if startingVersion >= indexVersionIntroducedAtSchema &&
		IndexVersion == initialIndexVersion &&
		currentIndexVersion == 0 {
		currentIndexVersion = IndexVersion
	} else if startingVersion < SchemaVersion && currentIndexVersion == 0 {
		currentIndexVersion = rebuildRequiredIndexVersion
	}
	if currentIndexVersion != result.ToIndexVersion {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", currentIndexVersion)); err != nil {
			return result, fmt.Errorf("setting index version to %d: %w", currentIndexVersion, err)
		}
		result.ToIndexVersion = currentIndexVersion
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return result, fmt.Errorf("committing schema upgrade: %w", err)
	}
	return result, nil
}

func schemaVersion(ctx context.Context, conn *sql.Conn) (int, error) {
	var version int
	err := conn.QueryRowContext(ctx, "SELECT version FROM schema_info LIMIT 1").Scan(&version)
	return version, err
}

func indexVersion(ctx context.Context, conn *sql.Conn) (int, error) {
	var version int
	err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	return version, err
}

func migrateSchema5To6(ctx context.Context, conn *sql.Conn) error {
	if err := execMigrationStatements(ctx, conn,
		"CREATE INDEX IF NOT EXISTS idx_branch_commits_position ON branch_commits(branch_id, position DESC)",
	); err != nil {
		return err
	}
	return addColumn(ctx, conn, "packages", "registry_url", migrationTypeText)
}

func migrateSchema6To7(ctx context.Context, conn *sql.Conn) error {
	return execMigrationStatements(ctx, conn,
		"DROP INDEX IF EXISTS idx_snapshots_unique",
		"CREATE UNIQUE INDEX idx_snapshots_unique ON dependency_snapshots(commit_id, manifest_id, name, requirement)",
	)
}

func migrateSchema7To8(ctx context.Context, conn *sql.Conn) error {
	return execMigrationStatements(ctx, conn, `
		CREATE TABLE IF NOT EXISTS notes (
			id INTEGER PRIMARY KEY,
			purl TEXT NOT NULL,
			namespace TEXT NOT NULL DEFAULT '',
			message TEXT,
			metadata TEXT,
			created_at DATETIME,
			updated_at DATETIME
		)`,
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_notes_purl_namespace ON notes(purl, namespace)",
		"CREATE INDEX IF NOT EXISTS idx_notes_namespace ON notes(namespace)",
	)
}

func migrateSchema8To9(ctx context.Context, conn *sql.Conn) error {
	if err := addColumn(ctx, conn, "notes", "origin", "TEXT NOT NULL DEFAULT 'git-pkgs'"); err != nil {
		return err
	}
	return addColumn(ctx, conn, "dependency_changes", "previous_dependency_type", migrationTypeText)
}

func migrateSchema9To10(ctx context.Context, conn *sql.Conn) error {
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "status", definition: migrationTypeText},
		{name: "status_checked_at", definition: "DATETIME"},
		{name: "metadata", definition: migrationTypeText},
	} {
		if err := addColumn(ctx, conn, "versions", column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

func migrateSchema10To11(ctx context.Context, conn *sql.Conn) error {
	if err := addColumn(ctx, conn, "packages", "funding_links", migrationTypeText); err != nil {
		return err
	}
	return addColumn(ctx, conn, "packages", "funding_synced_at", "DATETIME")
}

func migrateSchema11To12(ctx context.Context, conn *sql.Conn) error {
	if err := addColumn(ctx, conn, "packages", "maintainers", migrationTypeText); err != nil {
		return err
	}
	return addColumn(ctx, conn, "packages", "maintainers_synced_at", "DATETIME")
}

func migrateSchema12To13(ctx context.Context, conn *sql.Conn) error {
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "downloads", definition: migrationTypeInteger},
		{name: "downloads_period", definition: migrationTypeText},
		{name: "dependent_packages_count", definition: migrationTypeInteger},
		{name: "dependent_repos_count", definition: migrationTypeInteger},
		{name: "health_synced_at", definition: "DATETIME"},
	} {
		if err := addColumn(ctx, conn, "packages", column.name, column.definition); err != nil {
			return err
		}
	}
	return nil
}

func migrateSchema13To14(ctx context.Context, conn *sql.Conn) error {
	if err := addColumn(ctx, conn, "versions", "integrity_checked_at", "DATETIME"); err != nil {
		return err
	}
	return execMigrationStatements(ctx, conn, `
		CREATE TABLE IF NOT EXISTS version_lists (
			package_purl TEXT PRIMARY KEY,
			synced_at DATETIME NOT NULL
		)`,
	)
}

func migrateSchema14To15(ctx context.Context, conn *sql.Conn) error {
	return addColumn(ctx, conn, "dependency_snapshots", "direct", "INTEGER NOT NULL DEFAULT 0")
}

func execMigrationStatements(ctx context.Context, conn *sql.Conn, statements ...string) error {
	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func addColumn(ctx context.Context, conn *sql.Conn, table, column, definition string) error {
	exists, err := columnExists(ctx, conn, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	statement := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
	_, err = conn.ExecContext(ctx, statement)
	return err
}

func columnExists(ctx context.Context, conn *sql.Conn, table, column string) (bool, error) {
	rows, err := conn.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			columnID     int
			name         string
			columnType   string
			notNull      int
			defaultValue sql.NullString
			primaryKey   int
		)
		if err := rows.Scan(&columnID, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}
