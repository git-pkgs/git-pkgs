package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"
)

// Add new user-owned or cache tables here. Git-derived tables are rebuilt.
var preservedTables = []string{
	"packages",
	"versions",
	"version_lists",
	"vulnerabilities",
	"vulnerability_packages",
	"notes",
}

// RebuildFunc populates Git-derived tables in a fresh replacement database.
type RebuildFunc func(previous, replacement *DB) error

// RebuildRequiredError is returned when derived data is out of date and no
// rebuild function was supplied.
type RebuildRequiredError struct {
	CurrentVersion int
	TargetVersion  int
}

func (e *RebuildRequiredError) Error() string {
	return fmt.Sprintf(
		"database index version %d must be rebuilt for version %d",
		e.CurrentVersion,
		e.TargetVersion,
	)
}

// OpenWithRebuild upgrades a database and uses rebuild when its derived data is
// out of date. The existing file is replaced only after rebuild succeeds.
func OpenWithRebuild(path string, rebuild RebuildFunc) (*DB, UpgradeResult, error) {
	return openWithDatabaseLock(path, func() (*DB, UpgradeResult, error) {
		previous, result, err := openAndUpgrade(path)
		if err != nil {
			return nil, result, err
		}
		if !result.RequiresRebuild() {
			return previous, result, nil
		}
		if rebuild == nil {
			_ = previous.Close()
			return nil, result, &RebuildRequiredError{
				CurrentVersion: result.ToIndexVersion,
				TargetVersion:  IndexVersion,
			}
		}

		replacementPath, err := createReplacementPath(path)
		if err != nil {
			_ = previous.Close()
			return nil, result, err
		}
		defer func() { _ = os.Remove(replacementPath) }()

		replacement, err := Create(replacementPath)
		if err != nil {
			_ = previous.Close()
			return nil, result, fmt.Errorf("creating replacement database: %w", err)
		}

		if err := rebuild(previous, replacement); err != nil {
			_ = replacement.Close()
			_ = previous.Close()
			return nil, result, err
		}
		if err := copyPreservedData(previous, replacement); err != nil {
			_ = replacement.Close()
			_ = previous.Close()
			return nil, result, fmt.Errorf("preserving database data: %w", err)
		}
		if err := closeForReplacement(previous, replacement); err != nil {
			return nil, result, err
		}
		if err := preserveDatabaseMode(path, replacementPath); err != nil {
			return nil, result, err
		}
		if err := replaceDatabase(path, replacementPath); err != nil {
			return nil, result, err
		}

		upgraded, finalResult, err := openAndUpgrade(path)
		if err != nil {
			return nil, result, fmt.Errorf("opening rebuilt database: %w", err)
		}
		result.ToSchemaVersion = finalResult.ToSchemaVersion
		result.ToIndexVersion = finalResult.ToIndexVersion
		result.Rebuilt = true
		return upgraded, result, nil
	})
}

func openWithDatabaseLock(
	path string,
	operation func() (*DB, UpgradeResult, error),
) (db *DB, result UpgradeResult, err error) {
	upgradeLock := flock.New(path + ".upgrade.lock")
	if err := upgradeLock.Lock(); err != nil {
		return nil, result, fmt.Errorf("locking database upgrade: %w", err)
	}
	defer func() {
		if closeErr := upgradeLock.Close(); err == nil && closeErr != nil {
			if db != nil {
				_ = db.Close()
				db = nil
			}
			err = fmt.Errorf("unlocking database upgrade: %w", closeErr)
		}
	}()

	return operation()
}

func createReplacementPath(path string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".upgrade-*")
	if err != nil {
		return "", fmt.Errorf("creating replacement database path: %w", err)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("closing replacement database file: %w", err)
	}
	return name, nil
}

func copyPreservedData(previous, replacement *DB) (err error) {
	ctx := context.Background()
	conn, err := replacement.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS previous", previous.path); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(ctx, "DETACH DATABASE previous") }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	for _, table := range preservedTables {
		columns, err := tableColumns(ctx, conn, table)
		if err != nil {
			return fmt.Errorf("reading %s columns: %w", table, err)
		}
		quotedColumns := make([]string, len(columns))
		for i, column := range columns {
			quotedColumns[i] = quoteIdentifier(column)
		}
		columnList := strings.Join(quotedColumns, ", ")
		quotedTable := quoteIdentifier(table)
		statement := fmt.Sprintf(
			"INSERT OR REPLACE INTO main.%s (%s) SELECT %s FROM previous.%s",
			quotedTable,
			columnList,
			columnList,
			quotedTable,
		)
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("copying %s: %w", table, err)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	return nil
}

func tableColumns(ctx context.Context, conn *sql.Conn, table string) ([]string, error) {
	rows, err := conn.QueryContext(ctx, "SELECT name FROM pragma_table_info(?) ORDER BY cid", table)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("table has no columns")
	}
	return columns, nil
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func closeForReplacement(previous, replacement *DB) error {
	if _, err := replacement.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("checkpointing replacement database: %w", err)
	}
	if err := replacement.Close(); err != nil {
		return fmt.Errorf("closing replacement database: %w", err)
	}
	if _, err := previous.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		_ = previous.Close()
		return fmt.Errorf("checkpointing previous database: %w", err)
	}
	if err := previous.Close(); err != nil {
		return fmt.Errorf("closing previous database: %w", err)
	}
	return nil
}

func preserveDatabaseMode(path, replacementPath string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading database permissions: %w", err)
	}
	if err := os.Chmod(replacementPath, info.Mode().Perm()); err != nil {
		return fmt.Errorf("preserving database permissions: %w", err)
	}
	return nil
}

func replaceDatabase(path, replacementPath string) error {
	backupFile, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".backup-*")
	if err != nil {
		return fmt.Errorf("creating database backup path: %w", err)
	}
	backupPath := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		return fmt.Errorf("closing database backup file: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("preparing database backup path: %w", err)
	}

	if err := os.Rename(path, backupPath); err != nil {
		return fmt.Errorf("backing up previous database: %w", err)
	}
	if err := os.Rename(replacementPath, path); err != nil {
		if restoreErr := os.Rename(backupPath, path); restoreErr != nil {
			return fmt.Errorf("installing replacement database: %w; restoring previous database: %v", err, restoreErr)
		}
		return fmt.Errorf("installing replacement database: %w", err)
	}
	_ = os.Remove(backupPath)
	return nil
}
