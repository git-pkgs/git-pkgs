package cmd_test

import (
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	_ "modernc.org/sqlite"
)

func TestNewerSchemaRequiresNewerBinary(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"MIT"}`, "Initial commit")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	newerVersion := database.SchemaVersion + 1
	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	setTestDatabaseSchemaVersion(t, dbPath, newerVersion)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"Apache-2.0"}`, "Change license")

	_, _, err := runCmd(t, "reindex")
	assertNewerSchemaError(t, err, newerVersion)

	_, _, err = runCmd(t, "upgrade")
	assertNewerSchemaError(t, err, newerVersion)

	if got := readTestDatabaseSchemaVersion(t, dbPath); got != newerVersion {
		t.Fatalf("schema version after rejected upgrade = %d, want %d", got, newerVersion)
	}
}

func setTestDatabaseSchemaVersion(t *testing.T, dbPath string, version int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec("UPDATE schema_info SET version = ?", version); err != nil {
		t.Fatalf("setting schema version: %v", err)
	}
}

func readTestDatabaseSchemaVersion(t *testing.T, dbPath string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	var version int
	if err := db.QueryRow("SELECT version FROM schema_info LIMIT 1").Scan(&version); err != nil {
		t.Fatalf("reading schema version: %v", err)
	}
	return version
}

func assertNewerSchemaError(t *testing.T, err error, version int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected command to reject a newer schema")
	}
	for _, want := range []string{
		"schema version " + strconv.Itoa(version),
		"newer than supported version",
		"install a newer git-pkgs binary",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "git pkgs upgrade") {
		t.Errorf("newer schema error incorrectly recommends the upgrade command: %v", err)
	}
}
