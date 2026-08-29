package cmd_test

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestBranchAddRejectsOlderSchemaBeforeIndexing(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"MIT"}`, "Initial commit")

	gitCmd := exec.Command("git", "branch", "feature")
	gitCmd.Dir = repoDir
	if err := gitCmd.Run(); err != nil {
		t.Fatalf("creating feature branch: %v", err)
	}

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	setTestDatabaseSchemaVersion(t, repoDir, database.SchemaVersion-1, true)

	_, _, err := runCmd(t, "branch", "add", "feature")
	assertOlderSchemaError(t, err)
}

func TestBisectReindexRejectsOlderSchemaBeforeIndexing(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "example",
  "dependencies": {"foo": "1.0.0"}
}`, "Add foo")
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "example",
  "dependencies": {"foo": "2.0.0"}
}`, "Update foo")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	setTestDatabaseSchemaVersion(t, repoDir, database.SchemaVersion-1, true)
	addFileAndCommit(t, repoDir, "package.json", `{
  "name": "example",
  "dependencies": {"foo": "3.0.0"}
}`, "Update foo again")

	_, _, err := runCmd(t, "bisect", "start", "HEAD", "HEAD~2")
	assertOlderSchemaError(t, err)
}

func TestNewerSchemaRequiresCompatibleBinary(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"MIT"}`, "Initial commit")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	newerVersion := database.SchemaVersion + 1
	setTestDatabaseSchemaVersion(t, repoDir, newerVersion, false)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"Apache-2.0"}`, "Change license")

	_, _, err := runCmd(t, "reindex")
	assertNewerSchemaError(t, err, newerVersion)

	_, _, err = runCmd(t, "upgrade")
	assertNewerSchemaError(t, err, newerVersion)

	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("opening database after rejected upgrade: %v", err)
	}
	defer func() { _ = db.Close() }()
	version, err := db.SchemaVersion()
	if err != nil {
		t.Fatalf("reading schema version after rejected upgrade: %v", err)
	}
	if version != newerVersion {
		t.Fatalf("schema version after rejected upgrade = %d, want %d", version, newerVersion)
	}
}

func setTestDatabaseSchemaVersion(t *testing.T, repoDir string, version int, dropManifestLicenses bool) {
	t.Helper()
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if dropManifestLicenses {
		if _, err := db.Exec("DROP TABLE manifest_licenses"); err != nil {
			t.Fatalf("dropping manifest_licenses: %v", err)
		}
	}
	if _, err := db.Exec("UPDATE schema_info SET version = ?", version); err != nil {
		t.Fatalf("setting schema version: %v", err)
	}
}

func assertOlderSchemaError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected command to reject an older schema")
	}
	for _, want := range []string{
		"schema version " + strconv.Itoa(database.SchemaVersion-1),
		"git pkgs upgrade",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "no such table") {
		t.Errorf("command reached incompatible schema write: %v", err)
	}
}

func assertNewerSchemaError(t *testing.T, err error, version int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected command to reject a newer schema")
	}
	for _, want := range []string{
		"schema version " + strconv.Itoa(version),
		"newer than this git-pkgs binary supports",
		"compatible git-pkgs binary",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "run 'git pkgs upgrade'") {
		t.Errorf("newer schema error incorrectly recommends upgrade: %v", err)
	}
}
