package cmd_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestCommandAutomaticallyRebuildsOutdatedIndex(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package manifest")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks", "--quiet"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	gitBranch(t, repoDir, "feature")
	if _, _, err := runCmd(t, "branch", "add", "feature", "--quiet"); err != nil {
		t.Fatalf("adding tracked branch failed: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database failed: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO notes (purl, namespace, message) VALUES ('pkg:npm/express', 'test', 'keep me');
		DELETE FROM dependency_snapshots;
		PRAGMA user_version = 2147483647;
	`); err != nil {
		t.Fatalf("preparing outdated database failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing outdated database failed: %v", err)
	}

	stdout, _, err := runCmd(t, "list", "--format", "json")
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	var dependencies []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(stdout), &dependencies); err != nil {
		t.Fatalf("expected clean JSON output after automatic upgrade, got %q: %v", stdout, err)
	}
	var foundExpress bool
	for _, dependency := range dependencies {
		if dependency.Name == "express" {
			foundExpress = true
			break
		}
	}
	if !foundExpress {
		t.Fatalf("expected rebuilt dependency data, got: %+v", dependencies)
	}

	db, err = database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening rebuilt database failed: %v", err)
	}
	defer func() { _ = db.Close() }()

	var note string
	if err := db.QueryRow("SELECT message FROM notes WHERE purl = 'pkg:npm/express'").Scan(&note); err != nil {
		t.Fatalf("reading preserved note failed: %v", err)
	}
	if note != "keep me" {
		t.Errorf("expected preserved note, got %q", note)
	}

	branches, err := db.GetBranches()
	if err != nil {
		t.Fatalf("reading rebuilt branches failed: %v", err)
	}
	if len(branches) != 2 {
		t.Errorf("expected 2 tracked branches, got %d", len(branches))
	}
	defaultBranch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("reading default branch failed: %v", err)
	}
	if defaultBranch.Name != "main" {
		t.Errorf("expected main to remain the default branch, got %q", defaultBranch.Name)
	}
}

func TestBranchRemoveRecoversFromUnresolvableOutdatedBranch(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package manifest")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks", "--quiet"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	gitBranch(t, repoDir, "feature")
	if _, _, err := runCmd(t, "branch", "add", "feature", "--quiet"); err != nil {
		t.Fatalf("adding tracked branch failed: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database failed: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE branches SET last_analyzed_sha = '0000000000000000000000000000000000000000'
		WHERE name = 'feature';
		PRAGMA user_version = 2147483647;
	`); err != nil {
		t.Fatalf("preparing stale tracked branch failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing outdated database failed: %v", err)
	}

	deleteBranch := exec.Command("git", "branch", "-D", "feature")
	deleteBranch.Dir = repoDir
	if output, err := deleteBranch.CombinedOutput(); err != nil {
		t.Fatalf("deleting Git branch failed: %v\n%s", err, output)
	}

	if _, _, err := runCmd(t, "branch", "remove", "feature"); err != nil {
		t.Fatalf("removing unresolvable tracked branch failed: %v", err)
	}

	db, err = database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening rebuilt database failed: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.GetBranch("feature"); err != sql.ErrNoRows {
		t.Fatalf("expected feature branch to be removed, got: %v", err)
	}
	defaultBranch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("reading default branch failed: %v", err)
	}
	if defaultBranch.Name != "main" {
		t.Errorf("expected main to remain the default branch, got %q", defaultBranch.Name)
	}
}

func TestBranchRemoveRecoversFromMultipleUnresolvableOutdatedBranches(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package manifest")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks", "--quiet"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	for _, branch := range []string{"feature-one", "feature-two"} {
		gitBranch(t, repoDir, branch)
		if _, _, err := runCmd(t, "branch", "add", branch, "--quiet"); err != nil {
			t.Fatalf("adding tracked branch %q failed: %v", branch, err)
		}
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database failed: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE branches SET last_analyzed_sha = '0000000000000000000000000000000000000000'
		WHERE name IN ('feature-one', 'feature-two');
		PRAGMA user_version = 2147483647;
	`); err != nil {
		t.Fatalf("preparing stale tracked branches failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing outdated database failed: %v", err)
	}

	deleteBranches := exec.Command("git", "branch", "-D", "feature-one", "feature-two")
	deleteBranches.Dir = repoDir
	if output, err := deleteBranches.CombinedOutput(); err != nil {
		t.Fatalf("deleting Git branches failed: %v\n%s", err, output)
	}

	if _, _, err := runCmd(t, "branch", "remove", "feature-one"); err != nil {
		t.Fatalf("removing first unresolvable tracked branch failed: %v", err)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening pending database failed: %v", err)
	}
	var firstCount, secondCount int
	if err := rawDB.QueryRow("SELECT COUNT(*) FROM branches WHERE name = 'feature-one'").Scan(&firstCount); err != nil {
		t.Fatalf("checking first removed branch failed: %v", err)
	}
	if err := rawDB.QueryRow("SELECT COUNT(*) FROM branches WHERE name = 'feature-two'").Scan(&secondCount); err != nil {
		t.Fatalf("checking remaining branch failed: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("closing pending database failed: %v", err)
	}
	if firstCount != 0 || secondCount != 1 {
		t.Fatalf("unexpected tracked branches after first removal: feature-one=%d, feature-two=%d", firstCount, secondCount)
	}

	if _, _, err := runCmd(t, "branch", "remove", "feature-two"); err != nil {
		t.Fatalf("removing second unresolvable tracked branch failed: %v", err)
	}

	db, err = database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening rebuilt database failed: %v", err)
	}
	defer func() { _ = db.Close() }()
	branches, err := db.GetBranches()
	if err != nil {
		t.Fatalf("reading rebuilt branches failed: %v", err)
	}
	if len(branches) != 1 || branches[0].Name != "main" {
		t.Fatalf("expected only main to remain tracked, got: %+v", branches)
	}
}

func TestRebuildKeepsPreviousDatabaseOnIndexingError(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package manifest")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks", "--quiet"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	dbPath := filepath.Join(repoDir, ".git", "pkgs.sqlite3")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("opening database failed: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO notes (purl, namespace, message) VALUES ('pkg:npm/express', 'test', 'keep me');
		PRAGMA user_version = 2147483647;
	`); err != nil {
		t.Fatalf("preparing outdated database failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing outdated database failed: %v", err)
	}

	treeCommand := exec.Command("git", "rev-parse", "HEAD^{tree}")
	treeCommand.Dir = repoDir
	treeOutput, err := treeCommand.Output()
	if err != nil {
		t.Fatalf("resolving tree failed: %v", err)
	}
	treeHash := strings.TrimSpace(string(treeOutput))
	if len(treeHash) != 40 {
		t.Fatalf("unexpected tree hash %q", treeHash)
	}
	treePath := filepath.Join(repoDir, ".git", "objects", treeHash[:2], treeHash[2:])
	if err := os.Remove(treePath); err != nil {
		t.Fatalf("removing tree object failed: %v", err)
	}

	if _, _, err := runCmd(t, "list", "--format", "json"); err == nil {
		t.Fatal("expected rebuild to fail when a Git tree cannot be loaded")
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening previous database failed: %v", err)
	}
	defer func() { _ = rawDB.Close() }()
	var indexVersion int
	if err := rawDB.QueryRow("PRAGMA user_version").Scan(&indexVersion); err != nil {
		t.Fatalf("reading pending index version failed: %v", err)
	}
	if indexVersion == database.IndexVersion {
		t.Fatal("expected the previous database to remain pending after the failed rebuild")
	}
	var note string
	if err := rawDB.QueryRow("SELECT message FROM notes WHERE purl = 'pkg:npm/express'").Scan(&note); err != nil {
		t.Fatalf("reading preserved note failed: %v", err)
	}
	if note != "keep me" {
		t.Fatalf("expected previous note to remain, got %q", note)
	}
}

func TestExplicitCommandsReportSchemaAndIndexUpgrade(t *testing.T) {
	fromVersion := database.SchemaVersion - 1
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "upgrade",
			args: []string{"upgrade"},
			want: fmt.Sprintf("Upgraded database from schema version %d to %d and rebuilt its index.", fromVersion, database.SchemaVersion),
		},
		{
			name: "existing init",
			args: []string{"init", "--no-hooks"},
			want: fmt.Sprintf("Upgraded existing database from schema version %d to %d and rebuilt its index.", fromVersion, database.SchemaVersion),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package manifest")

			cleanup := chdir(t, repoDir)
			defer cleanup()

			if _, _, err := runCmd(t, "init", "--no-hooks", "--quiet"); err != nil {
				t.Fatalf("init failed: %v", err)
			}
			db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
			if err != nil {
				t.Fatalf("opening database failed: %v", err)
			}
			if _, err := db.Exec("UPDATE schema_info SET version = ?", fromVersion); err != nil {
				t.Fatalf("marking database outdated failed: %v", err)
			}
			if _, err := db.Exec("PRAGMA user_version = 0"); err != nil {
				t.Fatalf("marking database index outdated failed: %v", err)
			}
			if err := db.Close(); err != nil {
				t.Fatalf("closing database failed: %v", err)
			}

			stdout, _, err := runCmd(t, test.args...)
			if err != nil {
				t.Fatalf("command failed: %v", err)
			}
			if !strings.Contains(stdout, test.want) {
				t.Errorf("expected %q in output, got: %s", test.want, stdout)
			}
		})
	}
}

func gitBranch(t *testing.T, repoDir, name string) {
	t.Helper()
	cmd := exec.Command("git", "branch", name)
	cmd.Dir = repoDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("creating branch failed: %v", err)
	}
}
