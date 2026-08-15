package cmd_test

import (
	"encoding/json"
	"fmt"
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
