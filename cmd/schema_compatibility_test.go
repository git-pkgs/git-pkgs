package cmd_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/sbom"
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

// setTestDatabaseSchemaVersion sets the recorded schema version. With
// removeNewerSchema it also drops the tables and columns that version lacks.
func setTestDatabaseSchemaVersion(t *testing.T, repoDir string, version int, removeNewerSchema bool) {
	t.Helper()
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer func() { _ = db.Close() }()

	if removeNewerSchema {
		var statements []string
		if version < 17 {
			statements = append(statements,
				"ALTER TABLE packages DROP COLUMN repository_parent",
				"ALTER TABLE packages DROP COLUMN repository_parent_synced_at",
			)
		}
		if version < 16 {
			statements = append(statements, "DROP TABLE manifest_licenses")
		}
		for _, statement := range statements {
			if _, err := db.Exec(statement); err != nil {
				t.Fatalf("%s: %v", statement, err)
			}
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

func TestSBOMFallsBackToTreeWithoutManifestLicensesTable(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","license":"MIT"}`, "Initial commit")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	setTestDatabaseSchemaVersion(t, repoDir, 15, true)

	stdout, _, err := runCmd(t, "sbom", "--skip-enrichment")
	if err != nil {
		t.Fatalf("sbom failed on previous schema: %v", err)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Licenses []struct {
					Expression string `json:"expression"`
				} `json:"licenses"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("parsing sbom output: %v", err)
	}
	licenses := doc.Metadata.Component.Licenses
	if len(licenses) != 1 || licenses[0].Expression != "MIT" {
		t.Fatalf("SBOM root licenses = %+v, want MIT", licenses)
	}
}

// forkEnrichmentClient reports @plotly/d3 as a fork of the d3/d3 repository.
type forkEnrichmentClient struct{}

func (forkEnrichmentClient) BulkLookup(_ context.Context, purls []string) (map[string]*enrichment.PackageInfo, error) {
	result := make(map[string]*enrichment.PackageInfo)
	for _, purlStr := range purls {
		if purlStr == "pkg:npm/%40plotly/d3" {
			result[purlStr] = &enrichment.PackageInfo{
				Ecosystem: "npm", Name: "@plotly/d3", License: "BSD-3-Clause", Source: "ecosystems",
				RepositoryParent: &enrichment.RepositoryParent{
					FullName: "d3/d3", Evidence: enrichment.AncestryDeclaredFork,
					HostName: "GitHub", HostKind: "github", HostURL: "https://github.com",
				},
			}
		}
	}
	return result, nil
}

func (forkEnrichmentClient) GetVersions(context.Context, string) ([]enrichment.VersionInfo, error) {
	return nil, nil
}

func (forkEnrichmentClient) GetVersion(context.Context, string) (*enrichment.VersionInfo, error) {
	return nil, nil
}

func TestSBOMOmitsAncestryWithoutRepositoryParentCache(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", `{"name":"example","version":"1.0.0","dependencies":{"@plotly/d3":"3.8.2"}}`, "Add manifest")
	addFileAndCommit(t, repoDir, "package-lock.json", `{
  "name": "example",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "example", "version": "1.0.0", "dependencies": {"@plotly/d3": "3.8.2"}},
    "node_modules/@plotly/d3": {"version": "3.8.2"}
  }
}`, "Add lockfile")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
	setTestDatabaseSchemaVersion(t, repoDir, 16, true)

	original := cmd.NewEnrichmentClient
	cmd.NewEnrichmentClient = func(...enrichment.Option) (enrichment.Client, error) {
		return forkEnrichmentClient{}, nil
	}
	defer func() { cmd.NewEnrichmentClient = original }()

	for _, format := range []string{"json", "xml"} {
		stdout, stderr, err := runCmd(t, "sbom", "--format", format)
		if err != nil {
			t.Fatalf("sbom --format %s failed on schema 16: %v\n%s", format, err, stderr)
		}
		if !strings.Contains(stderr, "git pkgs upgrade") {
			t.Errorf("stderr = %q, want an upgrade hint", stderr)
		}
		doc, err := sbom.Parse([]byte(stdout))
		if err != nil {
			t.Fatalf("parsing %s sbom output: %v", format, err)
		}
		if len(doc.Packages) != 1 {
			t.Fatalf("%s packages = %+v, want 1", format, doc.Packages)
		}
		d3 := doc.Packages[0]
		if d3.LicenseDeclared != "BSD-3-Clause" || d3.Ancestors != nil {
			t.Errorf("%s @plotly/d3 license = %q, ancestors = %+v; want BSD-3-Clause and no ancestors",
				format, d3.LicenseDeclared, d3.Ancestors)
		}
	}
}
