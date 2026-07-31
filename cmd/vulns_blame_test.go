package cmd_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestVulnsBlameResolvesHEAD(t *testing.T) {
	vuln := setupVulnerableNPMRepo(t)

	stdout, _, err := runCmd(t, "vulns", "blame", "--format", "json")
	if err != nil {
		t.Fatalf("vulns blame failed: %v", err)
	}

	var entries []struct {
		VulnID  string `json:"vuln_id"`
		Package string `json:"package"`
		AddedBy string `json:"added_by"`
	}
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("parsing vulns blame output: %v", err)
	}

	for _, entry := range entries {
		if entry.VulnID == vuln.ID && entry.Package == "express" && entry.AddedBy == "Test User" {
			return
		}
	}

	t.Fatalf("expected express vulnerability blame entry, got: %#v", entries)
}

func TestVulnsExposureResolvesHEAD(t *testing.T) {
	vuln := setupVulnerableNPMRepo(t)

	stdout, _, err := runCmd(t, "vulns", "exposure", "--format", "json")
	if err != nil {
		t.Fatalf("vulns exposure failed: %v", err)
	}

	var entries []struct {
		VulnID       string `json:"vuln_id"`
		Package      string `json:"package"`
		IntroducedBy string `json:"introduced_by"`
	}
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("parsing vulns exposure output: %v", err)
	}

	for _, entry := range entries {
		if entry.VulnID == vuln.ID && entry.Package == "express" && entry.IntroducedBy == "Test User" {
			return
		}
	}

	t.Fatalf("expected express vulnerability exposure entry, got: %#v", entries)
}

func setupVulnerableNPMRepo(t *testing.T) database.Vulnerability {
	t.Helper()

	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")
	addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add package-lock.json")

	cleanup := chdir(t, repoDir)
	t.Cleanup(cleanup)

	if _, _, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}

	vuln := database.Vulnerability{
		ID:        "GHSA-issue-299",
		Severity:  "high",
		Summary:   "Test vulnerability",
		FetchedAt: time.Now().Format(time.RFC3339),
	}
	if err := db.InsertVulnerability(vuln); err != nil {
		_ = db.Close()
		t.Fatalf("inserting vulnerability: %v", err)
	}
	if err := db.InsertVulnerabilityPackage(database.VulnerabilityPackage{
		VulnerabilityID: vuln.ID,
		Ecosystem:       "npm",
		PackageName:     "express",
		FixedVersions:   "4.19.0",
	}); err != nil {
		_ = db.Close()
		t.Fatalf("inserting vulnerability package: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing database: %v", err)
	}

	return vuln
}
