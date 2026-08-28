package cmd_test

import (
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

const swiftRegistryPackageResolved = `{
  "pins": [
    {
	  "identity": "apple.swift-argument-parser",
	  "kind": "registry",
	  "location": "apple.swift-argument-parser",
      "state": {
        "revision": "19b3c3ceed117c5cc883517c4e658548315ba70b",
        "version": "1.6.0"
      }
    }
  ],
  "version": 2
}`

const swiftSourcePackageResolved = `{
  "pins": [
    {
      "identity": "cryptoswift",
      "kind": "remoteSourceControl",
      "location": "https://github.com/krzyzanowskim/CryptoSwift.git",
      "state": {
        "revision": "19b3c3ceed117c5cc883517c4e658548315ba70b",
        "version": "1.6.0"
      }
    }
  ],
  "version": 2
}`

func TestVulnsHistoryRejectsUnrepresentablePackageIdentity(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "Package.resolved", swiftRegistryPackageResolved, "Add Swift lockfile")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_, _, err := runCmd(t, "vulns", "history", "apple.swift-argument-parser", "--format", "json")
	if err == nil {
		t.Fatal("vulns history error = nil, want unsupported package identity error")
	}

	want := `querying OSV for swift package "apple.swift-argument-parser": package identity cannot be represented as a PURL`
	if err.Error() != want {
		t.Fatalf("vulns history error = %q, want %q", err, want)
	}
}

func TestVulnsScanReportsUnrepresentablePackageIdentity(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "Package.resolved", swiftRegistryPackageResolved, "Add Swift lockfile")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	_, stderr, err := runCmd(t, "vulns", "scan", "--live")
	if err != nil {
		t.Fatalf("vulns scan failed: %v", err)
	}
	want := "Skipping 1 dependency with a package identity that cannot be represented as a PURL: " +
		"swift package \"apple.swift-argument-parser\" (Package.resolved).\n"
	if stderr != want {
		t.Fatalf("vulns scan stderr = %q, want %q", stderr, want)
	}
}

func TestInitStoresSwiftSourceCoordinate(t *testing.T) {
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "Package.resolved", swiftSourcePackageResolved, "Add Swift lockfile")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	if _, _, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer func() { _ = db.Close() }()
	branch, err := db.GetDefaultBranch()
	if err != nil {
		t.Fatalf("get default branch: %v", err)
	}
	dependencies, err := db.GetLatestDependencies(branch.ID)
	if err != nil {
		t.Fatalf("get latest dependencies: %v", err)
	}
	if len(dependencies) != 1 {
		t.Fatalf("dependencies = %+v, want one Swift dependency", dependencies)
	}
	if dependencies[0].Name != "github.com/krzyzanowskim/CryptoSwift" {
		t.Errorf("dependency name = %q, want source coordinate", dependencies[0].Name)
	}
	if dependencies[0].PURL != "pkg:swift/github.com/krzyzanowskim/CryptoSwift@1.6.0" {
		t.Errorf("dependency PURL = %q, want source PURL", dependencies[0].PURL)
	}
}
