package cmd_test

import "testing"

const swiftRegistryPackageResolved = `{
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

	_, _, err := runCmd(t, "vulns", "history", "cryptoswift", "--format", "json")
	if err == nil {
		t.Fatal("vulns history error = nil, want unsupported package identity error")
	}

	want := `querying OSV for swift package "cryptoswift": package identity cannot be represented as a PURL`
	if err.Error() != want {
		t.Fatalf("vulns history error = %q, want %q", err, want)
	}
}
