package cmd_test

import (
	"strings"
	"testing"
)

func TestWhereCommandHonorsNestedGitignore(t *testing.T) {
	repoDir := createTestRepo(t)
	writeFile(t, repoDir, "packages/.gitignore", "ignored/\n")
	writeFile(t, repoDir, "packages/included/package.json", `{"dependencies":{"lodash":"4.17.21"}}`)
	writeFile(t, repoDir, "packages/ignored/package.json", `{"dependencies":{"lodash":"4.17.21"}}`)

	cleanup := chdir(t, repoDir)
	defer cleanup()

	stdout, _, err := runCmd(t, "where", "lodash")
	if err != nil {
		t.Fatalf("where failed: %v", err)
	}
	if !strings.Contains(stdout, "packages/included/package.json") {
		t.Fatalf("where output missing included manifest: %s", stdout)
	}
	if strings.Contains(stdout, "packages/ignored/package.json") {
		t.Fatalf("where output contains ignored manifest: %s", stdout)
	}
}

func TestWhereCommandHonorsEcosystemFilter(t *testing.T) {
	repoDir := createTestRepo(t)
	writeFile(t, repoDir, "package.json", `{"dependencies":{"lodash":"4.17.21"}}`)
	setGitConfig(t, repoDir, "pkgs.ignoredEcosystems", "npm")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	stdout, _, err := runCmd(t, "where", "lodash")
	if err != nil {
		t.Fatalf("where failed: %v", err)
	}
	if !strings.Contains(stdout, `Package "lodash" not found in manifest files.`) {
		t.Fatalf("unexpected where output: %s", stdout)
	}
}
