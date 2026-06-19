package cmd_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestIsPURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"pkg:cargo/serde@1.0.0", true},
		{"pkg:npm/lodash", true},
		{"pkg:npm/%40scope/pkg@1.0.0", true},
		{"serde", false},
		{"lodash", false},
		{"", false},
		{"package:npm/lodash", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cmd.IsPURL(tt.input)
			if got != tt.want {
				t.Errorf("IsPURL(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestUrlsPURL(t *testing.T) {
	t.Run("returns urls for cargo purl", func(t *testing.T) {
		stdout, _, err := runCmd(t, "urls", "pkg:cargo/serde@1.0.0")
		if err != nil {
			t.Fatalf("urls failed: %v", err)
		}
		if !strings.Contains(stdout, "registry") {
			t.Errorf("expected 'registry' in output, got: %s", stdout)
		}
		if !strings.Contains(stdout, "purl") {
			t.Errorf("expected 'purl' in output, got: %s", stdout)
		}
		if !strings.Contains(stdout, "crates.io") {
			t.Errorf("expected 'crates.io' in output, got: %s", stdout)
		}
	})

	t.Run("returns urls for npm purl", func(t *testing.T) {
		stdout, _, err := runCmd(t, "urls", "pkg:npm/express@4.19.0")
		if err != nil {
			t.Fatalf("urls failed: %v", err)
		}
		if !strings.Contains(stdout, "npmjs") {
			t.Errorf("expected 'npmjs' in output, got: %s", stdout)
		}
	})

	t.Run("json format", func(t *testing.T) {
		stdout, _, err := runCmd(t, "urls", "pkg:cargo/serde@1.0.0", "-f", "json")
		if err != nil {
			t.Fatalf("urls json failed: %v", err)
		}

		var urls map[string]string
		if err := json.Unmarshal([]byte(stdout), &urls); err != nil {
			t.Fatalf("failed to parse JSON: %v", err)
		}
		if urls["registry"] == "" {
			t.Error("expected registry URL in json output")
		}
		if urls["purl"] == "" {
			t.Error("expected purl in json output")
		}
	})

	t.Run("errors on invalid purl", func(t *testing.T) {
		_, _, err := runCmd(t, "urls", "pkg:")
		if err == nil {
			t.Error("expected error for invalid purl")
		}
	})

	t.Run("errors on unsupported ecosystem", func(t *testing.T) {
		_, _, err := runCmd(t, "urls", "pkg:nonexistent/foo@1.0.0")
		if err == nil {
			t.Error("expected error for unsupported ecosystem")
		}
		if err != nil && !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("expected 'unsupported' in error, got: %v", err)
		}
	})
}

func initRepoWithFiles(t *testing.T, files map[string]string) {
	t.Helper()
	repoDir := createTestRepo(t)
	for path, content := range files {
		addFileAndCommit(t, repoDir, path, content, "Add "+path)
	}
	cleanup := chdir(t, repoDir)
	t.Cleanup(cleanup)
	if _, _, err := runCmd(t, "init"); err != nil {
		t.Fatalf("init failed: %v", err)
	}
}

func runUrlsJSON(t *testing.T, args ...string) map[string]string {
	t.Helper()
	args = append([]string{"urls"}, args...)
	args = append(args, "-f", "json")
	stdout, _, err := runCmd(t, args...)
	if err != nil {
		t.Fatalf("urls failed: %v", err)
	}
	var urls map[string]string
	if err := json.Unmarshal([]byte(stdout), &urls); err != nil {
		t.Fatalf("failed to parse JSON: %v\noutput: %s", err, stdout)
	}
	return urls
}

func TestUrlsNameLookup(t *testing.T) {
	t.Run("manifest-only lookup omits version range", func(t *testing.T) {
		initRepoWithFiles(t, map[string]string{"package.json": packageJSON})

		urls := runUrlsJSON(t, "lodash", "-e", "npm")
		if urls["registry"] == "" {
			t.Errorf("expected registry URL, got: %v", urls)
		}
		if urls["purl"] != "pkg:npm/lodash" {
			t.Errorf("expected versionless purl pkg:npm/lodash, got: %q", urls["purl"])
		}
		if urls["download"] != "" {
			t.Errorf("expected no download URL without resolved version, got: %q", urls["download"])
		}
	})

	t.Run("substring lookup uses matched name", func(t *testing.T) {
		initRepoWithFiles(t, map[string]string{"package.json": packageJSON})

		urls := runUrlsJSON(t, "lod", "-e", "npm")
		if urls["purl"] != "pkg:npm/lodash" {
			t.Errorf("expected purl for matched package lodash, got: %q", urls["purl"])
		}
		if !strings.Contains(urls["registry"], "/lodash") {
			t.Errorf("expected registry URL for lodash, got: %q", urls["registry"])
		}
	})

	t.Run("lockfile lookup uses resolved version", func(t *testing.T) {
		initRepoWithFiles(t, map[string]string{
			"package.json":      packageJSON,
			"package-lock.json": packageLockJSON,
		})

		urls := runUrlsJSON(t, "lodash", "-e", "npm")
		if urls["purl"] != "pkg:npm/lodash@4.17.21" {
			t.Errorf("expected purl pkg:npm/lodash@4.17.21, got: %q", urls["purl"])
		}
		if urls["download"] != "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" {
			t.Errorf("expected exact download URL, got: %q", urls["download"])
		}
	})

	t.Run("go.mod lookup keeps exact version", func(t *testing.T) {
		goMod, err := os.ReadFile("testdata/ades-go.mod")
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		initRepoWithFiles(t, map[string]string{"go.mod": string(goMod)})

		urls := runUrlsJSON(t, "golang.org/x/mod", "-e", "golang")
		if urls["purl"] != "pkg:golang/golang.org/x/mod@v0.32.0" {
			t.Errorf("expected versioned purl, got: %q", urls["purl"])
		}
	})

	t.Run("errors when package not found", func(t *testing.T) {
		initRepoWithFiles(t, map[string]string{"package.json": packageJSON})

		_, _, err := runCmd(t, "urls", "nonexistent-package-xyz")
		if err == nil {
			t.Error("expected error for non-existent package")
		}
	})

	t.Run("errors when no database exists", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "README.md", "# Test", "Initial commit")
		cleanup := chdir(t, repoDir)
		defer cleanup()

		_, _, err := runCmd(t, "urls", "lodash")
		if err == nil {
			t.Error("expected error without database")
		}
	})
}
