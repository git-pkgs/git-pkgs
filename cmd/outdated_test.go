package cmd_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

func outdatedLockfile(versions ...string) string {
	var packages []string
	for i, version := range versions {
		path := "node_modules/lodash"
		if i > 0 {
			path = fmt.Sprintf("node_modules/parent%d/node_modules/lodash", i)
		}
		packages = append(packages, fmt.Sprintf("    %q: {\n      \"version\": %q\n    }", path, version))
	}
	return fmt.Sprintf(`{
  "name": "test-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
%s
  }
}
`, strings.Join(packages, ",\n"))
}

func TestOutdatedPreservesDependencyOccurrences(t *testing.T) {
	type occurrence struct {
		path       string
		version    string
		updateType string
	}
	tests := []struct {
		name      string
		manifests map[string]string
		want      []occurrence
	}{
		{
			name: "current occurrence does not hide outdated manifest",
			manifests: map[string]string{
				"apps/web/package-lock.json":     outdatedLockfile("4.17.20"),
				"services/api/package-lock.json": outdatedLockfile("4.17.21"),
			},
			want: []occurrence{{"apps/web/package-lock.json", "4.17.20", "patch"}},
		},
		{
			name: "current occurrence does not hide outdated installed version",
			manifests: map[string]string{
				"package-lock.json": outdatedLockfile("4.17.20", "4.17.21"),
			},
			want: []occurrence{{"package-lock.json", "4.17.20", "patch"}},
		},
		{
			name: "multiple outdated versions and manifests",
			manifests: map[string]string{
				"apps/web/package-lock.json":     outdatedLockfile("3.10.1", "4.16.0", "4.17.20"),
				"services/api/package-lock.json": outdatedLockfile("4.17.20"),
			},
			want: []occurrence{
				{"apps/web/package-lock.json", "3.10.1", "major"},
				{"apps/web/package-lock.json", "4.16.0", "minor"},
				{"apps/web/package-lock.json", "4.17.20", "patch"},
				{"services/api/package-lock.json", "4.17.20", "patch"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoDir := createTestRepo(t)
			for path, content := range tt.manifests {
				addFileAndCommit(t, repoDir, path, content, "Add lockfile")
			}
			cleanup := chdir(t, repoDir)
			defer cleanup()
			if _, _, err := runCmd(t, "init"); err != nil {
				t.Fatalf("init failed: %v", err)
			}
			db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
			if err != nil {
				t.Fatalf("open db: %v", err)
			}
			err = db.SavePackageEnrichment("pkg:npm/lodash", "npm", "lodash", "4.17.21", "MIT", "https://registry.npmjs.org", "test")
			if err == nil {
				err = db.SaveVersionList("pkg:npm/lodash", []database.CachedVersion{
					{
						PURL: "pkg:npm/lodash@4.17.20", PackagePURL: "pkg:npm/lodash",
						PublishedAt: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC), StatusCheckedAt: time.Now(),
					},
					{
						PURL: "pkg:npm/lodash@4.17.21", PackagePURL: "pkg:npm/lodash",
						PublishedAt: time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC), StatusCheckedAt: time.Now(),
					},
				})
			}
			if closeErr := db.Close(); closeErr != nil {
				t.Fatalf("close db: %v", closeErr)
			}
			if err != nil {
				t.Fatalf("save cached package metadata: %v", err)
			}

			for _, filter := range []string{"", "--major", "--minor", "--ecosystem=npm", "--ecosystem=pypi", "--at=2024-06-01"} {
				t.Run("json "+filter, func(t *testing.T) {
					args := []string{"outdated", "--format=json"}
					if filter != "" {
						args = append(args, filter)
					}
					stdout, _, err := runCmd(t, args...)
					if err != nil {
						t.Fatalf("outdated failed: %v", err)
					}
					var got []cmd.OutdatedPackage
					if err := json.Unmarshal([]byte(stdout), &got); err != nil {
						t.Fatalf("parse outdated JSON: %v", err)
					}
					want := make(map[cmd.OutdatedPackage]bool)
					for _, item := range tt.want {
						if filter == "--ecosystem=pypi" || filter == "--major" && item.updateType != "major" || filter == "--minor" && item.updateType == "patch" {
							continue
						}
						latest := "4.17.21"
						if filter == "--at=2024-06-01" {
							latest = "4.17.20"
							if item.version == latest {
								continue
							}
						}
						want[cmd.OutdatedPackage{
							Name: "lodash", Ecosystem: "npm", PURL: "pkg:npm/lodash",
							CurrentVersion: item.version, LatestVersion: latest,
							UpdateType: item.updateType, ManifestPath: item.path,
						}] = true
					}
					if len(got) != len(want) {
						t.Fatalf("outdated occurrences = %+v, want %d entries", got, len(want))
					}
					for _, item := range got {
						if !want[item] {
							t.Errorf("unexpected or duplicate outdated occurrence: %+v", item)
						}
						delete(want, item)
					}
				})
			}

			t.Run("text includes version and manifest", func(t *testing.T) {
				stdout, _, err := runCmd(t, "outdated")
				if err != nil {
					t.Fatalf("outdated failed: %v", err)
				}
				if !strings.Contains(stdout, fmt.Sprintf("Found %d outdated dependencies:", len(tt.want))) {
					t.Errorf("incorrect outdated count: %s", stdout)
				}
				for _, item := range tt.want {
					found := false
					for _, line := range strings.Split(stdout, "\n") {
						if strings.Contains(line, "lodash "+item.version+" -> 4.17.21") && strings.Contains(line, item.path) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("missing %s at %s from text output: %s", item.version, item.path, stdout)
					}
				}
			})
		})
	}
}
