package cmd

import (
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestResolvedLicenseVersions(t *testing.T) {
	direct := database.Dependency{
		Name:         "ua-parser-js",
		Ecosystem:    "npm",
		PURL:         "pkg:npm/ua-parser-js",
		Requirement:  "^1.0.41",
		ManifestPath: "app/package.json",
		ManifestKind: "manifest",
	}
	resolved := database.Dependency{
		Name:         "ua-parser-js",
		Ecosystem:    "npm",
		PURL:         "pkg:npm/ua-parser-js@1.0.41",
		Requirement:  "1.0.41",
		ManifestPath: "app/package-lock.json",
		ManifestKind: manifestKindLockfile,
	}

	for _, tt := range []struct {
		name     string
		deps     []database.Dependency
		wantPURL string
	}{
		{
			name:     "one resolved version in the manifest directory",
			deps:     []database.Dependency{direct, resolved},
			wantPURL: "pkg:npm/ua-parser-js@1.0.41",
		},
		{
			name: "multiple resolved versions are ambiguous",
			deps: []database.Dependency{
				direct,
				resolved,
				{
					Name:         "ua-parser-js",
					Ecosystem:    "npm",
					PURL:         "pkg:npm/ua-parser-js@0.7.41",
					Requirement:  "0.7.41",
					ManifestPath: "app/package-lock.json",
					ManifestKind: manifestKindLockfile,
				},
			},
		},
		{
			name: "resolved version in another directory does not match",
			deps: []database.Dependency{
				direct,
				{
					Name:         resolved.Name,
					Ecosystem:    resolved.Ecosystem,
					PURL:         resolved.PURL,
					Requirement:  resolved.Requirement,
					ManifestPath: "other/package-lock.json",
					ManifestKind: resolved.ManifestKind,
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			versions, resolvedDeps := resolvedLicenseVersions(
				map[string]database.Dependency{direct.PURL: direct},
				tt.deps,
			)
			if versions[direct.PURL] != tt.wantPURL {
				t.Fatalf("resolved version = %q, want %q", versions[direct.PURL], tt.wantPURL)
			}
			wantDeps := 0
			if tt.wantPURL != "" {
				wantDeps = 1
			}
			if len(resolvedDeps) != wantDeps {
				t.Fatalf("resolved dependencies = %d, want %d", len(resolvedDeps), wantDeps)
			}
		})
	}
}

func TestLoadLicenseVersionLicensesOfflineCacheMiss(t *testing.T) {
	_, err := loadLicenseVersionLicenses(nil, []database.Dependency{
		{
			Name:         "ua-parser-js",
			Ecosystem:    "npm",
			PURL:         "pkg:npm/ua-parser-js@1.0.41",
			Requirement:  "1.0.41",
			ManifestPath: "package-lock.json",
			ManifestKind: manifestKindLockfile,
		},
	}, true)
	if err == nil {
		t.Fatal("offline cache miss error = nil, want error")
	}
	if !strings.Contains(err.Error(), "rerun without --offline") {
		t.Fatalf("offline cache miss error = %q, want generic rerun guidance", err)
	}
	if strings.Contains(err.Error(), "--drift") {
		t.Fatalf("offline cache miss error = %q, should apply to both license modes", err)
	}
}
