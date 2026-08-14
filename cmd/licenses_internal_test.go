package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
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
		Direct:       true,
	}

	for _, tt := range []struct {
		name          string
		deps          []database.Dependency
		wantPURL      string
		wantAmbiguous bool
	}{
		{
			name:     "one resolved version in the manifest directory",
			deps:     []database.Dependency{direct, resolved},
			wantPURL: "pkg:npm/ua-parser-js@1.0.41",
		},
		{
			name:     "direct resolved version disambiguates multiple versions",
			wantPURL: "pkg:npm/ua-parser-js@1.0.41",
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
			name:          "multiple resolved versions without direct marker are ambiguous",
			wantAmbiguous: true,
			deps: func() []database.Dependency {
				first := resolved
				first.Direct = false
				second := first
				second.PURL = "pkg:npm/ua-parser-js@0.7.41"
				second.Requirement = "0.7.41"
				return []database.Dependency{direct, first, second}
			}(),
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
			versions, resolvedDeps, ambiguous := resolvedLicenseVersions(
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
			if ambiguous[direct.PURL] != tt.wantAmbiguous {
				t.Fatalf("ambiguous = %v, want %v", ambiguous[direct.PURL], tt.wantAmbiguous)
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

func TestCachedLicenseDataMatchesFetchedNormalization(t *testing.T) {
	const packagePURL = "pkg:npm/example"
	rawLicense := " mit "

	db, _, err := database.OpenOrCreate(filepath.Join(t.TempDir(), "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("OpenOrCreate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.SavePackageEnrichment(packagePURL, "npm", "example", "1.0.0", rawLicense, "", "test"); err != nil {
		t.Fatalf("SavePackageEnrichment: %v", err)
	}

	cached, missing, err := cachedLicenseData(db, []string{packagePURL}, true)
	if err != nil {
		t.Fatalf("cachedLicenseData: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("missing PURLs = %q, want none", missing)
	}
	fetched := licenseDataFromPackage(&enrichment.PackageInfo{
		Ecosystem:     "npm",
		Name:          "example",
		LatestVersion: "1.0.0",
		License:       rawLicense,
	})

	if cached[packagePURL].License != fetched.License {
		t.Fatalf("cached license = %q, fetched license = %q", cached[packagePURL].License, fetched.License)
	}
	if fetched.License != "MIT" {
		t.Fatalf("normalized license = %q, want MIT", fetched.License)
	}
}

func TestLicensePolicyEvaluate(t *testing.T) {
	for _, tt := range []struct {
		name        string
		opts        licenseOptions
		licenses    []string
		wantFlagged bool
		wantReason  string
	}{
		{
			name:     "no policy",
			licenses: []string{"MIT"},
		},
		{
			name:        "unknown license",
			opts:        licenseOptions{flagUnknown: true},
			wantFlagged: true,
			wantReason:  "unknown license",
		},
		{
			name:     "normalized allow list",
			opts:     licenseOptions{allowList: []string{"mit"}},
			licenses: []string{"MIT"},
		},
		{
			name:        "license outside allow list",
			opts:        licenseOptions{allowList: []string{"Apache-2.0"}},
			licenses:    []string{"MIT"},
			wantFlagged: true,
			wantReason:  `license "MIT" not in allow list`,
		},
		{
			name:        "normalized deny list",
			opts:        licenseOptions{denyList: []string{"mit"}},
			licenses:    []string{"MIT"},
			wantFlagged: true,
			wantReason:  `license "MIT" is denied`,
		},
		{
			name:        "non-permissive license",
			opts:        licenseOptions{flagPermissive: true},
			licenses:    []string{"LGPL-3.0-or-later"},
			wantFlagged: true,
			wantReason:  `license "LGPL-3.0-or-later" is not permissive`,
		},
		{
			name:        "copyleft license",
			opts:        licenseOptions{flagCopyleft: true},
			licenses:    []string{"GPL-3.0-only"},
			wantFlagged: true,
			wantReason:  `license "GPL-3.0-only" is copyleft`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flagged, reason := newLicensePolicy(tt.opts).evaluate(tt.licenses)
			if flagged != tt.wantFlagged {
				t.Errorf("flagged = %v, want %v", flagged, tt.wantFlagged)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestOutputLicenses(t *testing.T) {
	infos := []LicenseInfo{{
		Name:         "example",
		Ecosystem:    "npm",
		Version:      "1.0.0",
		Licenses:     []string{"MIT"},
		ManifestPath: "package.json",
		Flagged:      true,
		FlagReason:   "test policy",
	}}

	for _, tt := range []struct {
		name    string
		format  string
		groupBy bool
		want    []string
	}{
		{
			name:   "csv",
			format: formatCSV,
			want:   []string{"Name,Ecosystem,Version,Licenses,Manifest,Flagged,Reason", "example,npm,1.0.0,MIT,package.json,yes,test policy"},
		},
		{
			name:    "grouped text",
			format:  formatText,
			groupBy: true,
			want:    []string{"MIT:", "example [FLAGGED: test policy]"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			if err := outputLicenses(command, infos, tt.format, tt.groupBy); err != nil {
				t.Fatalf("outputLicenses: %v", err)
			}
			for _, want := range tt.want {
				if !strings.Contains(output.String(), want) {
					t.Errorf("output missing %q: %s", want, output.String())
				}
			}
		})
	}
}

func TestOutputLicenseDriftCSV(t *testing.T) {
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	entries := []LicenseDriftEntry{{
		Name:           "example",
		Ecosystem:      "npm",
		CurrentVersion: "1.0.0",
		LatestVersion:  "2.0.0",
		CurrentLicense: "MIT",
		LatestLicense:  "Apache-2.0",
		ManifestPath:   "package-lock.json",
		PURL:           "pkg:npm/example@1.0.0",
	}}

	if err := outputLicenseDriftCSV(command, entries); err != nil {
		t.Fatalf("outputLicenseDriftCSV: %v", err)
	}
	for _, want := range []string{
		"Name,Ecosystem,Current Version,Latest Version,Current License,Latest License,Manifest,PURL",
		"example,npm,1.0.0,2.0.0,MIT,Apache-2.0,package-lock.json,pkg:npm/example@1.0.0",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("output missing %q: %s", want, output.String())
		}
	}
}

func TestOutputLicenseDriftText(t *testing.T) {
	for _, tt := range []struct {
		name   string
		result *LicenseDriftResult
		want   []string
	}{
		{
			name: "empty with unresolved dependencies",
			result: &LicenseDriftResult{
				Summary: LicenseDriftSummary{UnresolvedDependencies: 2},
			},
			want: []string{"No license drift detected.", "Unresolved dependencies: 2"},
		},
		{
			name: "drift without latest version",
			result: &LicenseDriftResult{
				Dependencies: []LicenseDriftEntry{{
					Name:           "example",
					Ecosystem:      "npm",
					CurrentVersion: "1.0.0",
					CurrentLicense: "MIT",
					LatestLicense:  "Apache-2.0",
				}},
			},
			want: []string{"Found 1 dependencies with license drift:", "example (npm): 1.0.0 MIT -> latest Apache-2.0"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&output)
			outputLicenseDriftText(command, tt.result)
			for _, want := range tt.want {
				if !strings.Contains(output.String(), want) {
					t.Errorf("output missing %q: %s", want, output.String())
				}
			}
		})
	}
}
