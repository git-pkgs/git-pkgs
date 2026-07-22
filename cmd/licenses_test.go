package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/spdx"
)

// mockEnrichmentClient returns canned license data instead of calling external APIs.
type mockEnrichmentClient struct {
	mu               sync.Mutex
	packages         map[string]*enrichment.PackageInfo
	versions         map[string][]enrichment.VersionInfo
	versionInfos     map[string]*enrichment.VersionInfo
	getVersionsCalls int
	getVersionCalls  int
	bulkLookupCalls  int
	getVersionErr    error
}

func (m *mockEnrichmentClient) BulkLookup(_ context.Context, purls []string) (map[string]*enrichment.PackageInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bulkLookupCalls++

	result := make(map[string]*enrichment.PackageInfo)
	for _, p := range purls {
		if pkg, ok := m.packages[p]; ok {
			result[p] = pkg
		}
	}
	return result, nil
}

func (m *mockEnrichmentClient) GetVersions(_ context.Context, purl string) ([]enrichment.VersionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getVersionsCalls++
	return m.versions[purl], nil
}

func (m *mockEnrichmentClient) GetVersion(_ context.Context, purl string) (*enrichment.VersionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getVersionCalls++
	if m.getVersionErr != nil {
		return nil, m.getVersionErr
	}
	if info, ok := m.versionInfos[purl]; ok {
		return info, nil
	}
	return nil, nil
}

// setMockEnrichment replaces the enrichment client constructor with one that
// returns a mock, and returns a cleanup function to restore the original.
func setMockEnrichment(packages map[string]*enrichment.PackageInfo) func() {
	return setMockEnrichmentWithVersions(packages, nil)
}

func setMockEnrichmentWithVersions(packages map[string]*enrichment.PackageInfo, versions map[string][]enrichment.VersionInfo) func() {
	mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: packages, versions: versions})
	_ = mock
	return restore
}

func setMockEnrichmentWithVersionInfos(
	packages map[string]*enrichment.PackageInfo,
	versions map[string]*enrichment.VersionInfo,
) (*mockEnrichmentClient, func()) {
	return setMockEnrichmentClient(&mockEnrichmentClient{packages: packages, versionInfos: versions})
}

func setMockEnrichmentClient(mock *mockEnrichmentClient) (*mockEnrichmentClient, func()) {
	orig := cmd.NewEnrichmentClient
	cmd.NewEnrichmentClient = func(opts ...enrichment.Option) (enrichment.Client, error) {
		return mock, nil
	}
	return mock, func() { cmd.NewEnrichmentClient = orig }
}

// Gemfile with a known copyleft dependency (sidekiq uses LGPL)
const gemfileWithLGPL = `source 'https://rubygems.org'
gem 'sidekiq'
gem 'rails'
`

const uaParserPackageJSON = `{
  "dependencies": {
    "ua-parser-js": "^1.0.41"
  }
}
`

const uaParserPackageLockJSON = `{
  "name": "license-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "ua-parser-js": "^1.0.41"
      }
    },
    "node_modules/ua-parser-js": {
      "version": "1.0.41"
    }
  }
}
`

func TestLicensesCommand(t *testing.T) {
	t.Setenv("GIT_PKGS_DB", "")

	t.Run("permissive flag detects non-permissive licenses", func(t *testing.T) {
		restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
			"pkg:gem/sidekiq": {Ecosystem: "rubygems", Name: "sidekiq", License: "LGPL-3.0-or-later"},
			"pkg:gem/rails":   {Ecosystem: "rubygems", Name: "rails", License: "MIT"},
		})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--permissive"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if !strings.Contains(output, "LGPL") {
			t.Fatalf("expected LGPL in output, got: %s", output)
		}
		if !strings.Contains(output, "FLAGGED") {
			t.Error("LGPL license detected but not flagged as non-permissive")
		}
		if err == nil {
			t.Error("expected command to return error when violations found")
		}
	})

	t.Run("deny flag blocks specified licenses", func(t *testing.T) {
		restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
			"pkg:gem/sidekiq": {Ecosystem: "rubygems", Name: "sidekiq", License: "LGPL-3.0-or-later"},
			"pkg:gem/rails":   {Ecosystem: "rubygems", Name: "rails", License: "MIT"},
		})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--deny", "LGPL"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if !strings.Contains(output, "LGPL") {
			t.Fatalf("expected LGPL in output, got: %s", output)
		}
		if !strings.Contains(output, "FLAGGED") {
			t.Error("LGPL license detected but not flagged as denied")
		}
		if err == nil {
			t.Error("expected command to return error when denied license found")
		}
	})

	for _, tt := range []struct {
		name           string
		versionLicense string
		wantLicense    string
		wantViolation  bool
		wantWarning    bool
	}{
		{
			name:           "license policies use installed version metadata",
			versionLicense: "MIT",
			wantLicense:    "MIT",
		},
		{
			name:          "license policies fall back to package metadata",
			wantLicense:   "AGPL-3.0-or-later",
			wantViolation: true,
		},
		{
			name:          "license policies warn when version lookup fails",
			wantLicense:   "AGPL-3.0-or-later",
			wantViolation: true,
			wantWarning:   true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mock, restore := setMockEnrichmentWithVersionInfos(
				map[string]*enrichment.PackageInfo{
					"pkg:npm/ua-parser-js": {
						Ecosystem:     "npm",
						Name:          "ua-parser-js",
						LatestVersion: "2.0.10",
						License:       "AGPL-3.0-or-later",
					},
				},
				map[string]*enrichment.VersionInfo{
					"pkg:npm/ua-parser-js@1.0.41": {Number: "1.0.41", License: tt.versionLicense},
				},
			)
			defer restore()
			if tt.wantWarning {
				mock.getVersionErr = errors.New("enrichment unavailable")
			}

			initRepoWithFiles(t, map[string]string{
				"package.json":      uaParserPackageJSON,
				"package-lock.json": uaParserPackageLockJSON,
			})

			stdout, stderr, err := runCmd(t, "licenses", "--deny", "AGPL-3.0-or-later", "--format", "json")
			if (err != nil) != tt.wantViolation {
				t.Fatalf("licenses error = %v, want violation %v", err, tt.wantViolation)
			}
			gotWarning := strings.Contains(stderr, "Warning: version license lookup failed")
			if gotWarning != tt.wantWarning {
				t.Fatalf("version lookup warning = %v, want %v; stderr: %s", gotWarning, tt.wantWarning, stderr)
			}

			var result []cmd.LicenseInfo
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatalf("parse licenses output: %v\nOutput: %s", err, stdout)
			}
			if len(result) != 1 {
				t.Fatalf("license entries = %d, want 1", len(result))
			}
			if len(result[0].Licenses) != 1 || result[0].Licenses[0] != tt.wantLicense {
				t.Fatalf("licenses = %v, want [%s]", result[0].Licenses, tt.wantLicense)
			}
			if result[0].Flagged != tt.wantViolation {
				t.Fatalf("flagged = %v, want %v", result[0].Flagged, tt.wantViolation)
			}

			mock.mu.Lock()
			getVersionCalls := mock.getVersionCalls
			mock.mu.Unlock()
			if getVersionCalls != 1 {
				t.Fatalf("GetVersion calls = %d, want 1", getVersionCalls)
			}
		})
	}

	t.Run("copyleft flag detects copyleft licenses", func(t *testing.T) {
		restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
			"pkg:gem/sidekiq": {Ecosystem: "rubygems", Name: "sidekiq", License: "LGPL-3.0-or-later"},
			"pkg:gem/rails":   {Ecosystem: "rubygems", Name: "rails", License: "MIT"},
		})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--copyleft"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if !strings.Contains(output, "LGPL") {
			t.Fatalf("expected LGPL in output, got: %s", output)
		}
		if !strings.Contains(output, "FLAGGED") {
			t.Error("LGPL license detected but not flagged as copyleft")
		}
		if err == nil {
			t.Error("expected command to return error when copyleft license found")
		}
	})

	t.Run("json output format", func(t *testing.T) {
		restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
			"pkg:npm/express": {Ecosystem: "npm", Name: "express", License: "MIT"},
			"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", License: "MIT"},
		})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--format", "json"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		_ = rootCmd.Execute()

		output := stdout.String()
		if len(output) == 0 {
			t.Fatal("expected JSON output, got empty string")
		}

		var result []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, output)
		}

		if len(result) == 0 {
			t.Fatal("expected at least one license entry")
		}
		if _, ok := result[0]["name"]; !ok {
			t.Error("expected 'name' field in license JSON")
		}
	})

	t.Run("allow flag permits only listed licenses", func(t *testing.T) {
		restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
			"pkg:npm/express": {Ecosystem: "npm", Name: "express", License: "MIT"},
			"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", License: "BSD-3-Clause"},
		})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--allow", "MIT"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if !strings.Contains(output, "FLAGGED") {
			t.Error("non-MIT license (BSD-3-Clause) should be flagged when only MIT is allowed")
		}
		if err == nil {
			t.Error("expected command to return error when non-allowed license found")
		}
	})

	t.Run("offline uses stale cached metadata without a network request", func(t *testing.T) {
		mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: map[string]*enrichment.PackageInfo{
			"pkg:npm/express": {Ecosystem: "npm", Name: "express", License: "MIT"},
			"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", License: "BSD-3-Clause"},
			"pkg:npm/jest":    {Ecosystem: "npm", Name: "jest", License: "MIT"},
		}})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("initial licenses lookup failed: %v", err)
		}

		db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
		if err != nil {
			t.Fatalf("open database: %v", err)
		}
		staleAt := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
		if _, err := db.Exec("UPDATE packages SET enriched_at = ?", staleAt); err != nil {
			_ = db.Close()
			t.Fatalf("make cache stale: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}

		mock.mu.Lock()
		mock.bulkLookupCalls = 0
		mock.mu.Unlock()

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--offline"})
		rootCmd.SetOut(&stdout)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("offline licenses failed: %v", err)
		}
		if !strings.Contains(stdout.String(), "MIT") || !strings.Contains(stdout.String(), "BSD-3-Clause") {
			t.Fatalf("offline output did not use cached licenses: %s", stdout.String())
		}

		mock.mu.Lock()
		calls := mock.bulkLookupCalls
		mock.mu.Unlock()
		if calls != 0 {
			t.Fatalf("offline lookup made %d network call(s), want 0", calls)
		}
	})

	t.Run("offline fails when metadata is not cached", func(t *testing.T) {
		mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: map[string]*enrichment.PackageInfo{}})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--offline"})
		err := rootCmd.Execute()
		if err == nil {
			t.Fatal("expected offline lookup without cached metadata to fail")
		}
		if !strings.Contains(err.Error(), "license metadata is not cached") {
			t.Fatalf("unexpected error: %v", err)
		}

		mock.mu.Lock()
		calls := mock.bulkLookupCalls
		mock.mu.Unlock()
		if calls != 0 {
			t.Fatalf("offline lookup made %d network call(s), want 0", calls)
		}
	})

	t.Run("offline treats funding-only cache rows as missing license metadata", func(t *testing.T) {
		mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: map[string]*enrichment.PackageInfo{}})
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", `{"dependencies":{"express":"^4.18.0"}}`, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
		if err != nil {
			t.Fatalf("open database: %v", err)
		}
		if err := db.SavePackageFundingBatch([]database.PackageFundingData{{
			PURL:         "pkg:npm/express",
			Ecosystem:    "npm",
			Name:         "express",
			FundingLinks: []string{"https://opencollective.com/express"},
		}}); err != nil {
			_ = db.Close()
			t.Fatalf("save funding metadata: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}

		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--offline"})
		err = rootCmd.Execute()
		if err == nil {
			t.Fatal("expected offline lookup with funding-only cache metadata to fail")
		}
		if !strings.Contains(err.Error(), "license metadata is not cached") {
			t.Fatalf("unexpected error: %v", err)
		}

		mock.mu.Lock()
		calls := mock.bulkLookupCalls
		mock.mu.Unlock()
		if calls != 0 {
			t.Fatalf("offline lookup made %d network call(s), want 0", calls)
		}
	})

	t.Run("drift flag reports installed version license changes", func(t *testing.T) {
		mock, restore := setMockEnrichmentWithVersionInfos(
			map[string]*enrichment.PackageInfo{
				"pkg:npm/express": {Ecosystem: "npm", Name: "express", LatestVersion: "5.0.0", License: "GPL-3.0-only"},
				"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", LatestVersion: "4.17.21", License: "MIT"},
				"pkg:npm/jest":    {Ecosystem: "npm", Name: "jest", LatestVersion: "29.7.0", License: "MIT"},
			},
			map[string]*enrichment.VersionInfo{
				"pkg:npm/express@4.18.2": {Number: "4.18.2", License: "MIT"},
				"pkg:npm/lodash@4.17.21": {Number: "4.17.21", License: "MIT"},
				"pkg:npm/jest@29.7.0":    {Number: "29.7.0", License: "MIT"},
			},
		)
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--drift", "--format", "json"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("licenses --drift failed: %v\nstderr: %s", err, stderr.String())
		}

		var result cmd.LicenseDriftResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("failed to parse drift JSON: %v\nOutput: %s", err, stdout.String())
		}
		if result.Summary.DriftedDependencies != 1 {
			t.Fatalf("expected one drifted dependency, got %+v", result.Summary)
		}
		if len(result.Dependencies) != 1 {
			t.Fatalf("expected one drift entry, got %d", len(result.Dependencies))
		}

		entry := result.Dependencies[0]
		if entry.Name != "express" {
			t.Fatalf("expected express drift entry, got %q", entry.Name)
		}
		if entry.CurrentLicense != "MIT" || entry.LatestLicense != "GPL-3.0-only" {
			t.Fatalf("unexpected license drift values: %+v", entry)
		}

		mock.mu.Lock()
		getVersionCalls := mock.getVersionCalls
		getVersionsCalls := mock.getVersionsCalls
		mock.mu.Unlock()
		if getVersionCalls == 0 {
			t.Fatal("expected drift lookup to call GetVersion")
		}
		if getVersionsCalls != 0 {
			t.Fatalf("GetVersions calls = %d, want 0", getVersionsCalls)
		}

		db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
		if err != nil {
			t.Fatalf("open database: %v", err)
		}
		staleAt := time.Now().Add(-48 * time.Hour).Format(time.RFC3339)
		if _, err := db.Exec("UPDATE packages SET enriched_at = ?", staleAt); err != nil {
			_ = db.Close()
			t.Fatalf("make package cache stale: %v", err)
		}
		if _, err := db.Exec("UPDATE versions SET enriched_at = ?", staleAt); err != nil {
			_ = db.Close()
			t.Fatalf("make version cache stale: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}

		mock.mu.Lock()
		mock.bulkLookupCalls = 0
		mock.getVersionCalls = 0
		mock.mu.Unlock()

		stdout.Reset()
		stderr.Reset()
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--drift", "--offline", "--format", "json"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("offline license drift failed: %v\nstderr: %s", err, stderr.String())
		}

		mock.mu.Lock()
		bulkLookupCalls := mock.bulkLookupCalls
		getVersionCalls = mock.getVersionCalls
		mock.mu.Unlock()
		if bulkLookupCalls != 0 || getVersionCalls != 0 {
			t.Fatalf("offline drift made network calls: BulkLookup=%d GetVersion=%d", bulkLookupCalls, getVersionCalls)
		}
	})

	t.Run("drift text output omits repeated package names", func(t *testing.T) {
		_, restore := setMockEnrichmentWithVersionInfos(
			map[string]*enrichment.PackageInfo{
				"pkg:npm/express": {Ecosystem: "npm", Name: "express", LatestVersion: "5.0.0", License: "GPL-3.0-only"},
				"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", LatestVersion: "4.17.21", License: "MIT"},
				"pkg:npm/jest":    {Ecosystem: "npm", Name: "jest", LatestVersion: "29.7.0", License: "MIT"},
			},
			map[string]*enrichment.VersionInfo{
				"pkg:npm/express@4.18.2": {Number: "4.18.2", License: "MIT"},
				"pkg:npm/lodash@4.17.21": {Number: "4.17.21", License: "MIT"},
				"pkg:npm/jest@29.7.0":    {Number: "29.7.0", License: "MIT"},
			},
		)
		defer restore()

		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--drift"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("licenses --drift failed: %v\nstderr: %s", err, stderr.String())
		}

		output := stdout.String()
		if !strings.Contains(output, "express (npm): 4.18.2 MIT -> 5.0.0 GPL-3.0-only") {
			t.Fatalf("drift text output missing compact entry: %q", output)
		}
		if strings.Contains(output, "express@4.18.2") || strings.Contains(output, "express@5.0.0") {
			t.Fatalf("drift text output repeats package name: %q", output)
		}
	})

	t.Run("drift rejects incompatible license filters", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--drift", "--permissive", "--allow", "MIT"})
		err := rootCmd.Execute()
		if err == nil {
			t.Fatal("expected licenses --drift with filters to fail")
		}
		if !strings.Contains(err.Error(), "--drift cannot be combined with --allow, --permissive") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSpdxPermissiveCheck(t *testing.T) {
	tests := []struct {
		license    string
		permissive bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"BSD-3-Clause", true},
		{"BSD-2-Clause", true},
		{"ISC", true},
		{"GPL-3.0-only", false},
		{"GPL-2.0-only", false},
		{"LGPL-3.0-or-later", false},
		{"AGPL-3.0-only", false},
		{"MPL-2.0", false},
		{"MIT OR Apache-2.0", true},
		{"MIT OR GPL-3.0-only", false}, // has non-permissive option
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			got := spdx.IsFullyPermissive(tt.license)
			if got != tt.permissive {
				t.Errorf("IsFullyPermissive(%q) = %v, want %v", tt.license, got, tt.permissive)
			}
		})
	}
}

func TestSpdxCopyleftCheck(t *testing.T) {
	tests := []struct {
		license  string
		copyleft bool
	}{
		{"MIT", false},
		{"Apache-2.0", false},
		{"GPL-3.0-only", true},
		{"GPL-2.0-only", true},
		{"LGPL-3.0-or-later", true},
		{"AGPL-3.0-only", true},
		{"MPL-2.0", true},
		{"MIT OR GPL-3.0-only", true}, // has copyleft option
		{"MIT OR Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			got := spdx.HasCopyleft(tt.license)
			if got != tt.copyleft {
				t.Errorf("HasCopyleft(%q) = %v, want %v", tt.license, got, tt.copyleft)
			}
		})
	}
}

func TestSpdxNormalization(t *testing.T) {
	tests := []struct {
		input      string
		normalized string
	}{
		{"MIT", "MIT"},
		{"MIT License", "MIT"},
		{"Apache 2", "Apache-2.0"},
		{"Apache 2.0", "Apache-2.0"},
		{"GPL v3", "GPL-3.0-or-later"},
		{"GPLv3", "GPL-3.0-or-later"},
		{"LGPL 3", "LGPL-3.0-or-later"},
		{"BSD 3-Clause", "BSD-3-Clause"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := spdx.Normalize(tt.input)
			if err != nil {
				t.Fatalf("Normalize(%q) error: %v", tt.input, err)
			}
			if got != tt.normalized {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.normalized)
			}
		})
	}
}

// TestLicensesDockerPURLCanonicalization tests that docker images show proper
// names even when the API returns a canonicalized PURL different from the input.
// For example, pkg:docker/postgres becomes pkg:docker/library%2Fpostgres in the response.
func TestLicensesDockerPURLCanonicalization(t *testing.T) {
	restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
		"pkg:docker/postgres": {Ecosystem: "docker", Name: "postgres", License: "PostgreSQL"},
		"pkg:docker/redis":    {Ecosystem: "docker", Name: "redis", License: "BSD-3-Clause"},
	})
	defer restore()

	const dockerCompose = `version: '3'
services:
  db:
    image: postgres:16-alpine
  cache:
    image: redis:7-alpine
`
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "docker-compose.yml", dockerCompose, "Add docker-compose")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"init"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	rootCmd = cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"licenses", "--format", "json"})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	_ = rootCmd.Execute()

	output := stdout.String()
	if output == "" {
		t.Fatal("expected JSON output, got empty string")
	}

	var results []cmd.LicenseInfo
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, output)
	}

	for _, r := range results {
		if strings.Contains(r.PURL, "docker") {
			if r.Name == "" {
				t.Errorf("docker package %s has empty name", r.PURL)
			}
			if r.Ecosystem == "" {
				t.Errorf("docker package %s has empty ecosystem", r.PURL)
			}
		}
	}
}

func TestSpdxDenyListMatching(t *testing.T) {
	// Simulate the deny list logic from licenses.go
	denyList := []string{"GPL v3", "LGPL"}

	// Build deny set with normalization
	denySet := make(map[string]bool)
	for _, l := range denyList {
		if normalized, err := spdx.Normalize(l); err == nil {
			denySet[normalized] = true
		}
	}

	tests := []struct {
		license string
		denied  bool
	}{
		{"GPL-3.0-or-later", true}, // matches "GPL v3" normalized
		{"GPL-3.0-only", false},    // "GPL v3" normalizes to -or-later
		{"LGPL-3.0-or-later", true},
		{"MIT", false},
		{"Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			// Check if license is in deny set (with normalization)
			inDenyList := denySet[tt.license]
			if !inDenyList {
				if normalized, err := spdx.Normalize(tt.license); err == nil {
					inDenyList = denySet[normalized]
				}
			}
			if inDenyList != tt.denied {
				t.Errorf("license %q denied = %v, want %v", tt.license, inDenyList, tt.denied)
			}
		})
	}
}
