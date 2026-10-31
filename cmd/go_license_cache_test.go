package cmd_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestLicensesKeepGoModuleCasingInCache(t *testing.T) {
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "go.mod", `module example.com/app

go 1.26.0

require (
	github.com/Azure/GoSDK v1.2.3
	github.com/azure/gosdk v1.2.3
)
`, "Add case-distinct Go dependencies")
	t.Cleanup(chdir(t, dir))
	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatal(err)
	}
	packages := map[string]*enrichment.PackageInfo{
		"pkg:golang/github.com/Azure/GoSDK": {Ecosystem: "golang", Name: "github.com/Azure/GoSDK", License: "MIT"},
		"pkg:golang/github.com/azure/gosdk": {Ecosystem: "golang", Name: "github.com/azure/gosdk", License: "Apache-2.0"},
	}
	mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: packages})
	t.Cleanup(restore)
	for _, offline := range []bool{false, true} {
		args := []string{"licenses", "--format", "json"}
		if offline {
			mock.mu.Lock()
			mock.packages = nil
			mock.mu.Unlock()
			args = append(args, "--offline")
		}
		stdout, stderr, err := runCmd(t, args...)
		if err != nil {
			t.Fatalf("offline=%v: %v\n%s", offline, err, stderr)
		}
		var results []cmd.LicenseInfo
		if err := json.Unmarshal([]byte(stdout), &results); err != nil {
			t.Fatal(err)
		}
		if len(results) != len(packages) {
			t.Fatalf("offline=%v: licenses = %s", offline, stdout)
		}
		for _, result := range results {
			pkg := packages["pkg:golang/"+result.Name]
			if pkg == nil || len(result.Licenses) != 1 || result.Licenses[0] != pkg.License {
				t.Fatalf("offline=%v: unexpected license: %+v", offline, result)
			}
		}
	}
	if mock.bulkLookupCalls != 1 {
		t.Fatalf("metadata requests = %d, want 1", mock.bulkLookupCalls)
	}
}

func TestLicensesRequireRefreshForLegacyGoCache(t *testing.T) {
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "go.mod", "module example.com/app\n\ngo 1.26.0\n\nrequire github.com/BurntSushi/toml v1.6.0\n", "Add Go dependency")
	t.Cleanup(chdir(t, dir))
	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(filepath.Join(dir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const legacyPURL = "pkg:golang/github.com/burntsushi/toml"
	const currentPURL = "pkg:golang/github.com/BurntSushi/toml"
	if err := db.SavePackageEnrichment(legacyPURL, "golang", "github.com/BurntSushi/toml", "v1.6.0", "MIT", "", "ecosystems"); err != nil {
		t.Fatal(err)
	}
	// A later write can replace metadata without updating the stored name.
	if err := db.SavePackageEnrichment(legacyPURL, "golang", "github.com/burntsushi/toml", "v1.6.0", "Apache-2.0", "", "ecosystems"); err != nil {
		t.Fatal(err)
	}
	mock, restore := setMockEnrichmentClient(&mockEnrichmentClient{packages: map[string]*enrichment.PackageInfo{
		currentPURL: {Ecosystem: "golang", Name: "github.com/BurntSushi/toml", License: "MIT"},
	}})
	t.Cleanup(restore)
	_, _, err = runCmd(t, "licenses", "--offline", "--format", "json")
	if err == nil {
		t.Fatal("expected an offline cache miss for the mixed-case module")
	}
	for _, want := range []string{"lowercase Go cache keys", currentPURL, "without --offline"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want %q", err, want)
		}
	}
	if mock.bulkLookupCalls != 0 {
		t.Fatal("offline lookup made a metadata request")
	}
	for _, args := range [][]string{
		{"licenses", "--format", "json"},
		{"licenses", "--offline", "--format", "json"},
	} {
		stdout, stderr, err := runCmd(t, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr)
		}
		var results []cmd.LicenseInfo
		if err := json.Unmarshal([]byte(stdout), &results); err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 || len(results[0].Licenses) != 1 || results[0].Licenses[0] != "MIT" {
			t.Fatalf("%v: license output = %s", args, stdout)
		}
	}
	if mock.bulkLookupCalls != 1 {
		t.Fatalf("metadata requests = %d, want 1", mock.bulkLookupCalls)
	}
	cached, err := db.GetCachedPackagesIncludingStale([]string{legacyPURL, currentPURL})
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 2 || cached[legacyPURL] == nil || cached[legacyPURL].License != "Apache-2.0" || cached[currentPURL] == nil || cached[currentPURL].License != "MIT" {
		t.Fatalf("refresh did not preserve separate cache entries: %+v", cached)
	}
}
