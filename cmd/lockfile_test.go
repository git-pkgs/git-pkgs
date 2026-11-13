package cmd_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
)

const lockfilePoetryLock = `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false
python-versions = ">=3.7"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "0000000000000000000000000000000000000000000000000000000000000000"
`

// writeUntrackedLockfile changes into a fresh directory that is not a git
// repository and writes name there.
func writeUntrackedLockfile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(chdir(t, dir))
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func assertNoIndex(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
		t.Fatalf("--lockfile touched a repository or index in %s: %v", dir, err)
	}
}

func TestVulnsScanLockfileOutsideRepository(t *testing.T) {
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			dir := writeUntrackedLockfile(t, "package-lock.json", outdatedLockfile("4.17.20"))
			transport := &vulnsScanTransport{severities: []string{"high"}}
			original := http.DefaultTransport
			http.DefaultTransport = transport
			t.Cleanup(func() { http.DefaultTransport = original })

			stdout, stderr, err := runCmd(t, "vulns", "scan", "--lockfile", "package-lock.json", "--format", format, "--fail-on", "high")
			assertVulnsPolicyError(t, err, true)
			assertVulnsScanReport(t, stdout, format, []string{"high"})
			if !strings.Contains(stderr, "vulnerability policy failed") {
				t.Fatalf("missing policy diagnostic on stderr: %q", stderr)
			}
			assertNoIndex(t, dir)
		})
	}
}

// osvQueryRecorder answers OSV batch queries with no findings and records the
// request bodies.
type osvQueryRecorder struct {
	bodies []string
}

func (r *osvQueryRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r.bodies = append(r.bodies, string(body))
	var query struct{ Queries []json.RawMessage }
	if err := json.Unmarshal(body, &query); err != nil {
		return nil, err
	}
	results := make([]map[string]any, len(query.Queries))
	for i := range results {
		results[i] = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{"results": results})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(string(payload))), Request: req,
	}, nil
}

func TestVulnsScanUntrackedPoetryLockInRepository(t *testing.T) {
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "pyproject.toml", "[tool.poetry]\nname = \"demo\"\n", "Add project")
	t.Cleanup(chdir(t, dir))
	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(lockfilePoetryLock), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCmd(t, "vulns", "scan", "--no-sync")
	if err != nil || !strings.Contains(stdout, "No lockfile dependencies found to scan.") {
		t.Fatalf("scan without --lockfile = %q, %v; want no tracked lockfile dependencies", stdout, err)
	}

	recorder := &osvQueryRecorder{}
	original := http.DefaultTransport
	http.DefaultTransport = recorder
	t.Cleanup(func() { http.DefaultTransport = original })

	stdout, _, err = runCmd(t, "vulns", "scan", "--lockfile", "poetry.lock")
	if err != nil {
		t.Fatalf("vulns scan --lockfile: %v", err)
	}
	if !strings.Contains(stdout, "No vulnerabilities found.") {
		t.Fatalf("stdout = %q, want a completed scan", stdout)
	}
	if len(recorder.bodies) != 1 || !strings.Contains(recorder.bodies[0], "requests") ||
		!strings.Contains(recorder.bodies[0], "2.31.0") {
		t.Fatalf("OSV queries = %v, want requests 2.31.0", recorder.bodies)
	}
}

func TestLockfileFlagRejectsUnusableFiles(t *testing.T) {
	writeUntrackedLockfile(t, "package-lock.json", outdatedLockfile("4.17.20"))
	for _, name := range []string{"package.json", "go.sum", "requirements.txt", "deps.lock"} {
		if err := os.WriteFile(name, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--lockfile", "package.json"}, "does not list resolved versions"},
		{[]string{"--lockfile", "requirements.txt"}, "does not list resolved versions"},
		{[]string{"--lockfile", "go.sum"}, "does not list resolved versions"},
		{[]string{"--lockfile", "deps.lock"}, "unrecognized lockfile"},
		{[]string{"--lockfile", "missing/poetry.lock"}, "reading lockfile"},
		{[]string{"--lockfile", "package-lock.json", "--commit", "HEAD"}, "lockfile"},
		{[]string{"--lockfile", "package-lock.json", "--branch", "main"}, "lockfile"},
	} {
		for _, command := range [][]string{{"vulns", "scan"}, {"outdated"}, {"freshness"}, {"funding"}} {
			_, _, err := runCmd(t, append(command, tt.args...)...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%v %v: error = %v, want %q", command, tt.args, err, tt.want)
			}
		}
	}
}

// lockfileEnrichmentClient reports lodash 4.17.21 as the latest release with a
// funding link.
type lockfileEnrichmentClient struct {
	bulkLookups []string
}

func (c *lockfileEnrichmentClient) BulkLookup(_ context.Context, purls []string) (map[string]*enrichment.PackageInfo, error) {
	c.bulkLookups = append(c.bulkLookups, purls...)
	result := make(map[string]*enrichment.PackageInfo)
	for _, purlStr := range purls {
		if purlStr == "pkg:npm/lodash" {
			result[purlStr] = &enrichment.PackageInfo{
				Ecosystem: "npm", Name: "lodash", LatestVersion: "4.17.21", License: "MIT",
				FundingLinks: []string{"https://github.com/sponsors/jdalton"}, Source: "ecosystems",
			}
		}
	}
	return result, nil
}

func (c *lockfileEnrichmentClient) GetVersions(_ context.Context, purlStr string) ([]enrichment.VersionInfo, error) {
	if purlStr != "pkg:npm/lodash" {
		return nil, nil
	}
	return []enrichment.VersionInfo{
		{Number: "4.17.20", PublishedAt: time.Date(2020, time.August, 13, 0, 0, 0, 0, time.UTC)},
		{Number: "4.17.21", PublishedAt: time.Date(2021, time.February, 20, 0, 0, 0, 0, time.UTC)},
	}, nil
}

func (c *lockfileEnrichmentClient) GetVersion(context.Context, string) (*enrichment.VersionInfo, error) {
	return nil, nil
}

func setLockfileEnrichment(t *testing.T) *lockfileEnrichmentClient {
	t.Helper()
	client := &lockfileEnrichmentClient{}
	original := cmd.NewEnrichmentClient
	cmd.NewEnrichmentClient = func(...enrichment.Option) (enrichment.Client, error) {
		return client, nil
	}
	t.Cleanup(func() { cmd.NewEnrichmentClient = original })
	return client
}

func TestOutdatedLockfileOutsideRepository(t *testing.T) {
	dir := writeUntrackedLockfile(t, "package-lock.json", outdatedLockfile("4.17.20"))
	setLockfileEnrichment(t)

	stdout, _, err := runCmd(t, "outdated", "--lockfile", "package-lock.json", "--format", "json")
	if err != nil {
		t.Fatalf("outdated --lockfile: %v", err)
	}
	var packages []cmd.OutdatedPackage
	if err := json.Unmarshal([]byte(stdout), &packages); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(packages) != 1 || packages[0].Name != "lodash" || packages[0].CurrentVersion != "4.17.20" ||
		packages[0].LatestVersion != "4.17.21" || packages[0].UpdateType != "patch" ||
		packages[0].ManifestPath != "package-lock.json" {
		t.Fatalf("outdated = %+v", packages)
	}
	assertNoIndex(t, dir)
}

func TestFreshnessLockfileOutsideRepository(t *testing.T) {
	dir := writeUntrackedLockfile(t, "package-lock.json", outdatedLockfile("4.17.20"))
	setLockfileEnrichment(t)

	stdout, _, err := runCmd(t, "freshness", "--lockfile", "package-lock.json", "--format", "json")
	if err != nil {
		t.Fatalf("freshness --lockfile: %v", err)
	}
	var result cmd.FreshnessResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if result.Summary.MeasuredDependencies != 1 || len(result.Dependencies) != 1 ||
		result.Dependencies[0].DaysBehindLatest != 191 {
		t.Fatalf("freshness = %+v", result)
	}
	assertNoIndex(t, dir)
}

func TestFundingLockfileOutsideRepository(t *testing.T) {
	dir := writeUntrackedLockfile(t, "package-lock.json", outdatedLockfile("4.17.20"))
	client := setLockfileEnrichment(t)

	stdout, _, err := runCmd(t, "funding", "--lockfile", "package-lock.json", "--format", "json")
	if err != nil {
		t.Fatalf("funding --lockfile: %v", err)
	}
	var result cmd.FundingResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if result.Summary.WithFunding != 1 || len(result.Dependencies) != 1 ||
		result.Dependencies[0].FundingLinks[0] != "https://github.com/sponsors/jdalton" {
		t.Fatalf("funding = %+v", result)
	}
	if len(client.bulkLookups) != 1 || client.bulkLookups[0] != "pkg:npm/lodash" {
		t.Fatalf("BulkLookup requested %v, want pkg:npm/lodash", client.bulkLookups)
	}
	assertNoIndex(t, dir)
}
