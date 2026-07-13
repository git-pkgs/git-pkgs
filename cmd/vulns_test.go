package cmd

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/sarif"
	"github.com/git-pkgs/vulns"
	"github.com/spf13/cobra"
)

// mockSource implements vulns.Source for testing.
type mockSource struct {
	vulns    map[string]*vulns.Vulnerability // ID -> full vuln
	batchRes [][]vulns.Vulnerability         // QueryBatch results
	getCalls atomic.Int64
}

func (m *mockSource) Name() string { return "mock" }

func (m *mockSource) Query(_ context.Context, _ *purl.PURL) ([]vulns.Vulnerability, error) {
	return nil, nil
}

func (m *mockSource) QueryBatch(_ context.Context, _ []*purl.PURL) ([][]vulns.Vulnerability, error) {
	return m.batchRes, nil
}

func (m *mockSource) Get(_ context.Context, id string) (*vulns.Vulnerability, error) {
	m.getCalls.Add(1)
	if v, ok := m.vulns[id]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("not found: %s", id)
}

func newTestDB(t *testing.T) *database.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pkgs.sqlite3")
	db, err := database.Create(dbPath)
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestSyncVulnerabilitiesForDeps(t *testing.T) {
	now := time.Now()

	vuln1 := &vulns.Vulnerability{
		ID:        "GHSA-0001",
		Summary:   "Test vuln 1",
		Published: now,
		Modified:  now,
		Affected: []vulns.Affected{{
			Package: vulns.Package{Ecosystem: "npm", Name: "foo"},
			Ranges: []vulns.Range{{
				Type:   "ECOSYSTEM",
				Events: []vulns.Event{{Introduced: "0"}, {Fixed: "1.2.0"}},
			}},
		}},
	}
	vuln2 := &vulns.Vulnerability{
		ID:        "GHSA-0002",
		Summary:   "Test vuln 2",
		Published: now,
		Modified:  now,
		Affected: []vulns.Affected{{
			Package: vulns.Package{Ecosystem: "npm", Name: "bar"},
			Ranges: []vulns.Range{{
				Type:   "ECOSYSTEM",
				Events: []vulns.Event{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}},
			}},
		}},
	}

	// vuln3 affects both foo and bar (shared vuln)
	vuln3 := &vulns.Vulnerability{
		ID:        "GHSA-0003",
		Summary:   "Shared vuln",
		Published: now,
		Modified:  now,
		Affected: []vulns.Affected{
			{
				Package: vulns.Package{Ecosystem: "npm", Name: "foo"},
				Ranges: []vulns.Range{{
					Type:   "ECOSYSTEM",
					Events: []vulns.Event{{Introduced: "0"}, {Fixed: "3.0.0"}},
				}},
			},
			{
				Package: vulns.Package{Ecosystem: "npm", Name: "bar"},
				Ranges: []vulns.Range{{
					Type:   "ECOSYSTEM",
					Events: []vulns.Event{{Introduced: "0"}, {Fixed: "3.0.0"}},
				}},
			},
		},
	}

	source := &mockSource{
		vulns: map[string]*vulns.Vulnerability{
			"GHSA-0001": vuln1,
			"GHSA-0002": vuln2,
			"GHSA-0003": vuln3,
		},
		// batch results: foo has vuln1+vuln3, bar has vuln2+vuln3
		batchRes: [][]vulns.Vulnerability{
			{{ID: "GHSA-0001"}, {ID: "GHSA-0003"}},
			{{ID: "GHSA-0002"}, {ID: "GHSA-0003"}},
		},
	}

	deps := []database.Dependency{
		{Ecosystem: "npm", Name: "foo", Requirement: "1.0.0", ManifestPath: "package-lock.json", ManifestKind: "lockfile"},
		{Ecosystem: "npm", Name: "bar", Requirement: "1.5.0", ManifestPath: "package-lock.json", ManifestKind: "lockfile"},
	}

	db := newTestDB(t)
	var buf bytes.Buffer

	err := syncVulnerabilitiesForDeps(db, source, deps, true, false, &buf)
	if err != nil {
		t.Fatalf("syncVulnerabilitiesForDeps() error = %v", err)
	}

	// Shared vuln GHSA-0003 should only be fetched once (3 unique IDs = 3 Get calls)
	if got := source.getCalls.Load(); got != 3 {
		t.Errorf("expected 3 Get calls (one per unique vuln), got %d", got)
	}

	// Verify vulns were stored for foo
	fooVulns, err := db.GetVulnerabilitiesForPackage("npm", "foo")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForPackage(foo) error = %v", err)
	}
	if len(fooVulns) != 2 {
		t.Errorf("expected 2 vulns for foo, got %d", len(fooVulns))
	}

	// Verify vulns were stored for bar
	barVulns, err := db.GetVulnerabilitiesForPackage("npm", "bar")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForPackage(bar) error = %v", err)
	}
	if len(barVulns) != 2 {
		t.Errorf("expected 2 vulns for bar, got %d", len(barVulns))
	}

	// Verify output mentions both packages
	output := buf.String()
	if !strings.Contains(output, "Syncing vulnerabilities for 2 packages") {
		t.Errorf("expected sync message in output, got: %s", output)
	}
	if !strings.Contains(output, "Synced 3 vulnerabilities for 2 packages") {
		t.Errorf("expected summary message in output, got: %s", output)
	}
}

func TestSyncVulnerabilitiesForDeps_NoDeps(t *testing.T) {
	db := newTestDB(t)
	var buf bytes.Buffer

	source := &mockSource{}
	err := syncVulnerabilitiesForDeps(db, source, nil, true, false, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No lockfile dependencies to sync.") {
		t.Errorf("expected no-deps message, got: %s", buf.String())
	}
}

func TestSyncVulnerabilitiesForDeps_QuietMode(t *testing.T) {
	now := time.Now()
	source := &mockSource{
		vulns: map[string]*vulns.Vulnerability{
			"GHSA-0001": {ID: "GHSA-0001", Summary: "Test", Published: now, Modified: now},
		},
		batchRes: [][]vulns.Vulnerability{{{ID: "GHSA-0001"}}},
	}

	deps := []database.Dependency{
		{Ecosystem: "npm", Name: "foo", Requirement: "1.0.0", ManifestPath: "package-lock.json", ManifestKind: "lockfile"},
	}

	db := newTestDB(t)
	var buf bytes.Buffer

	err := syncVulnerabilitiesForDeps(db, source, deps, true, true, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output in quiet mode, got: %s", buf.String())
	}
}

func TestBuildVersRange(t *testing.T) {
	tests := []struct {
		name      string
		ranges    []vulns.Range
		ecosystem string
		want      string
	}{
		{
			name: "single introduced/fixed pair",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.5.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/>=1.0.0|<1.5.0",
		},
		{
			name: "multiple introduced/fixed pairs in one range",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.5.0"},
						{Introduced: "2.0.0"},
						{Fixed: "2.5.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/>=1.0.0|<1.5.0|>=2.0.0|<2.5.0",
		},
		{
			name: "introduced from zero with fix",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "0"},
						{Fixed: "1.2.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/<1.2.0",
		},
		{
			name: "introduced from zero then reintroduced",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "0"},
						{Fixed: "1.2.0"},
						{Introduced: "2.0.0"},
						{Fixed: "2.3.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/<1.2.0|>=2.0.0|<2.3.0",
		},
		{
			name: "lastAffected instead of fixed",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "1.0.0"},
						{LastAffected: "1.9.9"},
					},
				},
			},
			ecosystem: "PyPI",
			want:      "vers:PyPI/>=1.0.0|<=1.9.9",
		},
		{
			name: "no upper bound",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "3.0.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/>=3.0.0",
		},
		{
			name: "all versions affected (introduced 0 with no fix)",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/*",
		},
		{
			name: "multiple ranges",
			ranges: []vulns.Range{
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.1.0"},
					},
				},
				{
					Type: "ECOSYSTEM",
					Events: []vulns.Event{
						{Introduced: "2.0.0"},
						{Fixed: "2.1.0"},
					},
				},
			},
			ecosystem: "npm",
			want:      "vers:npm/>=1.0.0|<1.1.0|>=2.0.0|<2.1.0",
		},
		{
			name:      "empty ranges",
			ranges:    []vulns.Range{},
			ecosystem: "npm",
			want:      "",
		},
		{
			name: "skip GIT range type",
			ranges: []vulns.Range{
				{
					Type: "GIT",
					Events: []vulns.Event{
						{Introduced: "abc123"},
						{Fixed: "def456"},
					},
				},
			},
			ecosystem: "npm",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &vulns.Vulnerability{
				Affected: []vulns.Affected{{
					Package: vulns.Package{
						Ecosystem: tt.ecosystem,
						Name:      "test-pkg",
					},
					Ranges: tt.ranges,
				}},
			}
			got := buildVersRange(v, tt.ecosystem, "test-pkg")
			if got != tt.want {
				t.Errorf("buildVersRange() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOutputVulnsSARIF(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	results := []VulnResult{
		{
			ID:           "GHSA-0001",
			Summary:      "Example vulnerability",
			Severity:     "high",
			Package:      "lodash",
			Version:      "4.17.20",
			ManifestPath: "package-lock.json",
		},
		{
			ID:           "GHSA-0002",
			Summary:      "Another vulnerability",
			Severity:     "medium",
			Package:      "express",
			Version:      "4.18.1",
			ManifestPath: "package-lock.json",
		},
	}

	if err := outputVulnsSARIF(cmd, results); err != nil {
		t.Fatalf("outputVulnsSARIF() error = %v", err)
	}

	log, err := sarif.Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("sarif.Parse() error = %v\n%s", err, buf.String())
	}
	if err := sarif.Validate(log); err != nil {
		t.Fatalf("sarif.Validate() error = %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" {
		t.Fatalf("Version = %q, want 2.1.0", log.Version)
	}
	if got := log.Runs[0].Tool.Driver.Name; got != "git-pkgs" {
		t.Fatalf("Tool.Driver.Name = %q, want git-pkgs", got)
	}
	if got := log.Runs[0].Tool.Driver.Rules[0].ID; got != "GHSA-0001" {
		t.Fatalf("rule ID = %q, want GHSA-0001", got)
	}
	if got := log.Runs[0].Tool.Driver.Rules[1].ID; got != "GHSA-0002" {
		t.Fatalf("second rule ID = %q, want GHSA-0002", got)
	}
	if got := log.Runs[0].Results[0].Level; got != "error" {
		t.Fatalf("result level = %q, want error", got)
	}
	if got := log.Runs[0].Results[1].Level; got != "warning" {
		t.Fatalf("second result level = %q, want warning", got)
	}
	if got := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "package-lock.json" {
		t.Fatalf("location URI = %q, want package-lock.json", got)
	}
	for i, result := range log.Runs[0].Results {
		if result.RuleIndex != -1 || result.Rank != -1 {
			t.Fatalf("result %d lost constructor defaults: ruleIndex=%d rank=%v", i, result.RuleIndex, result.Rank)
		}
		location := result.Locations[0]
		if location.ID != -1 || location.PhysicalLocation.ArtifactLocation.Index != -1 {
			t.Fatalf(
				"result %d location lost constructor defaults: id=%d artifactIndex=%d",
				i,
				location.ID,
				location.PhysicalLocation.ArtifactLocation.Index,
			)
		}
	}
}

func TestExposureSortDeterministic(t *testing.T) {
	entries := []VulnExposureEntry{
		{VulnID: "GHSA-0003", ExposureDays: 10},
		{VulnID: "GHSA-0001", ExposureDays: 10},
		{VulnID: "GHSA-0002", ExposureDays: 10},
		{VulnID: "GHSA-0004", ExposureDays: 30},
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ExposureDays != entries[j].ExposureDays {
			return entries[i].ExposureDays > entries[j].ExposureDays
		}
		return entries[i].VulnID < entries[j].VulnID
	})

	want := []string{"GHSA-0004", "GHSA-0001", "GHSA-0002", "GHSA-0003"}
	for i, id := range want {
		if entries[i].VulnID != id {
			t.Errorf("entries[%d].VulnID = %q, want %q", i, entries[i].VulnID, id)
		}
	}
}

func TestPraiseSortDeterministic(t *testing.T) {
	authors := []PraiseAuthorSummary{
		{Author: "charlie", TotalFixes: 5},
		{Author: "alice", TotalFixes: 5},
		{Author: "bob", TotalFixes: 10},
	}

	sort.Slice(authors, func(i, j int) bool {
		if authors[i].TotalFixes != authors[j].TotalFixes {
			return authors[i].TotalFixes > authors[j].TotalFixes
		}
		return authors[i].Author < authors[j].Author
	})

	want := []string{"bob", "alice", "charlie"}
	for i, name := range want {
		if authors[i].Author != name {
			t.Errorf("authors[%d].Author = %q, want %q", i, authors[i].Author, name)
		}
	}
}
