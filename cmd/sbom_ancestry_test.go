package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/sbom"
	gitgo "github.com/go-git/go-git/v5"
)

const (
	plotlyD3PURL = "pkg:npm/%40plotly/d3"
	lodashPURL   = "pkg:npm/lodash"
	leftPadPURL  = "pkg:npm/left-pad"
	// upstreamD3PURL is the npm package published from the parent repository.
	// SBOM ancestry must never select it.
	upstreamD3PURL = "pkg:npm/d3"
)

// ancestryEnrichmentClient mirrors enrichment results for a fork, a non-fork
// and the fork's upstream package, recording every requested PURL. Requests
// for a forbidden PURL fail the test.
type ancestryEnrichmentClient struct {
	t         *testing.T
	forbidden []string
	requested []string
}

func (c *ancestryEnrichmentClient) BulkLookup(_ context.Context, purls []string) (map[string]*enrichment.PackageInfo, error) {
	for _, purlStr := range purls {
		if slices.Contains(c.forbidden, purlStr) {
			c.t.Errorf("unexpected BulkLookup of cached package %s", purlStr)
		}
	}
	c.requested = append(c.requested, purls...)
	packages := map[string]*enrichment.PackageInfo{
		plotlyD3PURL: {
			Ecosystem: "npm", Name: "@plotly/d3", LatestVersion: "3.8.2", License: "BSD-3-Clause",
			Repository: "https://github.com/plotly/d3", Source: "ecosystems",
			RepositoryParent: &enrichment.RepositoryParent{
				FullName: "d3/d3", Evidence: enrichment.AncestryDeclaredFork,
				HostName: "GitHub", HostKind: "github", HostURL: "https://github.com",
			},
		},
		lodashPURL: {
			Ecosystem: "npm", Name: "lodash", LatestVersion: "4.17.21", License: "MIT",
			Repository: "https://github.com/lodash/lodash", Source: "ecosystems",
		},
		upstreamD3PURL: {Ecosystem: "npm", Name: "d3", LatestVersion: "7.9.0", License: "ISC", Source: "ecosystems"},
	}
	result := make(map[string]*enrichment.PackageInfo)
	for _, purlStr := range purls {
		if pkg := packages[purlStr]; pkg != nil {
			result[purlStr] = pkg
		}
	}
	return result, nil
}

func (c *ancestryEnrichmentClient) GetVersions(context.Context, string) ([]enrichment.VersionInfo, error) {
	return nil, nil
}

func (c *ancestryEnrichmentClient) GetVersion(context.Context, string) (*enrichment.VersionInfo, error) {
	return nil, nil
}

// setupAncestrySBOMRepo creates and indexes a repository depending on a fork
// (@plotly/d3), a non-fork (lodash) and a package unknown to enrichment
// (left-pad), then changes into it.
func setupAncestrySBOMRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json",
		`{"name":"example","version":"1.0.0","dependencies":{"@plotly/d3":"3.8.2","lodash":"4.17.21","left-pad":"1.3.0"}}`,
		"add manifest")
	commitSBOMFile(t, repository, repoDir, "package-lock.json", `{
  "name": "example",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "example", "version": "1.0.0", "dependencies": {"@plotly/d3": "3.8.2", "left-pad": "1.3.0", "lodash": "4.17.21"}},
    "node_modules/@plotly/d3": {"version": "3.8.2"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`, "add lockfile")
	t.Chdir(repoDir)
	if _, stderr, err := runAncestrySBOMCommand(t, nil, "init", "--no-hooks"); err != nil {
		t.Fatalf("git pkgs init: %v\n%s", err, stderr)
	}
	return repoDir
}

func runAncestrySBOMCommand(t *testing.T, client enrichment.Client, args ...string) (string, string, error) {
	t.Helper()
	original := NewEnrichmentClient
	NewEnrichmentClient = func(...enrichment.Option) (enrichment.Client, error) {
		if client == nil {
			t.Fatal("unexpected enrichment client")
		}
		return client, nil
	}
	defer func() { NewEnrichmentClient = original }()

	var stdout, stderr bytes.Buffer
	command := NewRootCmd()
	command.SetArgs(args)
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

func runAncestrySBOM(t *testing.T, client enrichment.Client, args ...string) (*sbom.SBOM, string) {
	t.Helper()
	stdout, stderr, err := runAncestrySBOMCommand(t, client, append([]string{"sbom"}, args...)...)
	if err != nil {
		t.Fatalf("git pkgs sbom %v: %v\n%s", args, err, stderr)
	}
	document, err := sbom.Parse([]byte(stdout))
	if err != nil {
		t.Fatalf("parse SBOM: %v\n%s", err, stdout)
	}
	return document, stdout
}

func sbomPackageByName(t *testing.T, document *sbom.SBOM, name string) *sbom.Package {
	t.Helper()
	for i := range document.Packages {
		if document.Packages[i].Name == name {
			return &document.Packages[i]
		}
	}
	t.Fatalf("package %q not found in %+v", name, document.Packages)
	return nil
}

var wantPlotlyD3Ancestors = []sbom.Ancestor{{Type: "LIBRARY", Name: "d3/d3", PURL: "pkg:github/d3/d3"}}

func assertAncestrySBOM(t *testing.T, document *sbom.SBOM, output string) {
	t.Helper()
	if len(document.Packages) != 3 {
		t.Fatalf("packages = %d, want 3 (ancestors must not become components):\n%s", len(document.Packages), output)
	}
	d3 := sbomPackageByName(t, document, "@plotly/d3")
	if !reflect.DeepEqual(d3.Ancestors, wantPlotlyD3Ancestors) {
		t.Errorf("@plotly/d3 ancestors = %+v, want %+v\n%s", d3.Ancestors, wantPlotlyD3Ancestors, output)
	}
	if d3.LicenseDeclared != "BSD-3-Clause" {
		t.Errorf("@plotly/d3 license = %q, want BSD-3-Clause", d3.LicenseDeclared)
	}
	for _, name := range []string{"lodash", "left-pad"} {
		if ancestors := sbomPackageByName(t, document, name).Ancestors; ancestors != nil {
			t.Errorf("%s ancestors = %+v, want none", name, ancestors)
		}
	}
	for _, relationship := range document.Relationships {
		if strings.Contains(relationship.SourceID+relationship.TargetID, "pkg:github") {
			t.Errorf("ancestor appears in relationship %+v", relationship)
		}
	}
	if strings.Contains(output, upstreamD3PURL+"@") || strings.Contains(output, `"`+upstreamD3PURL+`"`) ||
		strings.Contains(output, ">"+upstreamD3PURL+"<") {
		t.Errorf("upstream package %s was selected as an ancestor:\n%s", upstreamD3PURL, output)
	}
}

func TestSBOMIncludesRepositoryAncestors(t *testing.T) {
	for _, format := range []string{"json", "xml"} {
		t.Run(format, func(t *testing.T) {
			setupAncestrySBOMRepo(t)
			client := &ancestryEnrichmentClient{t: t}
			document, output := runAncestrySBOM(t, client, "--format", format)
			assertAncestrySBOM(t, document, output)

			requested := slices.Clone(client.requested)
			slices.Sort(requested)
			if want := []string{plotlyD3PURL, leftPadPURL, lodashPURL}; !slices.Equal(requested, want) {
				t.Errorf("BulkLookup requested %v, want only the components %v", requested, want)
			}
			if format == "xml" && !strings.Contains(output, "<pedigree>") {
				t.Errorf("XML output missing pedigree:\n%s", output)
			}
		})
	}
}

func TestSBOMRepositoryAncestorsFromCache(t *testing.T) {
	setupAncestrySBOMRepo(t)
	runAncestrySBOM(t, &ancestryEnrichmentClient{t: t})

	for _, format := range []string{"json", "xml"} {
		t.Run(format, func(t *testing.T) {
			// left-pad is unknown to enrichment, so it is never cached.
			cachedClient := &ancestryEnrichmentClient{t: t, forbidden: []string{plotlyD3PURL, lodashPURL}}
			document, output := runAncestrySBOM(t, cachedClient, "--format", format)
			assertAncestrySBOM(t, document, output)
		})
	}
}

func TestSBOMFetchesAncestryMissingFromPackageCache(t *testing.T) {
	repoDir := setupAncestrySBOMRepo(t)
	// Package rows cached by another command, such as licenses, carry no
	// repository parent lookup.
	db, err := database.Open(filepath.Join(repoDir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	for _, pkg := range []struct{ purl, name, license string }{
		{plotlyD3PURL, "@plotly/d3", "BSD-3-Clause"},
		{lodashPURL, "lodash", "MIT"},
		{leftPadPURL, "left-pad", ""},
	} {
		if err := db.SavePackageEnrichment(pkg.purl, "npm", pkg.name, "", pkg.license, "", "ecosystems"); err != nil {
			t.Fatalf("SavePackageEnrichment: %v", err)
		}
	}
	_ = db.Close()

	client := &ancestryEnrichmentClient{t: t}
	document, output := runAncestrySBOM(t, client)
	assertAncestrySBOM(t, document, output)
	if !slices.Contains(client.requested, plotlyD3PURL) {
		t.Errorf("BulkLookup requested %v, want %s refetched for ancestry", client.requested, plotlyD3PURL)
	}
}

func TestSBOMSkipEnrichmentOmitsAncestors(t *testing.T) {
	setupAncestrySBOMRepo(t)
	for _, format := range []string{"json", "xml"} {
		t.Run(format, func(t *testing.T) {
			document, output := runAncestrySBOM(t, nil, "--skip-enrichment", "--format", format)
			if strings.Contains(output, "pedigree") {
				t.Errorf("unexpected pedigree with --skip-enrichment:\n%s", output)
			}
			if d3 := sbomPackageByName(t, document, "@plotly/d3"); d3.Ancestors != nil {
				t.Errorf("@plotly/d3 ancestors = %+v, want none", d3.Ancestors)
			}
		})
	}
}

func TestSBOMSPDXOmitsAncestors(t *testing.T) {
	setupAncestrySBOMRepo(t)
	_, output := runAncestrySBOM(t, &ancestryEnrichmentClient{t: t}, "--type", "spdx")
	if strings.Contains(output, "pkg:github/d3/d3") || strings.Contains(output, "d3/d3") {
		t.Errorf("SPDX output includes the repository ancestor:\n%s", output)
	}
}

func TestRepositoryAncestor(t *testing.T) {
	github := func(fullName string) *database.RepositoryParent {
		return &database.RepositoryParent{
			FullName: fullName, Evidence: enrichment.AncestryDeclaredFork,
			HostName: "GitHub", HostKind: "github", HostURL: "https://github.com",
		}
	}
	tests := []struct {
		name   string
		parent *database.RepositoryParent
		want   *sbom.Ancestor
	}{
		{name: "github", parent: github("d3/d3"), want: &sbom.Ancestor{Name: "d3/d3", PURL: "pkg:github/d3/d3"}},
		{
			name:   "github host URL with trailing slash",
			parent: &database.RepositoryParent{FullName: "d3/d3", Evidence: enrichment.AncestryDeclaredFork, HostKind: "github", HostURL: "https://github.com/"},
			want:   &sbom.Ancestor{Name: "d3/d3", PURL: "pkg:github/d3/d3"},
		},
		{name: "github name case normalized in PURL", parent: github("D3/D3"), want: &sbom.Ancestor{Name: "D3/D3", PURL: "pkg:github/d3/d3"}},
		{
			name:   "bitbucket",
			parent: &database.RepositoryParent{FullName: "pygame/pygame", Evidence: enrichment.AncestryDeclaredFork, HostKind: "bitbucket", HostURL: "https://bitbucket.org"},
			want:   &sbom.Ancestor{Name: "pygame/pygame", PURL: "pkg:bitbucket/pygame/pygame"},
		},
		{name: "nil parent", parent: nil},
		{
			name:   "GitHub Enterprise host",
			parent: &database.RepositoryParent{FullName: "d3/d3", Evidence: enrichment.AncestryDeclaredFork, HostKind: "github", HostURL: "https://github.example.com"},
		},
		{
			name:   "GitLab host without a PURL type",
			parent: &database.RepositoryParent{FullName: "group/project", Evidence: enrichment.AncestryDeclaredFork, HostKind: "gitlab", HostURL: "https://gitlab.com"},
		},
		{name: "missing host", parent: &database.RepositoryParent{FullName: "d3/d3", Evidence: enrichment.AncestryDeclaredFork}},
		{name: "nested repository name", parent: github("group/sub/project")},
		{name: "missing owner", parent: github("/d3")},
		{name: "missing name", parent: github("d3")},
		{name: "unknown evidence", parent: &database.RepositoryParent{FullName: "d3/d3", Evidence: "repository_url_match", HostKind: "github", HostURL: "https://github.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := repositoryAncestor(tt.parent)
			if tt.want == nil {
				if ok {
					t.Errorf("repositoryAncestor() = %+v, want no ancestor", got)
				}
				return
			}
			if !ok || got != *tt.want {
				t.Errorf("repositoryAncestor() = %+v, %v, want %+v", got, ok, *tt.want)
			}
		})
	}
}
