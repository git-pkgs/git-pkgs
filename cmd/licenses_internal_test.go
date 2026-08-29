package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/git-pkgs/archives"
	"github.com/git-pkgs/artifacts"
	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	licensespkg "github.com/git-pkgs/licenses"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
)

func TestDirectLicenseTargetsResolveManifestDeclarations(t *testing.T) {
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
			targets, _ := directLicenseTargets(tt.deps)
			if len(targets) != 1 {
				t.Fatalf("targets = %#v, want one", targets)
			}
			if targets[0].versionedPURL != tt.wantPURL {
				t.Fatalf("resolved version = %q, want %q", targets[0].versionedPURL, tt.wantPURL)
			}
			if targets[0].ambiguous != tt.wantAmbiguous {
				t.Fatalf("ambiguous = %v, want %v", targets[0].ambiguous, tt.wantAmbiguous)
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

func TestBuildLicenseInfosWithoutScansPreservesPackageMetadata(t *testing.T) {
	const packagePURL = "pkg:npm/example"
	result := buildLicenseInfos(
		map[string]*licenseData{
			packagePURL: {
				License:   "MIT",
				Name:      "example",
				Ecosystem: "npm",
			},
		},
		[]licenseTarget{
			{
				lookupPURL: packagePURL,
				dependency: database.Dependency{
					Name:         "example",
					Ecosystem:    "npm",
					Requirement:  "1.0.0",
					ManifestPath: "package.json",
				},
			},
		},
		nil,
		nil,
		newLicensePolicy(licenseOptions{denyList: []string{"MIT"}}),
	)
	if len(result.infos) != 1 {
		t.Fatalf("license infos = %#v, want one", result.infos)
	}
	info := result.infos[0]
	if info.Name != "example" || info.Ecosystem != "npm" || info.Version != "1.0.0" ||
		info.ManifestPath != "package.json" || info.PURL != packagePURL {
		t.Errorf("package metadata = %#v", info)
	}
	if !slices.Equal(info.Licenses, []string{"MIT"}) || info.LicenseSource != licenseSourcePackage {
		t.Errorf("license metadata = %#v", info)
	}
	if info.LicenseText != "" || info.NoticeText != "" || info.Declared != nil {
		t.Errorf("attribution metadata = %#v, want empty", info)
	}
	if !info.Flagged || info.FlagReason != `license "MIT" is denied` || !result.hasViolations {
		t.Errorf("policy result = %#v", result)
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

func TestLicenseTextOptions(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		wantError string
		wantScope string
	}{
		{
			name:      "requires JSON",
			args:      []string{"--license-text"},
			wantError: "--license-text requires --format json",
		},
		{
			name:      "rejects drift",
			args:      []string{"--license-text", "--format", "json", "--drift"},
			wantError: "--drift cannot be combined with --license-text",
		},
		{
			name:      "rejects dependency selection with drift",
			args:      []string{"--drift", "--dependencies", "all"},
			wantError: "--drift cannot be combined with --dependencies",
		},
		{
			name:      "rejects unknown dependency selection",
			args:      []string{"--dependencies", "runtime"},
			wantError: `unsupported dependency selection "runtime"`,
		},
		{
			name:      "accepts historical dependencies",
			args:      []string{"--license-text", "--format", "json", "--commit", "HEAD~1", "--branch", "main"},
			wantScope: licenseDependenciesDirect,
		},
		{
			name:      "accepts indirect dependencies",
			args:      []string{"--license-text", "--format", "json", "--dependencies", "indirect"},
			wantScope: licenseDependenciesIndirect,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := &cobra.Command{Use: "root"}
			addLicensesCmd(parent)
			command, _, err := parent.Find([]string{"licenses"})
			if err != nil {
				t.Fatal(err)
			}
			if err := command.ParseFlags(test.args); err != nil {
				t.Fatal(err)
			}
			options, err := licenseOptionsFromCommand(command)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("licenseOptionsFromCommand: %v", err)
				}
				if !options.includeText {
					t.Fatal("includeText = false, want true")
				}
				if options.dependencies != test.wantScope {
					t.Fatalf("dependencies = %q, want %q", options.dependencies, test.wantScope)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestSelectLicenseTargets(t *testing.T) {
	dependencies := []database.Dependency{
		{
			Name: "example", Ecosystem: "npm", PURL: "pkg:npm/example", Requirement: "^1.0.0",
			ManifestPath: "package.json", ManifestKind: manifestKindManifest,
		},
		{
			Name: "example", Ecosystem: "npm", PURL: "pkg:npm/example@1.0.0", Requirement: "1.0.0",
			ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile, Direct: true,
		},
		{
			Name: "example", Ecosystem: "npm", PURL: "pkg:npm/example@0.9.0", Requirement: "0.9.0",
			ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile,
		},
		{
			Name: "transitive", Ecosystem: "npm", PURL: "pkg:npm/transitive@2.0.0", Requirement: "2.0.0",
			ManifestPath: "package-lock.json", ManifestKind: manifestKindLockfile,
		},
		{
			Name: "go-direct", Ecosystem: "golang", PURL: "pkg:golang/example.com/direct@1.0.0", Requirement: "1.0.0",
			ManifestPath: "go.mod", ManifestKind: manifestKindManifest, Direct: true,
		},
		{
			Name: "go-indirect", Ecosystem: "golang", PURL: "pkg:golang/example.com/indirect@2.0.0", Requirement: "2.0.0",
			ManifestPath: "go.mod", ManifestKind: manifestKindManifest,
		},
	}

	for _, test := range []struct {
		selection string
		want      []string
	}{
		{licenseDependenciesDirect, []string{
			"pkg:npm/example@1.0.0",
			"pkg:golang/example.com/direct@1.0.0",
		}},
		{licenseDependenciesIndirect, []string{
			"pkg:npm/example@0.9.0",
			"pkg:golang/example.com/indirect@2.0.0",
			"pkg:npm/transitive@2.0.0",
		}},
		{licenseDependenciesAll, []string{
			"pkg:npm/example@0.9.0",
			"pkg:npm/example@1.0.0",
			"pkg:golang/example.com/direct@1.0.0",
			"pkg:golang/example.com/indirect@2.0.0",
			"pkg:npm/transitive@2.0.0",
		}},
	} {
		t.Run(test.selection, func(t *testing.T) {
			targets := selectLicenseTargets(dependencies, test.selection)
			got := make([]string, 0, len(targets))
			for _, target := range targets {
				got = append(got, target.versionedPURL)
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("targets = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateLicenseTextTargetsRejectsUnresolvedDependency(t *testing.T) {
	err := validateLicenseTextTargets([]licenseTarget{{
		dependency: database.Dependency{Name: "example", ManifestPath: "package.json"},
	}})
	if err == nil || !strings.Contains(err.Error(), "resolved version for example from package.json") {
		t.Fatalf("validateLicenseTextTargets() error = %v", err)
	}
	if err := validateLicenseTextTargets([]licenseTarget{{versionedPURL: "pkg:npm/example@1.0.0"}}); err != nil {
		t.Fatalf("validateLicenseTextTargets() error = %v", err)
	}
}

func TestScanDependencyArtifacts(t *testing.T) {
	const versionedPURL = "pkg:npm/example@1.0.0"
	licenseText := "SPDX-License-Identifier: MIT\n"
	content := licenseTestZIP(t, map[string]string{
		"package/LICENSE":       licenseText,
		"package/NOTICE.custom": "Package attribution notice\n",
		"package/package.json":  `{"name":"example","license":"Apache-2.0"}`,
	})
	loader := &fakeLicenseArtifactLoader{filename: "artifact", content: content}
	dependencies := []database.Dependency{
		{Name: "example", Ecosystem: "npm", PURL: versionedPURL, Requirement: "1.0.0", ManifestKind: manifestKindLockfile},
		{Name: "example", Ecosystem: "npm", PURL: versionedPURL, Requirement: "1.0.0", ManifestKind: manifestKindLockfile},
	}

	results, err := scanDependencyArtifacts(context.Background(), dependencies, loader, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(loader.calls) != 1 || loader.calls[0].PURL != versionedPURL {
		t.Fatalf("artifact loads = %#v, want one load for %s", loader.calls, versionedPURL)
	}
	scan := results[versionedPURL]
	if !slices.Equal(scan.licenses, []string{"MIT"}) {
		t.Errorf("licenses = %v, want [MIT]", scan.licenses)
	}
	if scan.licenseText != licenseText || scan.noticeText != "Package attribution notice\n" {
		t.Errorf("attribution text = %#v", scan)
	}
	if len(scan.declared) != 1 || scan.declared[0].NormalizedExpression != "Apache-2.0" {
		t.Errorf("declared = %#v, want Apache-2.0", scan.declared)
	}
}

func TestUniqueLicenseArtifactRequestsKeepDistinctFiles(t *testing.T) {
	const versionedPURL = "pkg:pypi/example@1.0.0"
	dependencies := []database.Dependency{
		{Name: "example", PURL: versionedPURL, Requirement: "1.0.0", Integrity: "sha256-" + strings.Repeat("a", 64)},
		{Name: "example", PURL: versionedPURL, Requirement: "1.0.0", Integrity: "sha256-" + strings.Repeat("b", 64)},
		{Name: "example", PURL: versionedPURL, Requirement: "1.0.0", Integrity: "sha256-" + strings.Repeat("a", 64)},
	}
	requests, err := uniqueLicenseArtifactRequests(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("requests = %#v, want two distinct files", requests)
	}
	if requests[0].PURL != versionedPURL || requests[1].PURL != versionedPURL {
		t.Fatalf("request PURLs = %q, %q", requests[0].PURL, requests[1].PURL)
	}
}

func TestScanDependencyArtifactsReportsLoaderFailure(t *testing.T) {
	loader := &fakeLicenseArtifactLoader{err: errors.New("registry unavailable")}
	_, err := scanDependencyArtifacts(context.Background(), []database.Dependency{{
		Name: "example", Ecosystem: "npm", PURL: "pkg:npm/example@1.0.0", Requirement: "1.0.0",
		ManifestKind: manifestKindLockfile,
	}}, loader, false)
	if err == nil || !strings.Contains(err.Error(), "loading package artifact pkg:npm/example@1.0.0") {
		t.Fatalf("loader error = %v", err)
	}
}

func TestValidateLicenseArchiveLimits(t *testing.T) {
	tests := []struct {
		name    string
		files   []archives.FileInfo
		wantErr string
	}{
		{
			name: "within limits",
			files: []archives.FileInfo{
				{Path: "LICENSE", Size: maxLicenseArtifactBytes - 1},
				{Path: "NOTICE", Size: 1},
			},
		},
		{
			name:    "negative size",
			files:   []archives.FileInfo{{Path: "LICENSE", Size: -1}},
			wantErr: `archive entry "LICENSE" has negative size -1`,
		},
		{
			name: "cumulative size",
			files: []archives.FileInfo{
				{Path: "LICENSE", Size: maxLicenseArtifactBytes},
				{Path: "NOTICE", Size: 1},
			},
			wantErr: "archive contents exceed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateLicenseArchive(&licenseArchiveReader{files: test.files})
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateLicenseArchive() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestOutputLicensesJSONIncludesAttribution(t *testing.T) {
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	infos := []LicenseInfo{{
		Name:        "example",
		Ecosystem:   "npm",
		Licenses:    []string{"MIT"},
		LicenseText: "license body",
		NoticeText:  "notice body",
		Declared: []licensespkg.DeclaredRecord{{
			Path:                 "package.json",
			Raw:                  []string{"MIT"},
			NormalizedExpression: "MIT",
		}},
		ManifestPath: "package.json",
	}}
	if err := outputLicensesJSON(command, infos); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"license_text": "license body"`,
		`"notice_text": "notice body"`,
		`"normalized_expression": "MIT"`,
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("JSON output missing %q: %s", want, output.String())
		}
	}
}

type fakeLicenseArtifactLoader struct {
	filename string
	content  []byte
	err      error
	calls    []acquire.Request
}

type licenseArchiveReader struct {
	files []archives.FileInfo
}

func (reader *licenseArchiveReader) List() ([]archives.FileInfo, error) {
	return reader.files, nil
}

func (*licenseArchiveReader) ListDir(string) ([]archives.FileInfo, error) {
	return nil, errors.New("unexpected ListDir call")
}

func (*licenseArchiveReader) Extract(string) (io.ReadCloser, error) {
	return nil, errors.New("unexpected Extract call")
}

func (*licenseArchiveReader) Hash(string) (string, error) {
	return "", errors.New("unexpected Hash call")
}

func (*licenseArchiveReader) Close() error {
	return nil
}

func (loader *fakeLicenseArtifactLoader) Load(
	_ context.Context,
	request acquire.Request,
	_ bool,
) (*acquire.Result, error) {
	loader.calls = append(loader.calls, request)
	if loader.err != nil {
		return nil, loader.err
	}
	sum := sha256.Sum256(loader.content)
	artifact, err := artifacts.New(
		request.PURL,
		digest.Digest(fmt.Sprintf("sha256:%x", sum)),
		int64(len(loader.content)),
		loader.filename,
		"application/zip",
	)
	if err != nil {
		return nil, err
	}
	return &acquire.Result{
		Artifact: artifact,
		Body:     io.NopCloser(bytes.NewReader(loader.content)),
	}, nil
}

func (loader *fakeLicenseArtifactLoader) Close() error {
	return nil
}

func licenseTestZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var content bytes.Buffer
	writer := zip.NewWriter(&content)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return content.Bytes()
}
