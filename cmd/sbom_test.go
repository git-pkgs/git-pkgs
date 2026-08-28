package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/internal/database"
	gitpkg "github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/sbom"
	"github.com/git-pkgs/spdx"
	gitgo "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type sbomEnrichmentClient struct {
	packages        map[string]*enrichment.PackageInfo
	versions        map[string]*enrichment.VersionInfo
	getVersionCalls int
	bulkLookupCalls int
}

func (c *sbomEnrichmentClient) BulkLookup(
	_ context.Context,
	purls []string,
) (map[string]*enrichment.PackageInfo, error) {
	c.bulkLookupCalls++
	result := make(map[string]*enrichment.PackageInfo)
	for _, purlStr := range purls {
		if pkg := c.packages[purlStr]; pkg != nil {
			result[purlStr] = pkg
		}
	}
	return result, nil
}

func (c *sbomEnrichmentClient) GetVersions(_ context.Context, _ string) ([]enrichment.VersionInfo, error) {
	return nil, nil
}

func (c *sbomEnrichmentClient) GetVersion(_ context.Context, purlStr string) (*enrichment.VersionInfo, error) {
	c.getVersionCalls++
	return c.versions[purlStr], nil
}

func TestBuildSBOM(t *testing.T) {
	lodashDep := database.Dependency{
		Ecosystem:      "npm",
		Name:           "lodash",
		Requirement:    "4.17.21",
		PURL:           "pkg:npm/lodash",
		ManifestPath:   "package-lock.json",
		ManifestKind:   manifestKindLockfile,
		DependencyType: "runtime",
	}
	lodashDeclaration := database.Dependency{
		Ecosystem:      "npm",
		Name:           "lodash",
		Requirement:    "^4.17.0",
		PURL:           "pkg:npm/lodash",
		ManifestPath:   "package.json",
		ManifestKind:   manifestKindManifest,
		DependencyType: "runtime",
	}
	reactDep := database.Dependency{
		Ecosystem:    "npm",
		Name:         "react",
		Requirement:  "18.2.0",
		ManifestPath: "package.json",
	}
	components := []sbomComponent{
		{primary: lodashDep, occurrences: []database.Dependency{lodashDeclaration, lodashDep}},
		{primary: reactDep, occurrences: []database.Dependency{reactDep}},
	}
	licenses := map[string]string{"pkg:npm/lodash@4.17.21": "MIT"}

	doc := buildSBOM(components, licenses, "demo", "1.0.0", projectLicenses{}, true)

	if len(doc.Packages) != 2 {
		t.Fatalf("Packages = %d, want 2", len(doc.Packages))
	}
	if doc.Document.Component.Name != "demo" || doc.Document.Component.Version != "1.0.0" {
		t.Errorf("component = %+v", doc.Document.Component)
	}
	lodash := doc.Packages[0]
	if lodash.PURL() != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash purl = %q", lodash.PURL())
	}
	if lodash.LicenseDeclared != licenses["pkg:npm/lodash@4.17.21"] {
		t.Errorf("lodash license = %q", lodash.LicenseDeclared)
	}
	wantProperties := []sbom.Property{
		{Name: "git-pkgs:occurrence:0:manifest_path", Value: "package.json"},
		{Name: "git-pkgs:occurrence:0:requirement", Value: "^4.17.0"},
		{Name: "git-pkgs:occurrence:0:dependency_type", Value: "runtime"},
		{Name: "git-pkgs:occurrence:1:manifest_path", Value: "package-lock.json"},
		{Name: "git-pkgs:occurrence:1:requirement", Value: "4.17.21"},
		{Name: "git-pkgs:occurrence:1:dependency_type", Value: "runtime"},
	}
	if !slices.Equal(lodash.Properties, wantProperties) {
		t.Errorf("lodash properties = %+v, want %+v", lodash.Properties, wantProperties)
	}
	react := doc.Packages[1]
	if react.PURL() == "" {
		t.Errorf("react purl should be synthesised from ecosystem/name/version")
	}

	// Round-trip through the encoder so output remains parseable.
	for _, f := range []sbom.Format{sbom.FormatCycloneDXJSON, sbom.FormatSPDXJSON} {
		var buf bytes.Buffer
		if err := sbom.Encode(&buf, doc, f); err != nil {
			t.Fatalf("Encode(%d): %v", f, err)
		}
		if _, err := sbom.Parse(buf.Bytes()); err != nil {
			t.Fatalf("Parse(%d): %v\n%s", f, err, buf.String())
		}
		if !strings.Contains(buf.String(), "pkg:npm/lodash@4.17.21") {
			t.Errorf("encoded output missing purl:\n%s", buf.String())
		}
	}
}

func TestEncodeSBOMOccurrencePropertiesCycloneDX(t *testing.T) {
	dep := database.Dependency{
		Ecosystem:      "npm",
		Name:           "lodash",
		Requirement:    "4.17.21",
		PURL:           "pkg:npm/lodash",
		ManifestPath:   "package-lock.json",
		ManifestKind:   manifestKindLockfile,
		DependencyType: "runtime",
	}
	document := buildSBOM([]sbomComponent{{primary: dep, occurrences: []database.Dependency{dep}}},
		nil, "demo", "1.0.0", projectLicenses{}, true)

	var jsonOutput bytes.Buffer
	if err := sbom.Encode(&jsonOutput, document, sbom.FormatCycloneDXJSON); err != nil {
		t.Fatalf("Encode(CycloneDX JSON): %v", err)
	}
	parsed, err := sbom.Parse(jsonOutput.Bytes())
	if err != nil {
		t.Fatalf("Parse(CycloneDX JSON): %v\n%s", err, jsonOutput.String())
	}
	if len(parsed.Packages) != 1 || !slices.Equal(parsed.Packages[0].Properties, document.Packages[0].Properties) {
		t.Fatalf("properties after CycloneDX JSON round trip = %+v, want %+v",
			parsed.Packages, document.Packages[0].Properties)
	}

	var xmlOutput bytes.Buffer
	if err := sbom.Encode(&xmlOutput, document, sbom.FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode(CycloneDX XML): %v", err)
	}
	var xmlDocument struct {
		Components []struct {
			Properties []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:",chardata"`
			} `xml:"properties>property"`
		} `xml:"components>component"`
	}
	if err := xml.Unmarshal(xmlOutput.Bytes(), &xmlDocument); err != nil {
		t.Fatalf("Unmarshal(CycloneDX XML): %v\n%s", err, xmlOutput.String())
	}
	if len(xmlDocument.Components) != 1 {
		t.Fatalf("CycloneDX XML components = %d, want 1\n%s", len(xmlDocument.Components), xmlOutput.String())
	}
	properties := make([]sbom.Property, 0, len(xmlDocument.Components[0].Properties))
	for _, property := range xmlDocument.Components[0].Properties {
		properties = append(properties, sbom.Property(property))
	}
	if !slices.Equal(properties, document.Packages[0].Properties) {
		t.Fatalf("properties after CycloneDX XML encoding = %+v, want %+v",
			properties, document.Packages[0].Properties)
	}
}

func TestBuildSBOMOmitsOccurrencePropertiesForSPDX(t *testing.T) {
	dep := database.Dependency{
		Ecosystem:      "npm",
		Name:           "lodash",
		Requirement:    "4.17.21",
		ManifestPath:   "package-lock.json",
		ManifestKind:   manifestKindLockfile,
		DependencyType: "runtime",
	}
	document := buildSBOM([]sbomComponent{{primary: dep, occurrences: []database.Dependency{dep}}},
		nil, "demo", "1.0.0", projectLicenses{}, false)

	if len(document.Packages) != 1 || len(document.Packages[0].Properties) != 0 {
		t.Fatalf("SPDX package properties = %+v, want none", document.Packages)
	}
	var output bytes.Buffer
	if err := sbom.Encode(&output, document, sbom.FormatSPDXJSON); err != nil {
		t.Fatalf("Encode(SPDX JSON): %v", err)
	}
	if strings.Contains(output.String(), "git-pkgs:occurrence") {
		t.Fatalf("SPDX output contains CycloneDX occurrence properties:\n%s", output.String())
	}
}

func TestSBOMCommandAssociatesWorkspaceManifestWithRootLockfile(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{
  "name": "workspace-root",
  "private": true,
  "workspaces": ["packages/*"]
}`, "add workspace root")
	commitSBOMFile(t, repository, repoDir, "packages/web/package.json", `{
  "name": "web",
  "version": "1.0.0",
  "dependencies": {"lodash": "^4.17.0"}
}`, "add workspace package")
	commitSBOMFile(t, repository, repoDir, "package-lock.json", `{
  "name": "workspace-root",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "workspace-root",
      "workspaces": ["packages/*"]
    },
    "packages/web": {
      "name": "web",
      "version": "1.0.0",
      "dependencies": {"lodash": "^4.17.0"}
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}`, "add workspace lockfile")

	document := runSBOMCommandForTest(t, repoDir)
	var lodashPackages []sbom.Package
	for _, pkg := range document.Packages {
		if pkg.Name == "lodash" {
			lodashPackages = append(lodashPackages, pkg)
		}
	}
	if len(lodashPackages) != 1 {
		t.Fatalf("lodash components = %d, want 1", len(lodashPackages))
	}
	lodash := lodashPackages[0]
	if lodash.PURL() != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("lodash PURL = %q, want resolved version", lodash.PURL())
	}
	if !sbomPropertiesContain(lodash.Properties, "manifest_path", "packages/web/package.json") {
		t.Fatalf("lodash properties = %+v, want workspace manifest occurrence", lodash.Properties)
	}
}

func TestSBOMCommandDoesNotResolveDirectDeclarationToTransitiveVersion(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{
  "name": "direct-precedence",
  "version": "1.0.0",
  "dependencies": {"foo": "^5.0.0"}
}`, "add package manifest")
	commitSBOMFile(t, repository, repoDir, "package-lock.json", `{
  "name": "direct-precedence",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "direct-precedence",
      "version": "1.0.0",
      "dependencies": {"foo": "^5.0.0"}
    },
    "node_modules/foo": {
      "version": "4.0.0"
    },
    "node_modules/bar": {
      "version": "1.0.0",
      "dependencies": {"foo": "5.1.0"}
    },
    "node_modules/bar/node_modules/foo": {
      "version": "5.1.0"
    }
  }
}`, "add package lockfile")

	document := runSBOMCommandForTest(t, repoDir)
	fooByVersion := make(map[string]sbom.Package)
	for _, pkg := range document.Packages {
		if pkg.Name == "foo" {
			fooByVersion[pkg.Version] = pkg
		}
	}
	if len(fooByVersion) != 3 {
		t.Fatalf("foo components = %+v, want unresolved declaration and two resolved versions", fooByVersion)
	}
	declaration, ok := fooByVersion["^5.0.0"]
	if !ok || declaration.PURL() != "pkg:npm/foo" ||
		!sbomPropertiesContain(declaration.Properties, "manifest_path", "package.json") {
		t.Fatalf("unresolved foo declaration = %+v, want package.json occurrence", declaration)
	}
	transitive, ok := fooByVersion["5.1.0"]
	if !ok || sbomPropertiesContain(transitive.Properties, "manifest_path", "package.json") {
		t.Fatalf("transitive foo component = %+v, must not contain package.json occurrence", transitive)
	}
}

func TestSBOMCommandScopesDirectPreferenceToLockfileDirectory(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "package.json", `{
  "name": "workspace-root",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {"foo": "^4.0.0"}
}`, "add workspace root")
	commitSBOMFile(t, repository, repoDir, "packages/web/package.json", `{
  "name": "web",
  "version": "1.0.0",
  "dependencies": {"foo": "^5.0.0"}
}`, "add workspace package")
	commitSBOMFile(t, repository, repoDir, "package-lock.json", `{
  "name": "workspace-root",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "workspace-root",
      "workspaces": ["packages/*"],
      "dependencies": {"foo": "^4.0.0"}
    },
    "packages/web": {
      "name": "web",
      "version": "1.0.0",
      "dependencies": {"foo": "^5.0.0"}
    },
    "node_modules/foo": {
      "version": "4.0.0"
    },
    "packages/web/node_modules/foo": {
      "version": "5.1.0"
    }
  }
}`, "add workspace lockfile")

	document := runSBOMCommandForTest(t, repoDir)
	fooByVersion := make(map[string]sbom.Package)
	for _, pkg := range document.Packages {
		if pkg.Name == "foo" {
			fooByVersion[pkg.Version] = pkg
		}
	}
	if len(fooByVersion) != 2 {
		t.Fatalf("foo components = %+v, want two resolved versions", fooByVersion)
	}
	root := fooByVersion["4.0.0"]
	if !sbomPropertiesContain(root.Properties, "manifest_path", "package.json") ||
		sbomPropertiesContain(root.Properties, "manifest_path", "packages/web/package.json") {
		t.Fatalf("root foo properties = %+v, want only root declaration", root.Properties)
	}
	workspace := fooByVersion["5.1.0"]
	if !sbomPropertiesContain(workspace.Properties, "manifest_path", "packages/web/package.json") ||
		sbomPropertiesContain(workspace.Properties, "manifest_path", "package.json") {
		t.Fatalf("workspace foo properties = %+v, want only workspace declaration", workspace.Properties)
	}
}

func runSBOMCommandForTest(t *testing.T, repoDir string) *sbom.SBOM {
	t.Helper()
	oldDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("Chdir(%s): %v", repoDir, err)
	}
	defer func() {
		if err := os.Chdir(oldDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	}()

	command := NewRootCmd()
	command.SetArgs([]string{"init", "--no-hooks"})
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err != nil {
		t.Fatalf("git pkgs init: %v", err)
	}

	var output bytes.Buffer
	command = NewRootCmd()
	command.SetArgs([]string{"sbom", "--skip-enrichment", "--format", "json"})
	command.SetOut(&output)
	command.SetErr(&bytes.Buffer{})
	if err := command.Execute(); err != nil {
		t.Fatalf("git pkgs sbom: %v", err)
	}

	document, err := sbom.Parse(output.Bytes())
	if err != nil {
		t.Fatalf("parse SBOM: %v\n%s", err, output.String())
	}
	return document
}

func sbomPropertiesContain(properties []sbom.Property, suffix, value string) bool {
	for _, property := range properties {
		if strings.HasSuffix(property.Name, ":"+suffix) && property.Value == value {
			return true
		}
	}
	return false
}

func TestProjectLicenseAtRevision(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	first := commitSBOMFile(t, repository, repoDir, "package.json", `{
  "name": "demo",
  "version": "1.0.0",
  "license": "MIT"
}`, "add package manifest")
	commitSBOMFile(t, repository, repoDir, "package.json", `{
  "name": "demo",
  "version": "1.1.0",
  "license": "Apache-2.0"
}`, "change project license")
	commitSBOMFile(t, repository, repoDir, "packages/nested/package.json", `{
  "name": "nested",
  "version": "1.0.0",
  "license": "GPL-3.0-only"
}`, "add nested package")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}

	got, warnings, err := projectLicensesAtRevision(repo, first.String())
	if err != nil {
		t.Fatalf("projectLicensesAtRevision(first): %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("first revision warnings = %q", warnings)
	}
	if got.Expression != "MIT" || len(got.Names) != 0 {
		t.Fatalf("first revision licenses = %+v, want MIT", got)
	}

	got, warnings, err = projectLicensesAtRevision(repo, "HEAD")
	if err != nil {
		t.Fatalf("projectLicensesAtRevision(HEAD): %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("HEAD warnings = %q", warnings)
	}
	if got.Expression != "Apache-2.0" || len(got.Names) != 0 {
		t.Fatalf("HEAD licenses = %+v, want Apache-2.0", got)
	}
}

func TestNormalizeProjectLicensesSeparatesNonSPDXNames(t *testing.T) {
	licenses := normalizeProjectLicenses([]string{
		"BSD-3-Clause",
		"License :: OSI Approved :: BSD License",
		"Acme Internal Terms",
	})

	if licenses.Expression == "" || !spdx.Valid(licenses.Expression) {
		t.Fatalf("normalized expression = %q, want valid SPDX", licenses.Expression)
	}
	if strings.Contains(licenses.Expression, "License ::") {
		t.Fatalf("normalized expression contains raw classifier: %q", licenses.Expression)
	}
	if len(licenses.Names) != 1 || licenses.Names[0] != "Acme Internal Terms" {
		t.Fatalf("non-SPDX names = %q, want [Acme Internal Terms]", licenses.Names)
	}
}

func TestNormalizeProjectLicensesCombinesIndependentExpressions(t *testing.T) {
	licenses := normalizeProjectLicenses([]string{
		"MIT OR Apache-2.0",
		"BSD-3-Clause",
	})

	if !spdx.Valid(licenses.Expression) {
		t.Fatalf("normalized expression = %q, want valid SPDX", licenses.Expression)
	}
	if licenses.Expression != "BSD-3-Clause AND (MIT OR Apache-2.0)" {
		t.Fatalf("normalized expression = %q, want independent declarations joined with AND "+
			"and manifest-level OR preserved", licenses.Expression)
	}
}

func TestProjectLicenseFileAtRevision(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "original license terms\n", "add license file")
	manifestRevision := commitSBOMFile(t, repository, repoDir, "Cargo.toml", `[package]
name = "demo"
version = "1.0.0"
license-file = "LICENSE.custom"
`, "add cargo manifest")
	commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "updated license terms\n", "update license file")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}

	licenses, warnings, err := projectLicensesAtRevision(repo, manifestRevision.String())
	if err != nil {
		t.Fatalf("projectLicensesAtRevision: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q", warnings)
	}
	if licenses.Expression != "" || len(licenses.Names) != 0 || len(licenses.Files) != 1 {
		t.Fatalf("project licenses = %+v, want one declared file", licenses)
	}
	if file := licenses.Files[0]; file.Path != "LICENSE.custom" || file.Text != "original license terms\n" {
		t.Fatalf("project license file = %+v, want original revision content", file)
	}
}

func TestProjectLicenseFileMissingWarnsAndContinues(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "Cargo.toml", `[package]
name = "demo"
version = "1.0.0"
license-file = "LICENSE.missing"
`, "add cargo manifest")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}
	licenses, warnings, err := projectLicensesAtRevision(repo, "HEAD")
	if err != nil {
		t.Fatalf("projectLicensesAtRevision: %v", err)
	}
	if len(licenses.Files) != 0 {
		t.Fatalf("project license files = %+v, want none", licenses.Files)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "LICENSE.missing") ||
		!strings.Contains(warnings[0], "was not found") {
		t.Fatalf("warnings = %q", warnings)
	}
}

func TestProjectLicenseFileEmptyWarnsAndContinues(t *testing.T) {
	repoDir := t.TempDir()
	repository, err := gitgo.PlainInit(repoDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	commitSBOMFile(t, repository, repoDir, "LICENSE.custom", "\n", "add empty license file")
	commitSBOMFile(t, repository, repoDir, "Cargo.toml", `[package]
name = "demo"
version = "1.0.0"
license-file = "LICENSE.custom"
`, "add cargo manifest")

	repo, err := gitpkg.OpenRepository(repoDir)
	if err != nil {
		t.Fatalf("OpenRepository: %v", err)
	}
	licenses, warnings, err := projectLicensesAtRevision(repo, "HEAD")
	if err != nil {
		t.Fatalf("projectLicensesAtRevision: %v", err)
	}
	if len(licenses.Files) != 0 {
		t.Fatalf("project license files = %+v, want none", licenses.Files)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "LICENSE.custom") ||
		!strings.Contains(warnings[0], "is empty") {
		t.Fatalf("warnings = %q", warnings)
	}
}

func testRootLicenses() (*sbom.SBOM, projectLicenses) {
	licenses := projectLicenses{
		Expression: "MIT OR Apache-2.0",
		Names:      []string{"Acme Internal Terms"},
		Files: []projectLicenseFile{{
			Path: "LICENSE.custom",
			Text: "Custom file terms\n",
		}},
	}
	document := buildSBOM(nil, nil, "demo", "1.0.0", licenses, true)
	return document, licenses
}

func TestEncodeSBOMWithRootLicensesCycloneDXJSON(t *testing.T) {
	document, licenses := testRootLicenses()
	var output bytes.Buffer
	if err := sbom.Encode(&output, document, sbom.FormatCycloneDXJSON); err != nil {
		t.Fatalf("sbom.Encode: %v", err)
	}
	var result struct {
		Metadata struct {
			Component struct {
				Licenses []struct {
					Expression string `json:"expression"`
					License    *struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"license"`
				} `json:"licenses"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, output.String())
	}
	got := result.Metadata.Component.Licenses
	if len(got) != 3 {
		t.Fatalf("root licenses = %+v, want three license entries", got)
	}
	wantNames := []string{licenses.Expression, licenses.Names[0], licenses.Files[0].Path}
	for i, choice := range got {
		if choice.Expression != "" || choice.License == nil || choice.License.Name != wantNames[i] {
			t.Fatalf("root license choice %d = %+v, want named license %q", i, choice, wantNames[i])
		}
	}
}

func TestEncodeSBOMWithRootLicensesCycloneDXXML(t *testing.T) {
	document, licenses := testRootLicenses()
	var output bytes.Buffer
	if err := sbom.Encode(&output, document, sbom.FormatCycloneDXXML); err != nil {
		t.Fatalf("sbom.Encode: %v", err)
	}
	var result struct {
		Metadata struct {
			Component struct {
				LicenseExpression string   `xml:"licenses>expression"`
				LicenseNames      []string `xml:"licenses>license>name"`
			} `xml:"component"`
		} `xml:"metadata"`
	}
	if err := xml.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, output.String())
	}
	component := result.Metadata.Component
	wantNames := []string{licenses.Expression, licenses.Names[0], licenses.Files[0].Path}
	if component.LicenseExpression != "" || !slices.Equal(component.LicenseNames, wantNames) {
		t.Fatalf("root licenses = %+v, want named licenses %q", component, wantNames)
	}
}

func TestEncodeSBOMWithRootLicensesSPDXJSON(t *testing.T) {
	document, licenses := testRootLicenses()
	var output bytes.Buffer
	if err := sbom.Encode(&output, document, sbom.FormatSPDXJSON); err != nil {
		t.Fatalf("sbom.Encode: %v", err)
	}
	var result struct {
		Packages []struct {
			SPDXID          string `json:"SPDXID"`
			Name            string `json:"name"`
			LicenseDeclared string `json:"licenseDeclared"`
		} `json:"packages"`
		ExtractedLicensingInfos []struct {
			LicenseID     string `json:"licenseId"`
			Name          string `json:"name"`
			ExtractedText string `json:"extractedText"`
		} `json:"hasExtractedLicensingInfos"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("Unmarshal: %v\n%s", err, output.String())
	}
	rootLicense := findRootPackageLicense(result.Packages)
	if !spdx.Valid(rootLicense) {
		t.Fatalf("root license = %q, want valid SPDX expression with both LicenseRefs", rootLicense)
	}
	if len(result.ExtractedLicensingInfos) != 2 {
		t.Fatalf("extracted licensing infos = %+v, want two", result.ExtractedLicensingInfos)
	}
	fileInfo := result.ExtractedLicensingInfos[1]
	if fileInfo.Name != licenses.Files[0].Path || fileInfo.ExtractedText != licenses.Files[0].Text ||
		!strings.Contains(rootLicense, fileInfo.LicenseID) {
		t.Fatalf("file extracted licensing info = %+v", fileInfo)
	}
}

func findRootPackageLicense(packages []struct {
	SPDXID          string `json:"SPDXID"`
	Name            string `json:"name"`
	LicenseDeclared string `json:"licenseDeclared"`
}) string {
	for _, pkg := range packages {
		if pkg.Name == "demo" {
			return pkg.LicenseDeclared
		}
	}
	return ""
}

func commitSBOMFile(
	t *testing.T,
	repository *gitgo.Repository,
	repoDir, name, content, message string,
) plumbing.Hash {
	t.Helper()
	fullPath := filepath.Join(repoDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := worktree.Add(name); err != nil {
		t.Fatalf("Add: %v", err)
	}
	when := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	hash, err := worktree.Commit(message, &gitgo.CommitOptions{
		Author: &object.Signature{Name: "Test User", Email: "test@example.com", When: when},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return hash
}

func TestSelectSBOMDependenciesPrefersResolvedVersions(t *testing.T) {
	direct := database.Dependency{
		Ecosystem:    "npm",
		Name:         "ua-parser-js",
		Requirement:  "^1.0.41",
		PURL:         "pkg:npm/ua-parser-js",
		ManifestPath: "package.json",
		ManifestKind: "manifest",
	}
	resolved := database.Dependency{
		Ecosystem:    "npm",
		Name:         "ua-parser-js",
		Requirement:  "1.0.41",
		PURL:         "pkg:npm/ua-parser-js",
		ManifestPath: "package-lock.json",
		ManifestKind: manifestKindLockfile,
	}
	nested := resolved
	nested.Requirement = "2.0.10"

	selected := selectSBOMDependencies([]database.Dependency{direct, resolved, nested, resolved})
	if len(selected) != 2 {
		t.Fatalf("selected dependencies = %d, want 2", len(selected))
	}
	if got := sbomPURLForDependency(selected[0].primary); got != "pkg:npm/ua-parser-js@1.0.41" {
		t.Fatalf("first PURL = %q, want version 1.0.41", got)
	}
	if got := sbomPURLForDependency(selected[1].primary); got != "pkg:npm/ua-parser-js@2.0.10" {
		t.Fatalf("second PURL = %q, want version 2.0.10", got)
	}
	if got := selected[0].occurrences; len(got) != 3 || got[0] != direct || got[1] != resolved || got[2] != resolved {
		t.Fatalf("first component occurrences = %+v, want direct declaration and both matching lockfile rows", got)
	}
	if got := selected[1].occurrences; len(got) != 1 || got[0] != nested {
		t.Fatalf("second component occurrences = %+v, want only nested lockfile row", got)
	}
}

func TestSelectSBOMDependenciesRetainsWorkspaceOccurrences(t *testing.T) {
	webDeclaration := database.Dependency{
		Ecosystem:      "npm",
		Name:           "lodash",
		Requirement:    "^4.17.0",
		PURL:           "pkg:npm/lodash",
		ManifestPath:   "web/package.json",
		ManifestKind:   manifestKindManifest,
		DependencyType: "runtime",
	}
	apiDeclaration := webDeclaration
	apiDeclaration.Requirement = "~4.17.15"
	apiDeclaration.ManifestPath = "api/package.json"
	webResolved := webDeclaration
	webResolved.Requirement = "4.17.21"
	webResolved.ManifestPath = "web/package-lock.json"
	webResolved.ManifestKind = manifestKindLockfile
	webResolved.Direct = true
	apiResolved := webResolved
	apiResolved.ManifestPath = "api/package-lock.json"

	components := selectSBOMDependencies([]database.Dependency{
		apiDeclaration,
		apiResolved,
		webDeclaration,
		webResolved,
	})
	if len(components) != 1 {
		t.Fatalf("components = %d, want 1", len(components))
	}
	if got := sbomPURLForDependency(components[0].primary); got != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("component PURL = %q, want resolved PURL", got)
	}
	wantOccurrences := []database.Dependency{apiDeclaration, apiResolved, webDeclaration, webResolved}
	if !slices.Equal(components[0].occurrences, wantOccurrences) {
		t.Fatalf("occurrences = %+v, want %+v", components[0].occurrences, wantOccurrences)
	}
}

func TestSelectSBOMDependenciesKeepsUnmatchedValidConstraintUnresolved(t *testing.T) {
	declaration := database.Dependency{
		Ecosystem:    "npm",
		Name:         "lodash",
		Requirement:  "^5.0.0",
		PURL:         "pkg:npm/lodash",
		ManifestPath: "package.json",
		ManifestKind: manifestKindManifest,
	}
	resolved := declaration
	resolved.Requirement = "4.17.21"
	resolved.ManifestPath = "package-lock.json"
	resolved.ManifestKind = manifestKindLockfile

	components := selectSBOMDependencies([]database.Dependency{declaration, resolved})
	if len(components) != 2 {
		t.Fatalf("components = %d, want unresolved declaration and resolved lockfile", len(components))
	}
	if components[0].primary != declaration || !slices.Equal(components[0].occurrences, []database.Dependency{declaration}) {
		t.Fatalf("unresolved component = %+v, want declaration only", components[0])
	}
	if components[1].primary != resolved || !slices.Equal(components[1].occurrences, []database.Dependency{resolved}) {
		t.Fatalf("resolved component = %+v, want lockfile occurrence only", components[1])
	}
}

func TestSelectSBOMDependenciesKeepsDependenciesWithoutPURL(t *testing.T) {
	dep := database.Dependency{Name: "local-tool", Requirement: "1.0.0"}
	otherVersion := dep
	otherVersion.Requirement = "2.0.0"

	selected := selectSBOMDependencies([]database.Dependency{dep, dep, otherVersion})
	if len(selected) != 2 {
		t.Fatalf("selected dependencies = %d, want 2", len(selected))
	}
	for _, selectedDep := range selected {
		if got := sbomPURLForDependency(selectedDep.primary); got != "" {
			t.Fatalf("PURL = %q, want empty", got)
		}
	}
}

func TestEnrichLicensesUsesVersionMetadata(t *testing.T) {
	for _, tt := range []struct {
		name           string
		versionLicense string
		wantLicense    string
		wantFallbacks  int
	}{
		{
			name:           "version license",
			versionLicense: "MIT",
			wantLicense:    "MIT",
		},
		{
			name:          "package fallback",
			wantLicense:   "AGPL-3.0-or-later",
			wantFallbacks: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &sbomEnrichmentClient{
				packages: map[string]*enrichment.PackageInfo{
					"pkg:npm/ua-parser-js": {License: "AGPL-3.0-or-later"},
				},
				versions: map[string]*enrichment.VersionInfo{
					"pkg:npm/ua-parser-js@1.0.41": {Number: "1.0.41", License: tt.versionLicense},
				},
			}
			original := NewEnrichmentClient
			NewEnrichmentClient = func(...enrichment.Option) (enrichment.Client, error) {
				return client, nil
			}
			defer func() { NewEnrichmentClient = original }()

			deps := []database.Dependency{
				{
					Ecosystem:    "npm",
					Name:         "ua-parser-js",
					Requirement:  "1.0.41",
					PURL:         "pkg:npm/ua-parser-js",
					ManifestKind: manifestKindLockfile,
				},
			}
			licenses, fallbacks, err := enrichLicenses(nil, deps)
			if err != nil {
				t.Fatalf("enrich licenses: %v", err)
			}
			if got := licenses["pkg:npm/ua-parser-js@1.0.41"]; got != tt.wantLicense {
				t.Fatalf("license = %q, want %q", got, tt.wantLicense)
			}
			if fallbacks != tt.wantFallbacks {
				t.Fatalf("package fallbacks = %d, want %d", fallbacks, tt.wantFallbacks)
			}
			if client.bulkLookupCalls != 1 || client.getVersionCalls != 1 {
				t.Fatalf("enrichment calls: BulkLookup=%d GetVersion=%d, want 1 each",
					client.bulkLookupCalls, client.getVersionCalls)
			}
		})
	}
}

func TestSBOMFormat(t *testing.T) {
	tests := []struct {
		typ, fmt string
		want     sbom.Format
		wantErr  bool
	}{
		{"cyclonedx", "json", sbom.FormatCycloneDXJSON, false},
		{"cyclonedx", "xml", sbom.FormatCycloneDXXML, false},
		{"spdx", "json", sbom.FormatSPDXJSON, false},
		{"spdx", "xml", 0, true},
		{"", "", sbom.FormatCycloneDXJSON, false},
	}
	for _, tt := range tests {
		got, err := sbomFormat(tt.typ, tt.fmt)
		if (err != nil) != tt.wantErr {
			t.Errorf("sbomFormat(%s,%s) err = %v", tt.typ, tt.fmt, err)
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("sbomFormat(%s,%s) = %d, want %d", tt.typ, tt.fmt, got, tt.want)
		}
	}
}
