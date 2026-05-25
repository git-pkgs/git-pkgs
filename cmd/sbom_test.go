package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/sbom"
)

func TestBuildSBOM(t *testing.T) {
	deps := []database.Dependency{
		{Ecosystem: "npm", Name: "lodash", Requirement: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
		{Ecosystem: "npm", Name: "react", Requirement: "18.2.0"},
	}
	licenses := map[string]string{"pkg:npm/lodash": "MIT"}

	doc := buildSBOM(deps, licenses, "demo", "1.0.0")

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
	if lodash.LicenseDeclared != licenses["pkg:npm/lodash"] {
		t.Errorf("lodash license = %q", lodash.LicenseDeclared)
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
