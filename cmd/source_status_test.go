package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
)

func TestSourceTrackerStatuses(t *testing.T) {
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	tracker := newSourceTracker()
	tracker.consider("swift", "", false)
	tracker.consider("npm", "registry.npmjs.org", true)
	tracker.markOK("npm", "registry.npmjs.org", now.Add(-90*time.Second))
	tracker.markError("npm", "registry.npmjs.org", errors.New("one package timed out"))
	tracker.consider("cargo", "crates.io", true)
	tracker.markError("cargo", "crates.io", errors.New("registry unavailable"))

	sources, warnings := tracker.statuses(now)
	if len(sources) != 3 {
		t.Fatalf("sources = %d, want 3", len(sources))
	}
	if sources[0].Ecosystem != "cargo" || sources[0].Status != sourceStatusError {
		t.Fatalf("cargo source = %+v, want error", sources[0])
	}
	if sources[0].Error != "registry unavailable" {
		t.Fatalf("cargo error = %q", sources[0].Error)
	}
	if sources[1].Ecosystem != "npm" || sources[1].Status != sourceStatusOK {
		t.Fatalf("npm source = %+v, want ok", sources[1])
	}
	if sources[1].CacheAgeSeconds == nil || *sources[1].CacheAgeSeconds != 90 {
		t.Fatalf("npm cache age = %v, want 90", sources[1].CacheAgeSeconds)
	}
	if sources[2].Ecosystem != "swift" || sources[2].Status != sourceStatusUnsupported {
		t.Fatalf("swift source = %+v, want unsupported", sources[2])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "one package timed out") {
		t.Fatalf("warnings = %q, want partial npm error", warnings)
	}
	if tracker.allUnavailable() {
		t.Fatal("tracker with an ok source reported all unavailable")
	}
}

func TestSourceTrackerAllUnavailable(t *testing.T) {
	tracker := newSourceTracker()
	tracker.consider("cargo", "crates.io", true)
	tracker.markError("cargo", "crates.io", errors.New("registry unavailable"))
	tracker.consider("swift", "", false)

	err := tracker.unavailableError()
	if err == nil {
		t.Fatal("unavailableError = nil, want error")
	}
	if !strings.Contains(err.Error(), "registry unavailable") {
		t.Fatalf("unavailableError = %q", err)
	}
}

func TestSourceTrackerCanonicalizesEcosystemAliases(t *testing.T) {
	now := time.Now().UTC()
	tracker := newSourceTracker()
	tracker.consider("rubygems", "rubygems.org", true)
	tracker.markOK("gem", "rubygems.org", now)

	sources, _ := tracker.statuses(now)
	if len(sources) != 1 {
		t.Fatalf("sources = %+v, want one canonical source", sources)
	}
	if sources[0].Ecosystem != "rubygems" || sources[0].Status != sourceStatusOK {
		t.Fatalf("source = %+v, want successful rubygems source", sources[0])
	}
}

func TestSourceStatusJSONIncludesZeroCacheAgeOnlyForSuccess(t *testing.T) {
	now := time.Now().UTC()
	tracker := newSourceTracker()
	tracker.markOK("npm", "registry.npmjs.org", now)
	tracker.markError("cargo", "crates.io", errors.New("unavailable"))

	envelope := resultEnvelope(tracker, []string{}, now)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	var output struct {
		Sources []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(output.Sources) != 2 {
		t.Fatalf("sources = %v, want two", output.Sources)
	}
	for _, source := range output.Sources {
		_, hasAge := source["cache_age_seconds"]
		switch source["status"] {
		case sourceStatusOK:
			if !hasAge || source["cache_age_seconds"] != float64(0) {
				t.Fatalf("successful source omitted zero cache age: %v", source)
			}
		case sourceStatusError:
			if hasAge {
				t.Fatalf("error source included cache age: %v", source)
			}
		}
	}
}

func TestRegistrySourceAcceptsCanonicalAlias(t *testing.T) {
	upstream, supported := registrySource("rubygems")
	if !supported || upstream != "rubygems.org" {
		t.Fatalf("registrySource(rubygems) = %q, %v; want rubygems.org, true", upstream, supported)
	}
}

func TestLicenseUpstreamRouting(t *testing.T) {
	tests := []struct {
		name       string
		purl       string
		directMode bool
		want       string
	}{
		{name: "public hybrid", purl: "pkg:npm/example", want: licenseDefaultUpstream},
		{name: "public direct", purl: "pkg:npm/example", directMode: true, want: "registry.npmjs.org"},
		{name: "private registry", purl: "pkg:npm/example?repository_url=https:%2F%2Fregistry.example.test", want: "registry.example.test"},
		{name: "default cargo index", purl: "pkg:cargo/example?repository_url=https:%2F%2Fgithub.com%2Frust-lang%2Fcrates.io-index", want: "crates.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := licenseUpstreamForPURL(tt.purl, tt.directMode); got != tt.want {
				t.Fatalf("licenseUpstreamForPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConsiderLicenseSourcesSeedsOnlyLockfileEcosystems(t *testing.T) {
	tracker := newSourceTracker()
	considerLicenseSources(tracker, []database.Dependency{
		{Ecosystem: "npm", Name: "example", ManifestKind: manifestKindManifest},
		{
			Ecosystem:    "cargo",
			Name:         "example",
			ManifestKind: "lockfile",
		},
	}, false)

	sources, _ := tracker.statuses(time.Now().UTC())
	if len(sources) != 1 {
		t.Fatalf("sources = %+v, want one lockfile-only source", sources)
	}
	if sources[0].Ecosystem != "cargo" || sources[0].Upstream != licenseDefaultUpstream {
		t.Fatalf("source = %+v, want cargo via %s", sources[0], licenseDefaultUpstream)
	}
}

func TestMetadataJSONOutputsUseResultEnvelope(t *testing.T) {
	tracker := newSourceTracker()
	tracker.consider("npm", "registry.npmjs.org", true)
	tracker.markOK("npm", "registry.npmjs.org", time.Now().UTC())

	tests := []struct {
		name   string
		output func(*cobra.Command) error
	}{
		{
			name: "outdated",
			output: func(cmd *cobra.Command) error {
				return outputOutdatedJSON(cmd, []OutdatedPackage{{Name: "example"}}, tracker)
			},
		},
		{
			name: "deprecated",
			output: func(cmd *cobra.Command) error {
				return outputDeprecatedJSON(cmd, []DeprecatedPackage{{Name: "example"}}, tracker)
			},
		},
		{
			name: "licenses",
			output: func(cmd *cobra.Command) error {
				return outputLicensesJSON(cmd, []LicenseInfo{{Name: "example"}}, tracker)
			},
		},
		{
			name: "vulns",
			output: func(cmd *cobra.Command) error {
				return outputVulnsJSON(cmd, []VulnResult{{Package: "example"}}, tracker)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&output)
			if err := tt.output(cmd); err != nil {
				t.Fatalf("output: %v", err)
			}

			var envelope struct {
				Results []json.RawMessage `json:"results"`
				Sources []SourceStatus    `json:"sources"`
			}
			if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
				t.Fatalf("decode envelope: %v\n%s", err, output.String())
			}
			if len(envelope.Results) != 1 || len(envelope.Sources) != 1 {
				t.Fatalf("envelope = %+v, want one result and source", envelope)
			}
		})
	}
}
