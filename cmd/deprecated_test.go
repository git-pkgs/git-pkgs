package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/registries"
	"github.com/spf13/cobra"
)

func TestVersionedPURLForDependency(t *testing.T) {
	t.Run("builds versioned PURL from dependency", func(t *testing.T) {
		got := versionedPURLForDependency(database.Dependency{
			Name:        "lodash",
			Ecosystem:   "npm",
			Requirement: "4.17.21",
		})
		if got != "pkg:npm/lodash@4.17.21" {
			t.Fatalf("versioned PURL = %q, want pkg:npm/lodash@4.17.21", got)
		}
	})

	t.Run("preserves existing versioned PURL", func(t *testing.T) {
		got := versionedPURLForDependency(database.Dependency{
			PURL:        "pkg:npm/%40scope/pkg@1.0.0?repository_url=https://registry.example.test",
			Name:        "@scope/pkg",
			Ecosystem:   "npm",
			Requirement: "1.0.0",
		})
		if got != "pkg:npm/%40scope/pkg@1.0.0?repository_url=https://registry.example.test" {
			t.Fatalf("versioned PURL = %q, want existing PURL", got)
		}
	})

	t.Run("normalizes the default crates.io index URL", func(t *testing.T) {
		got := versionedPURLForDependency(database.Dependency{
			PURL:        "pkg:cargo/time@0.3.50?repository_url=https:%2F%2Fgithub.com%2Frust-lang%2Fcrates.io-index",
			Name:        "time",
			Ecosystem:   "cargo",
			Requirement: "0.3.50",
		})
		if got != "pkg:cargo/time@0.3.50" {
			t.Fatalf("versioned PURL = %q, want unqualified crates.io PURL", got)
		}
	})
}

func TestDeprecatedPackages(t *testing.T) {
	purlToDeps := map[string][]database.Dependency{
		"pkg:npm/request@2.88.2": {
			{
				Name:         "request",
				Ecosystem:    "npm",
				Requirement:  "2.88.2",
				ManifestPath: "package-lock.json",
			},
		},
		"pkg:npm/lodash@4.17.21": {
			{
				Name:         "lodash",
				Ecosystem:    "npm",
				Requirement:  "4.17.21",
				ManifestPath: "package-lock.json",
			},
		},
		"pkg:cargo/time@0.3.50": {
			{
				Name:         "time",
				Ecosystem:    "cargo",
				Requirement:  "0.3.50",
				ManifestPath: "Cargo.lock",
			},
		},
		"pkg:golang/example.com/retracted@v1.1.0": {
			{
				Name:         "example.com/retracted",
				Ecosystem:    "golang",
				Requirement:  "v1.1.0",
				ManifestPath: "go.sum",
			},
		},
	}
	versionData := map[string]*registries.Version{
		"pkg:npm/request@2.88.2": {
			Number: "2.88.2",
			Status: registries.StatusDeprecated,
			Metadata: map[string]any{
				"deprecated": "request has been deprecated",
			},
		},
		"pkg:npm/lodash@4.17.21": {
			Number: "4.17.21",
			Status: registries.StatusNone,
		},
		"pkg:cargo/time@0.3.50": {
			Number: "0.3.50",
			Status: registries.StatusYanked,
		},
		"pkg:golang/example.com/retracted@v1.1.0": {
			Number: "v1.1.0",
			Status: registries.StatusRetracted,
		},
	}

	got := deprecatedPackages(purlToDeps, versionData)
	if len(got) != 3 {
		t.Fatalf("reported count = %d, want 3", len(got))
	}
	byName := make(map[string]DeprecatedPackage, len(got))
	for _, dep := range got {
		byName[dep.Name] = dep
	}
	if byName["request"].Status != string(registries.StatusDeprecated) {
		t.Fatalf("request status = %q, want deprecated", byName["request"].Status)
	}
	if byName["request"].Message != "request has been deprecated" {
		t.Fatalf("message = %q, want deprecation message", byName["request"].Message)
	}
	if byName["time"].Status != string(registries.StatusYanked) {
		t.Fatalf("time status = %q, want yanked", byName["time"].Status)
	}
	if byName["example.com/retracted"].Status != string(registries.StatusRetracted) {
		t.Fatalf("Go module status = %q, want retracted", byName["example.com/retracted"].Status)
	}
}

func TestFetchDeprecatedVersionDataUsesCache(t *testing.T) {
	db, err := database.Create(filepath.Join(t.TempDir(), "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = db.SaveVersions([]database.CachedVersion{
		{
			PURL:            "pkg:npm/request@2.88.2",
			PackagePURL:     "pkg:npm/request",
			Status:          string(registries.StatusDeprecated),
			StatusCheckedAt: time.Now(),
			Metadata: map[string]any{
				"deprecated": "cached deprecation message",
			},
		},
	})
	if err != nil {
		t.Fatalf("save cached versions: %v", err)
	}

	got := fetchDeprecatedVersionData(db, []string{"pkg:npm/request@2.88.2"})
	version := got["pkg:npm/request@2.88.2"]
	if version == nil {
		t.Fatal("expected cached version data")
	}
	if version.Status != registries.StatusDeprecated {
		t.Fatalf("status = %q, want deprecated", version.Status)
	}
	if msg := deprecationMessage(version); msg != "cached deprecation message" {
		t.Fatalf("message = %q, want cached deprecation message", msg)
	}
}

func TestCachedDeprecatedVersionDataIgnoresUncheckedStatus(t *testing.T) {
	db, err := database.Create(filepath.Join(t.TempDir(), "pkgs.sqlite3"))
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = db.SaveVersions([]database.CachedVersion{
		{
			PURL:        "pkg:npm/request@2.88.2",
			PackagePURL: "pkg:npm/request",
			PublishedAt: time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("save cached versions: %v", err)
	}

	got := cachedDeprecatedVersionData(db, []string{"pkg:npm/request@2.88.2"})
	if _, ok := got["pkg:npm/request@2.88.2"]; ok {
		t.Fatal("expected enrichment-only cache row to be ignored")
	}
}

func TestOutputDeprecatedJSONEmptyEnvelope(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	if err := outputDeprecatedJSON(cmd, []DeprecatedPackage{}); err != nil {
		t.Fatalf("output json: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "{\n  \"results\": [],\n  \"sources\": []\n}" {
		t.Fatalf("json output = %q, want empty result envelope", got)
	}
}
