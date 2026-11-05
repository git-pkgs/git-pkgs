package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/git-pkgs/changelog"
	"github.com/spf13/cobra"
)

func TestBuildChangelogResult(t *testing.T) {
	parser := changelog.Parse("## [3.0.0]\n\nThird\n\n## [2.0.0]\n\nSecond\n\n## [1.0.0]\n\nFirst\n")

	t.Run("all entries", func(t *testing.T) {
		result := buildChangelogResult(
			parser,
			"example",
			"npm",
			"",
			"",
			"https://github.com/example/example",
			"CHANGELOG.md",
		)
		if result.Package != "example" || result.Ecosystem != "npm" {
			t.Fatalf("result metadata = %+v", result)
		}
		if result.Repository != "https://github.com/example/example" ||
			result.ChangelogFilename != "CHANGELOG.md" {
			t.Fatalf("result source metadata = %+v", result)
		}
		if len(result.Entries) != 3 {
			t.Fatalf("entries = %+v, want three", result.Entries)
		}
		if result.Entries[0].Version != "3.0.0" || result.Entries[0].Content != "Third" {
			t.Errorf("first entry = %+v", result.Entries[0])
		}
	})

	t.Run("bounded entries", func(t *testing.T) {
		result := buildChangelogResult(
			parser,
			"example",
			"npm",
			"1.0.0",
			"3.0.0",
			"https://github.com/example/example",
			"CHANGELOG.md",
		)
		if result.From != "1.0.0" || result.To != "3.0.0" {
			t.Fatalf("range = %q..%q", result.From, result.To)
		}
		if len(result.Entries) != 2 ||
			result.Entries[0].Version != "3.0.0" ||
			result.Entries[1].Version != "2.0.0" {
			t.Fatalf("entries = %+v, want 3.0.0 and 2.0.0", result.Entries)
		}
	})

	t.Run("bounds between headings", func(t *testing.T) {
		result := buildChangelogResult(
			parser,
			"example",
			"npm",
			"1.5.0",
			"2.5.0",
			"https://github.com/example/example",
			"CHANGELOG.md",
		)
		if len(result.Entries) != 1 || result.Entries[0].Version != "2.0.0" {
			t.Fatalf("entries = %+v, want 2.0.0", result.Entries)
		}
	})
}

func TestOutputChangelogJSONUsesEmptyArray(t *testing.T) {
	command := &cobra.Command{}
	var output bytes.Buffer
	command.SetOut(&output)
	result := &ChangelogResult{
		Package:           "example",
		Ecosystem:         "npm",
		Repository:        "https://github.com/example/example",
		ChangelogFilename: "CHANGELOG.md",
		Entries:           []ChangelogEntry{},
	}

	if err := outputChangelogJSON(command, result); err != nil {
		t.Fatalf("outputChangelogJSON: %v", err)
	}

	var decoded struct {
		Entries []ChangelogEntry `json:"entries"`
	}
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if decoded.Entries == nil || len(decoded.Entries) != 0 {
		t.Fatalf("entries = %#v, want empty non-nil array", decoded.Entries)
	}
}

func TestDetectEcosystem(t *testing.T) {
	t.Run("known manager flag without detection", func(t *testing.T) {
		eco, err := detectEcosystem("cargo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eco != "cargo" {
			t.Errorf("got %q, want %q", eco, "cargo")
		}
	})

	t.Run("npm manager flag", func(t *testing.T) {
		eco, err := detectEcosystem("npm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eco != "npm" {
			t.Errorf("got %q, want %q", eco, "npm")
		}
	})

	t.Run("lockfile manager maps to ecosystem", func(t *testing.T) {
		eco, err := detectEcosystem("pnpm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eco != "npm" {
			t.Errorf("got %q, want %q", eco, "npm")
		}
	})

	t.Run("unknown manager flag", func(t *testing.T) {
		_, err := detectEcosystem("nonexistent-manager")
		if err == nil {
			t.Fatal("expected error for unknown manager")
		}
	})
}

func TestDetectEcosystemSharedDefinitions(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tt := range []struct{ manager, ecosystem string }{
		{"bundler", "rubygems"},
		{"gomod", "go"},
		{"gradle", "maven"},
		{"cabal", "hackage"},
		{"stack", "hackage"},
		{"pkg", "julia"},
		{"carthage", "carthage"},
		{"elm", "elm"},
		{"dub", "dub"},
		{"haxelib", "haxelib"},
		{"nix", "nix"},
	} {
		t.Run(tt.manager, func(t *testing.T) {
			got, err := detectEcosystem(tt.manager)
			if err != nil || got != tt.ecosystem {
				t.Fatalf("detectEcosystem(%q) = %q, %v; want %q", tt.manager, got, err, tt.ecosystem)
			}
		})
	}
	for _, manager := range []string{"helm", "brew", "gem", "rebar3", "pip"} {
		t.Run(manager, func(t *testing.T) {
			if got, err := detectEcosystem(manager); err == nil {
				t.Fatalf("detectEcosystem(%q) = %q; want unknown manager error", manager, got)
			}
		})
	}
}
