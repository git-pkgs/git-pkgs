package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestSortedUniqueLicenses(t *testing.T) {
	got := sortedUniqueLicenses([]string{
		" MIT ",
		"MIT License",
		"Apache 2.0",
		"Apache-2.0",
		"Custom License",
		" Custom License ",
		"",
		"   ",
	})
	want := []string{"Apache-2.0", "Custom License", "MIT"}
	if !slices.Equal(got, want) {
		t.Fatalf("sortedUniqueLicenses() = %q, want %q", got, want)
	}
}

func TestFormatDeclaredLicensesSanitizesControlCharacters(t *testing.T) {
	got := formatDeclaredLicenses([]string{"MIT\x1b[31m", "Custom\x00License"})
	want := "MIT[31m, CustomLicense"
	if got != want {
		t.Fatalf("formatDeclaredLicenses() = %q, want %q", got, want)
	}
}

func TestParseFileUsesDependencyEcosystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deno.json")
	content := `{"imports": {"chalk": "npm:chalk@5.3.0", "path": "jsr:@std/path@^1.0.0"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	parsed, err := parseFile(path, "")
	if err != nil {
		t.Fatalf("parseFile: %v", err)
	}
	got := make(map[string]string)
	for _, dep := range parsed.Dependencies {
		got[dep.Name] = dep.Ecosystem
	}
	want := map[string]string{"chalk": "npm", "@std/path": "deno"}
	if len(got) != len(want) || got["chalk"] != want["chalk"] || got["@std/path"] != want["@std/path"] {
		t.Fatalf("ecosystems = %v, want %v", got, want)
	}
}
