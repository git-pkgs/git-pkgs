package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEcosystems(t *testing.T) {
	t.Run("text output includes header and known ecosystems", func(t *testing.T) {
		var buf bytes.Buffer
		rootCmd := NewRootCmd()
		rootCmd.SetArgs([]string{"ecosystems"})
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&bytes.Buffer{})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("ecosystems command failed: %v", err)
		}

		output := buf.String()
		for _, want := range []string{"Ecosystem", "Manifest", "Lockfiles", "Managers", "Registry", "npm", "package.json"} {
			if !strings.Contains(output, want) {
				t.Errorf("expected %q in output, got:\n%s", want, output)
			}
		}
	})

	t.Run("json output is valid and contains ecosystems", func(t *testing.T) {
		var buf bytes.Buffer
		rootCmd := NewRootCmd()
		rootCmd.SetArgs([]string{"ecosystems", "-f", "json"})
		rootCmd.SetOut(&buf)
		rootCmd.SetErr(&bytes.Buffer{})

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("ecosystems -f json failed: %v", err)
		}

		var details []EcosystemDetail
		if err := json.Unmarshal(buf.Bytes(), &details); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
		}

		if len(details) == 0 {
			t.Fatal("expected at least one ecosystem")
		}

		// Check that npm is present with expected fields
		var found bool
		for _, d := range details {
			if d.Name == "npm" {
				found = true
				if d.Manifest != "package.json" {
					t.Errorf("npm manifest = %q, want package.json", d.Manifest)
				}
				if len(d.Lockfiles) == 0 {
					t.Error("npm should have lockfiles")
				}
				if len(d.Managers) == 0 {
					t.Error("npm should have managers")
				}
				break
			}
		}
		if !found {
			t.Error("npm ecosystem not found in output")
		}
	})
}

func TestBuildEcosystemDetails(t *testing.T) {
	details := buildEcosystemDetails()

	if len(details) == 0 {
		t.Fatal("expected at least one ecosystem detail")
	}

	// Check no duplicates
	seen := make(map[string]bool)
	for _, d := range details {
		if seen[d.Name] {
			t.Errorf("duplicate ecosystem: %s", d.Name)
		}
		seen[d.Name] = true
	}
}
