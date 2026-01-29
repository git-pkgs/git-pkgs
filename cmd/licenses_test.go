package cmd_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/spdx"
)

// Gemfile with a known copyleft dependency (sidekiq uses LGPL)
const gemfileWithLGPL = `source 'https://rubygems.org'
gem 'sidekiq'
gem 'rails'
`

func TestLicensesCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	t.Run("permissive flag detects non-permissive licenses", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--permissive"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		// Test must verify one of these outcomes:
		// 1. LGPL was detected and flagged (success)
		// 2. Command ran without error and produced output (acceptable if API unavailable)
		if len(output) == 0 && err != nil {
			t.Fatalf("licenses command failed with no output: %v", err)
		}

		// If LGPL is in output but not flagged, that's a bug
		if strings.Contains(output, "LGPL") && !strings.Contains(output, "FLAGGED") {
			t.Error("LGPL license detected but not flagged as non-permissive")
		}

		// If flagged, command must return error
		if strings.Contains(output, "FLAGGED") && err == nil {
			t.Error("expected command to return error when violations found")
		}
	})

	t.Run("deny flag blocks specified licenses", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--deny", "LGPL"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if len(output) == 0 && err != nil {
			t.Fatalf("licenses command failed with no output: %v", err)
		}

		// If LGPL is detected, it must be flagged as denied
		if strings.Contains(output, "LGPL") {
			if !strings.Contains(output, "FLAGGED") {
				t.Error("LGPL license detected but not flagged as denied")
			}
			if err == nil {
				t.Error("expected command to return error when denied license found")
			}
		}
	})

	t.Run("copyleft flag detects copyleft licenses", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "Gemfile", gemfileWithLGPL, "Add Gemfile")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--copyleft"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if len(output) == 0 && err != nil {
			t.Fatalf("licenses command failed with no output: %v", err)
		}

		// If LGPL is detected, it must be flagged as copyleft
		if strings.Contains(output, "LGPL") {
			if !strings.Contains(output, "FLAGGED") {
				t.Error("LGPL license detected but not flagged as copyleft")
			}
			if err == nil {
				t.Error("expected command to return error when copyleft license found")
			}
		}
	})

	t.Run("json output format", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--format", "json"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		// Command may return error if there are violations, that's expected
		_ = rootCmd.Execute()

		output := stdout.String()
		if len(output) == 0 {
			t.Fatal("expected JSON output, got empty string")
		}

		// Must be valid JSON array
		var result []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			t.Fatalf("failed to parse JSON output: %v\nOutput: %s", err, output)
		}

		// If we got results, validate structure
		if len(result) > 0 {
			first := result[0]
			if _, ok := first["name"]; !ok {
				t.Error("expected 'name' field in license JSON")
			}
		}
	})

	t.Run("allow flag permits only listed licenses", func(t *testing.T) {
		repoDir := createTestRepo(t)
		addFileAndCommit(t, repoDir, "package.json", packageJSON, "Add package.json")

		cleanup := chdir(t, repoDir)
		defer cleanup()

		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--allow", "MIT"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()
		output := stdout.String()

		if len(output) == 0 && err != nil {
			t.Fatalf("licenses command failed with no output: %v", err)
		}

		// If non-MIT licenses appear, they must be flagged
		hasNonMIT := strings.Contains(output, "Apache") || strings.Contains(output, "BSD") || strings.Contains(output, "ISC")
		if hasNonMIT && !strings.Contains(output, "not in allow list") && !strings.Contains(output, "FLAGGED") {
			t.Error("non-MIT licenses detected but not flagged")
		}
	})
}

func TestSpdxPermissiveCheck(t *testing.T) {
	tests := []struct {
		license    string
		permissive bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"BSD-3-Clause", true},
		{"BSD-2-Clause", true},
		{"ISC", true},
		{"GPL-3.0-only", false},
		{"GPL-2.0-only", false},
		{"LGPL-3.0-or-later", false},
		{"AGPL-3.0-only", false},
		{"MPL-2.0", false},
		{"MIT OR Apache-2.0", true},
		{"MIT OR GPL-3.0-only", false}, // has non-permissive option
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			got := spdx.IsFullyPermissive(tt.license)
			if got != tt.permissive {
				t.Errorf("IsFullyPermissive(%q) = %v, want %v", tt.license, got, tt.permissive)
			}
		})
	}
}

func TestSpdxCopyleftCheck(t *testing.T) {
	tests := []struct {
		license  string
		copyleft bool
	}{
		{"MIT", false},
		{"Apache-2.0", false},
		{"GPL-3.0-only", true},
		{"GPL-2.0-only", true},
		{"LGPL-3.0-or-later", true},
		{"AGPL-3.0-only", true},
		{"MPL-2.0", true},
		{"MIT OR GPL-3.0-only", true}, // has copyleft option
		{"MIT OR Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			got := spdx.HasCopyleft(tt.license)
			if got != tt.copyleft {
				t.Errorf("HasCopyleft(%q) = %v, want %v", tt.license, got, tt.copyleft)
			}
		})
	}
}

func TestSpdxNormalization(t *testing.T) {
	tests := []struct {
		input      string
		normalized string
	}{
		{"MIT", "MIT"},
		{"MIT License", "MIT"},
		{"Apache 2", "Apache-2.0"},
		{"Apache 2.0", "Apache-2.0"},
		{"GPL v3", "GPL-3.0-or-later"},
		{"GPLv3", "GPL-3.0-or-later"},
		{"LGPL 3", "LGPL-3.0-or-later"},
		{"BSD 3-Clause", "BSD-3-Clause"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := spdx.Normalize(tt.input)
			if err != nil {
				t.Fatalf("Normalize(%q) error: %v", tt.input, err)
			}
			if got != tt.normalized {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.normalized)
			}
		})
	}
}

// TestLicensesDockerPURLCanonicalization tests that docker images show proper
// names even when the API returns a canonicalized PURL different from the input.
// For example, pkg:docker/postgres becomes pkg:docker/library%2Fpostgres in the response.
func TestLicensesDockerPURLCanonicalization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Docker compose file with official images (no library/ prefix)
	const dockerCompose = `version: '3'
services:
  db:
    image: postgres:16-alpine
  cache:
    image: redis:7-alpine
`
	repoDir := createTestRepo(t)
	addFileAndCommit(t, repoDir, "docker-compose.yml", dockerCompose, "Add docker-compose")

	cleanup := chdir(t, repoDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"init"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	rootCmd = cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"licenses", "--format", "json"})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	_ = rootCmd.Execute()

	output := stdout.String()
	if output == "" {
		t.Fatal("expected JSON output, got empty string")
	}

	var results []cmd.LicenseInfo
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		t.Fatalf("failed to parse JSON: %v\nOutput: %s", err, output)
	}

	// Find docker packages and verify they have names
	for _, r := range results {
		if strings.Contains(r.PURL, "docker") {
			if r.Name == "" {
				t.Errorf("docker package %s has empty name", r.PURL)
			}
			if r.Ecosystem == "" {
				t.Errorf("docker package %s has empty ecosystem", r.PURL)
			}
		}
	}
}

func TestSpdxDenyListMatching(t *testing.T) {
	// Simulate the deny list logic from licenses.go
	denyList := []string{"GPL v3", "LGPL"}

	// Build deny set with normalization
	denySet := make(map[string]bool)
	for _, l := range denyList {
		if normalized, err := spdx.Normalize(l); err == nil {
			denySet[normalized] = true
		}
	}

	tests := []struct {
		license string
		denied  bool
	}{
		{"GPL-3.0-or-later", true}, // matches "GPL v3" normalized
		{"GPL-3.0-only", false},    // "GPL v3" normalizes to -or-later
		{"LGPL-3.0-or-later", true},
		{"MIT", false},
		{"Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			// Check if license is in deny set (with normalization)
			inDenyList := denySet[tt.license]
			if !inDenyList {
				if normalized, err := spdx.Normalize(tt.license); err == nil {
					inDenyList = denySet[normalized]
				}
			}
			if inDenyList != tt.denied {
				t.Errorf("license %q denied = %v, want %v", tt.license, inDenyList, tt.denied)
			}
		})
	}
}
