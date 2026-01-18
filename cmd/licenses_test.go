package cmd_test

import (
	"bytes"
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

		// Initialize database
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"init"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Run licenses --permissive (should fail due to LGPL)
		var stdout, stderr bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--permissive"})
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)

		err := rootCmd.Execute()

		output := stdout.String()

		// Should contain flagged output for non-permissive license
		if !strings.Contains(output, "FLAGGED") && !strings.Contains(output, "not permissive") {
			// If sidekiq's LGPL license was fetched, it should be flagged
			// But if API call failed or returned unknown, check for that
			if strings.Contains(output, "sidekiq") {
				t.Logf("Output: %s", output)
				// Only fail if we got license data but didn't flag it
				if strings.Contains(output, "LGPL") && !strings.Contains(output, "FLAGGED") {
					t.Error("expected LGPL license to be flagged as not permissive")
				}
			}
		}

		// If there are violations, command should return error
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

		// Run licenses --deny LGPL
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--deny", "LGPL"})
		rootCmd.SetOut(&stdout)

		err := rootCmd.Execute()
		output := stdout.String()

		// If sidekiq was found with LGPL, it should be denied
		if strings.Contains(output, "LGPL") {
			if !strings.Contains(output, "FLAGGED") || !strings.Contains(output, "denied") {
				t.Error("expected LGPL license to be flagged as denied")
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

		// Run licenses --copyleft
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--copyleft"})
		rootCmd.SetOut(&stdout)

		err := rootCmd.Execute()
		output := stdout.String()

		// If sidekiq was found with LGPL, it should be flagged as copyleft
		if strings.Contains(output, "LGPL") {
			if !strings.Contains(output, "FLAGGED") || !strings.Contains(output, "copyleft") {
				t.Error("expected LGPL license to be flagged as copyleft")
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

		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--format", "json"})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			// May fail if API returns violations, that's ok
			t.Logf("command returned error (may be expected): %v", err)
		}

		output := stdout.String()
		// Should be valid JSON array
		if !strings.HasPrefix(strings.TrimSpace(output), "[") {
			t.Errorf("expected JSON array output, got: %s", output[:min(100, len(output))])
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

		// Only allow MIT - anything else should be flagged
		var stdout bytes.Buffer
		rootCmd = cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"licenses", "--allow", "MIT"})
		rootCmd.SetOut(&stdout)

		_ = rootCmd.Execute()
		output := stdout.String()

		// If we got any non-MIT licenses, they should be flagged
		if strings.Contains(output, "Apache") || strings.Contains(output, "BSD") {
			if !strings.Contains(output, "not in allow list") {
				t.Error("expected non-MIT licenses to be flagged as not in allow list")
			}
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
