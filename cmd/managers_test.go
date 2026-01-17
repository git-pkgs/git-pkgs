package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestDetectManagers(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		expected []string
	}{
		{
			name: "npm from package-lock.json",
			files: map[string]string{
				"package.json":      `{"name": "test"}`,
				"package-lock.json": `{"lockfileVersion": 3}`,
			},
			expected: []string{"npm"},
		},
		{
			name: "pnpm from pnpm-lock.yaml",
			files: map[string]string{
				"package.json":   `{"name": "test"}`,
				"pnpm-lock.yaml": "lockfileVersion: 6.0",
			},
			expected: []string{"pnpm"},
		},
		{
			name: "yarn from yarn.lock",
			files: map[string]string{
				"package.json": `{"name": "test"}`,
				"yarn.lock":    "# yarn lockfile v1",
			},
			expected: []string{"yarn"},
		},
		{
			name: "bun from bun.lock",
			files: map[string]string{
				"package.json": `{"name": "test"}`,
				"bun.lock":     "{}",
			},
			expected: []string{"bun"},
		},
		{
			name: "bundler from Gemfile.lock",
			files: map[string]string{
				"Gemfile":      "source 'https://rubygems.org'",
				"Gemfile.lock": "GEM\n  remote: https://rubygems.org/",
			},
			expected: []string{"bundler"},
		},
		{
			name: "cargo from Cargo.lock",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"test\"",
				"Cargo.lock": "[[package]]\nname = \"test\"",
			},
			expected: []string{"cargo"},
		},
		{
			name: "gomod from go.sum",
			files: map[string]string{
				"go.mod": "module test",
				"go.sum": "",
			},
			expected: []string{"gomod"},
		},
		{
			name: "multiple ecosystems",
			files: map[string]string{
				"Gemfile":           "source 'https://rubygems.org'",
				"Gemfile.lock":      "GEM",
				"package.json":      `{"name": "test"}`,
				"package-lock.json": `{}`,
			},
			expected: []string{"npm", "bundler"},
		},
		{
			name: "pnpm first when both npm lockfiles present",
			files: map[string]string{
				"package.json":      `{"name": "test"}`,
				"package-lock.json": `{}`,
				"pnpm-lock.yaml":    "lockfileVersion: 6.0",
			},
			expected: []string{"pnpm"}, // only highest priority npm lockfile used
		},
		// Manifest-only fallback tests
		{
			name: "npm from package.json only (no lockfile)",
			files: map[string]string{
				"package.json": `{"name": "test"}`,
			},
			expected: []string{"npm"},
		},
		{
			name: "bundler from Gemfile only (no lockfile)",
			files: map[string]string{
				"Gemfile": "source 'https://rubygems.org'",
			},
			expected: []string{"bundler"},
		},
		{
			name: "cargo from Cargo.toml only (no lockfile)",
			files: map[string]string{
				"Cargo.toml": "[package]",
			},
			expected: []string{"cargo"},
		},
		{
			name: "gomod from go.mod only (no go.sum)",
			files: map[string]string{
				"go.mod": "module test",
			},
			expected: []string{"gomod"},
		},
		{
			name: "lockfile takes precedence over manifest default",
			files: map[string]string{
				"package.json":   `{"name": "test"}`,
				"pnpm-lock.yaml": "lockfileVersion: 6.0",
			},
			expected: []string{"pnpm"}, // pnpm from lockfile, not npm default
		},
		// Additional ecosystem tests
		{
			name: "maven from pom.xml",
			files: map[string]string{
				"pom.xml": "<project></project>",
			},
			expected: []string{"maven"},
		},
		{
			name: "nuget from packages.lock.json",
			files: map[string]string{
				"packages.config":   "<packages></packages>",
				"packages.lock.json": "{}",
			},
			expected: []string{"nuget"},
		},
		{
			name: "swift from Package.resolved",
			files: map[string]string{
				"Package.swift":    "// swift-tools-version:5.5",
				"Package.resolved": "{}",
			},
			expected: []string{"swift"},
		},
		{
			name: "deno from deno.lock",
			files: map[string]string{
				"deno.json": "{}",
				"deno.lock": "{}",
			},
			expected: []string{"deno"},
		},
		{
			name: "crystal from shard.lock",
			files: map[string]string{
				"shard.yml":  "name: test",
				"shard.lock": "version: 2.0",
			},
			expected: []string{"shards"},
		},
		{
			name: "julia from Manifest.toml",
			files: map[string]string{
				"Project.toml":  "[deps]",
				"Manifest.toml": "[[deps]]",
			},
			expected: []string{"pkg"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			for name, content := range tt.files {
				path := filepath.Join(tmpDir, name)
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("failed to write %s: %v", name, err)
				}
			}

			detected, err := cmd.DetectManagers(tmpDir)
			if err != nil {
				t.Fatalf("DetectManagers failed: %v", err)
			}

			var names []string
			for _, d := range detected {
				names = append(names, d.Name)
			}

			if len(names) != len(tt.expected) {
				t.Errorf("expected %d managers %v, got %d: %v", len(tt.expected), tt.expected, len(names), names)
				return
			}

			for _, exp := range tt.expected {
				found := false
				for _, name := range names {
					if name == exp {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected manager %s not found in %v", exp, names)
				}
			}
		})
	}
}

// writeManifestForLockfile creates the corresponding manifest file for a lockfile
func writeManifestForLockfile(t *testing.T, tmpDir, lockfile string) {
	t.Helper()
	switch lockfile {
	case "Gemfile.lock":
		if err := os.WriteFile(filepath.Join(tmpDir, "Gemfile"), []byte("source 'https://rubygems.org'"), 0644); err != nil {
			t.Fatalf("failed to write Gemfile: %v", err)
		}
	case "Cargo.lock":
		if err := os.WriteFile(filepath.Join(tmpDir, "Cargo.toml"), []byte("[package]"), 0644); err != nil {
			t.Fatalf("failed to write Cargo.toml: %v", err)
		}
	case "go.sum":
		if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module test"), 0644); err != nil {
			t.Fatalf("failed to write go.mod: %v", err)
		}
	}
}

func TestInstallDryRun(t *testing.T) {
	tests := []struct {
		name           string
		lockfile       string
		lockContent    string
		flags          []string
		expectedOutput string
	}{
		{
			name:           "npm install",
			lockfile:       "package-lock.json",
			lockContent:    `{"lockfileVersion": 3}`,
			flags:          []string{},
			expectedOutput: "[npm install]",
		},
		{
			name:           "npm ci with frozen flag",
			lockfile:       "package-lock.json",
			lockContent:    `{"lockfileVersion": 3}`,
			flags:          []string{"--frozen"},
			expectedOutput: "[npm ci]",
		},
		{
			name:           "bundler install",
			lockfile:       "Gemfile.lock",
			lockContent:    "GEM",
			flags:          []string{},
			expectedOutput: "[bundle install]",
		},
		{
			name:           "bundler frozen",
			lockfile:       "Gemfile.lock",
			lockContent:    "GEM",
			flags:          []string{"--frozen"},
			expectedOutput: "[bundle install --frozen]",
		},
		{
			name:           "cargo fetch",
			lockfile:       "Cargo.lock",
			lockContent:    "[[package]]",
			flags:          []string{},
			expectedOutput: "[cargo fetch]",
		},
		{
			name:           "go mod download",
			lockfile:       "go.sum",
			lockContent:    "",
			flags:          []string{},
			expectedOutput: "[go mod download]",
		},
		{
			name:           "extra args passed through",
			lockfile:       "package-lock.json",
			lockContent:    `{}`,
			flags:          []string{"-x", "--legacy-peer-deps"},
			expectedOutput: "--legacy-peer-deps",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create lockfile
			if err := os.WriteFile(filepath.Join(tmpDir, tt.lockfile), []byte(tt.lockContent), 0644); err != nil {
				t.Fatalf("failed to write lockfile: %v", err)
			}

			// Also create manifest for some managers
			writeManifestForLockfile(t, tmpDir, tt.lockfile)

			cleanup := chdir(t, tmpDir)
			defer cleanup()

			rootCmd := cmd.NewRootCmd()
			args := append([]string{"install", "--dry-run"}, tt.flags...)
			rootCmd.SetArgs(args)

			var stdout bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stdout)

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("install --dry-run failed: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.expectedOutput, output)
			}
		})
	}
}

func TestAddDryRun(t *testing.T) {
	tests := []struct {
		name           string
		lockfile       string
		args           []string
		expectedOutput string
	}{
		{
			name:           "npm add package",
			lockfile:       "package-lock.json",
			args:           []string{"lodash"},
			expectedOutput: "[npm install lodash]",
		},
		{
			name:           "npm add dev package",
			lockfile:       "package-lock.json",
			args:           []string{"lodash", "--dev"},
			expectedOutput: "--save-dev",
		},
		{
			name:           "bundler add package",
			lockfile:       "Gemfile.lock",
			args:           []string{"rails"},
			expectedOutput: "[bundle add rails]",
		},
		{
			name:           "bundler add dev package",
			lockfile:       "Gemfile.lock",
			args:           []string{"rspec", "--dev"},
			expectedOutput: "--group",
		},
		{
			name:           "cargo add package",
			lockfile:       "Cargo.lock",
			args:           []string{"serde"},
			expectedOutput: "[cargo add serde]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := os.WriteFile(filepath.Join(tmpDir, tt.lockfile), []byte("{}"), 0644); err != nil {
				t.Fatalf("failed to write lockfile: %v", err)
			}

			// Create manifest files
			writeManifestForLockfile(t, tmpDir, tt.lockfile)

			cleanup := chdir(t, tmpDir)
			defer cleanup()

			rootCmd := cmd.NewRootCmd()
			args := append([]string{"add", "--dry-run"}, tt.args...)
			rootCmd.SetArgs(args)

			var stdout bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stdout)

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("add --dry-run failed: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.expectedOutput, output)
			}
		})
	}
}

func TestRemoveDryRun(t *testing.T) {
	tests := []struct {
		name           string
		lockfile       string
		pkg            string
		expectedOutput string
	}{
		{
			name:           "npm remove",
			lockfile:       "package-lock.json",
			pkg:            "lodash",
			expectedOutput: "[npm uninstall lodash]",
		},
		{
			name:           "bundler remove",
			lockfile:       "Gemfile.lock",
			pkg:            "rails",
			expectedOutput: "[bundle remove rails]",
		},
		{
			name:           "cargo remove",
			lockfile:       "Cargo.lock",
			pkg:            "serde",
			expectedOutput: "[cargo remove serde]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := os.WriteFile(filepath.Join(tmpDir, tt.lockfile), []byte("{}"), 0644); err != nil {
				t.Fatalf("failed to write lockfile: %v", err)
			}

			writeManifestForLockfile(t, tmpDir, tt.lockfile)

			cleanup := chdir(t, tmpDir)
			defer cleanup()

			rootCmd := cmd.NewRootCmd()
			rootCmd.SetArgs([]string{"remove", "--dry-run", tt.pkg})

			var stdout bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stdout)

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("remove --dry-run failed: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.expectedOutput, output)
			}
		})
	}
}

func TestUpdateDryRun(t *testing.T) {
	tests := []struct {
		name           string
		lockfile       string
		args           []string
		expectedOutput string
	}{
		{
			name:           "npm update all",
			lockfile:       "package-lock.json",
			args:           []string{},
			expectedOutput: "[npm update]",
		},
		{
			name:           "npm update package",
			lockfile:       "package-lock.json",
			args:           []string{"lodash"},
			expectedOutput: "[npm update lodash]",
		},
		{
			name:           "bundler update all",
			lockfile:       "Gemfile.lock",
			args:           []string{},
			expectedOutput: "[bundle update]",
		},
		{
			name:           "bundler update package",
			lockfile:       "Gemfile.lock",
			args:           []string{"rails"},
			expectedOutput: "[bundle update rails]",
		},
		{
			name:           "go update all",
			lockfile:       "go.sum",
			args:           []string{},
			expectedOutput: "[go get -u]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if err := os.WriteFile(filepath.Join(tmpDir, tt.lockfile), []byte("{}"), 0644); err != nil {
				t.Fatalf("failed to write lockfile: %v", err)
			}

			writeManifestForLockfile(t, tmpDir, tt.lockfile)

			cleanup := chdir(t, tmpDir)
			defer cleanup()

			rootCmd := cmd.NewRootCmd()
			args := append([]string{"update", "--dry-run"}, tt.args...)
			rootCmd.SetArgs(args)

			var stdout bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stdout)

			err := rootCmd.Execute()
			if err != nil {
				t.Fatalf("update --dry-run failed: %v", err)
			}

			output := stdout.String()
			if !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.expectedOutput, output)
			}
		})
	}
}

func TestManagerOverride(t *testing.T) {
	tmpDir := t.TempDir()

	// Create npm lockfile but override to pnpm
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"install", "--dry-run", "-m", "pnpm"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("install --dry-run failed: %v", err)
	}

	output := stdout.String()
	if !strings.Contains(output, "pnpm install") {
		t.Errorf("expected pnpm install, got:\n%s", output)
	}
}

func TestNoManagerDetected(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty directory, no lockfiles
	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"install", "--dry-run"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no manager detected")
	}

	if !strings.Contains(err.Error(), "no package manager detected") {
		t.Errorf("expected 'no package manager detected' error, got: %v", err)
	}
}

func TestPromptForManager(t *testing.T) {
	tests := []struct {
		name        string
		detected    []cmd.DetectedManager
		input       string
		wantName    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "single manager returns without prompting",
			detected: []cmd.DetectedManager{{Name: "npm", Lockfile: "package-lock.json"}},
			input:    "",
			wantName: "npm",
		},
		{
			name: "valid selection",
			detected: []cmd.DetectedManager{
				{Name: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Lockfile: "Gemfile.lock"},
			},
			input:    "2\n",
			wantName: "bundler",
		},
		{
			name: "first selection",
			detected: []cmd.DetectedManager{
				{Name: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Lockfile: "Gemfile.lock"},
			},
			input:    "1\n",
			wantName: "npm",
		},
		{
			name: "invalid selection - too high",
			detected: []cmd.DetectedManager{
				{Name: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Lockfile: "Gemfile.lock"},
			},
			input:       "3\n",
			wantErr:     true,
			errContains: "invalid selection",
		},
		{
			name: "invalid selection - zero",
			detected: []cmd.DetectedManager{
				{Name: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Lockfile: "Gemfile.lock"},
			},
			input:       "0\n",
			wantErr:     true,
			errContains: "invalid selection",
		},
		{
			name: "invalid selection - not a number",
			detected: []cmd.DetectedManager{
				{Name: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Lockfile: "Gemfile.lock"},
			},
			input:       "abc\n",
			wantErr:     true,
			errContains: "invalid selection",
		},
		{
			name:        "no managers detected",
			detected:    []cmd.DetectedManager{},
			input:       "",
			wantErr:     true,
			errContains: "no package manager detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			in := strings.NewReader(tt.input)

			mgr, err := cmd.PromptForManager(tt.detected, &out, in)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got: %v", tt.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if mgr.Name != tt.wantName {
				t.Errorf("expected manager %q, got %q", tt.wantName, mgr.Name)
			}
		})
	}
}

func TestPromptForManagerOutput(t *testing.T) {
	detected := []cmd.DetectedManager{
		{Name: "npm", Lockfile: "package-lock.json"},
		{Name: "bundler", Lockfile: "Gemfile.lock"},
	}

	var out bytes.Buffer
	in := strings.NewReader("1\n")

	_, err := cmd.PromptForManager(detected, &out, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Multiple package managers detected") {
		t.Error("expected prompt header in output")
	}
	if !strings.Contains(output, "[1] npm (package-lock.json)") {
		t.Error("expected npm option in output")
	}
	if !strings.Contains(output, "[2] bundler (Gemfile.lock)") {
		t.Error("expected bundler option in output")
	}
	if !strings.Contains(output, "Select [1-2]:") {
		t.Error("expected selection prompt in output")
	}
}
