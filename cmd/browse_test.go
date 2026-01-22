package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestBrowseNoPackageArg(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no package argument provided")
	}
}

func TestBrowseNoManagerDetected(t *testing.T) {
	tmpDir := t.TempDir()

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse", "lodash"})

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

func TestBrowseManagerOverride(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a project with no lockfile but override manager
	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	// Use a manager that doesn't require lockfile detection, use --path to avoid editor
	rootCmd.SetArgs([]string{"browse", "lodash", "-m", "npm", "--path"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	// This will fail because npm isn't installed or lodash isn't installed,
	// but it should get past manager detection
	err := rootCmd.Execute()
	if err == nil {
		// If it succeeds, that's fine too (npm and lodash might be installed)
		return
	}

	// Should not be a manager detection error
	if strings.Contains(err.Error(), "no package manager detected") {
		t.Errorf("manager override should bypass detection, got: %v", err)
	}
}

func TestBrowseEcosystemFilter(t *testing.T) {
	tmpDir := t.TempDir()

	// Create npm and bundler lockfiles
	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "Gemfile"), []byte("source 'https://rubygems.org'"), 0644); err != nil {
		t.Fatalf("failed to write Gemfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "Gemfile.lock"), []byte("GEM"), 0644); err != nil {
		t.Fatalf("failed to write Gemfile.lock: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse", "rails", "-e", "rubygems", "--path"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	// This will likely fail because bundler/rails isn't installed,
	// but it should filter to bundler correctly
	err := rootCmd.Execute()
	if err == nil {
		return // success
	}

	// Error should be about path lookup, not manager detection
	if strings.Contains(err.Error(), "no package manager detected") {
		t.Errorf("ecosystem filter should select bundler, got: %v", err)
	}
}

func TestBrowseInvalidEcosystem(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse", "lodash", "-e", "invalid"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for invalid ecosystem")
	}

	if !strings.Contains(err.Error(), "no invalid package manager detected") {
		t.Errorf("expected ecosystem not found error, got: %v", err)
	}
}

func TestBrowsePathNotSupported(t *testing.T) {
	tmpDir := t.TempDir()

	// maven doesn't support path operation
	if err := os.WriteFile(filepath.Join(tmpDir, "pom.xml"), []byte("<project></project>"), 0644); err != nil {
		t.Fatalf("failed to write pom.xml: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse", "junit", "-m", "maven", "--path"})

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error for unsupported path operation")
	}

	if !strings.Contains(err.Error(), "does not support the path operation") {
		t.Errorf("expected path not supported error, got: %v", err)
	}
}

func TestBrowseNoEditor(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write lockfile: %v", err)
	}

	// Create a fake node_modules/lodash directory so path lookup succeeds
	lodashDir := filepath.Join(tmpDir, "node_modules", "lodash")
	if err := os.MkdirAll(lodashDir, 0755); err != nil {
		t.Fatalf("failed to create node_modules: %v", err)
	}

	cleanup := chdir(t, tmpDir)
	defer cleanup()

	// Unset EDITOR and VISUAL
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", "")

	rootCmd := cmd.NewRootCmd()
	rootCmd.SetArgs([]string{"browse", "lodash", "-m", "yarn"}) // yarn uses template, no CLI needed

	var stdout bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stdout)

	err := rootCmd.Execute()
	if err == nil {
		t.Error("expected error when no editor configured")
	}

	if !strings.Contains(err.Error(), "no editor configured") {
		t.Errorf("expected 'no editor configured' error, got: %v", err)
	}
}
