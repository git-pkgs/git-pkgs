package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestDiffDriver(t *testing.T) {
	t.Run("sorts by name and version", func(t *testing.T) {
		// A minimal Gemfile.lock with duplicate gem names at different versions.
		// This exercises the sort order used by convertLockfile.
		lockContent := `GEM
  remote: https://rubygems.org/
  specs:
    aws-sdk (3.370.0)
    aws-sdk (3.973.1)
    aws-sdk (3.370.0)
    foo (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  aws-sdk
  foo

BUNDLED WITH
   2.4.0
`
		tmpDir := t.TempDir()
		lockPath := filepath.Join(tmpDir, "Gemfile.lock")
		if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
			t.Fatal(err)
		}

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff-driver", lockPath})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff-driver failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")

		// Versions of the same package should appear in sorted order
		var awsLines []string
		for _, line := range lines {
			if strings.HasPrefix(line, "aws-sdk ") {
				awsLines = append(awsLines, line)
			}
		}

		if len(awsLines) < 2 {
			t.Fatalf("expected at least 2 aws-sdk lines, got %d: %v", len(awsLines), lines)
		}

		for i := 1; i < len(awsLines); i++ {
			if awsLines[i-1] > awsLines[i] {
				t.Errorf("lines not sorted: %q came before %q", awsLines[i-1], awsLines[i])
			}
		}
	})

	t.Run("sorts by scope when name and version match", func(t *testing.T) {
		// A Pipfile.lock can list the same package at the same version in both
		// the default and develop sections. The parser emits two entries that
		// differ only in scope; without scope in the sort key the relative
		// order of those lines is non-deterministic (#217).
		lockContent := `{
  "_meta": {"hash": {"sha256": ""}, "pipfile-spec": 6},
  "default": {
    "alpha":   {"version": "==1.0.0"},
    "bravo":   {"version": "==1.0.0"},
    "charlie": {"version": "==1.0.0"},
    "delta":   {"version": "==1.0.0"},
    "echo":    {"version": "==1.0.0"},
    "foxtrot": {"version": "==1.0.0"}
  },
  "develop": {
    "alpha":   {"version": "==1.0.0"},
    "bravo":   {"version": "==1.0.0"},
    "charlie": {"version": "==1.0.0"},
    "delta":   {"version": "==1.0.0"},
    "echo":    {"version": "==1.0.0"},
    "foxtrot": {"version": "==1.0.0"}
  }
}`
		tmpDir := t.TempDir()
		lockPath := filepath.Join(tmpDir, "Pipfile.lock")
		if err := os.WriteFile(lockPath, []byte(lockContent), 0644); err != nil {
			t.Fatal(err)
		}

		var stdout bytes.Buffer
		rootCmd := cmd.NewRootCmd()
		rootCmd.SetArgs([]string{"diff-driver", lockPath})
		rootCmd.SetOut(&stdout)

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("diff-driver failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if len(lines) != 12 {
			t.Fatalf("expected 12 lines, got %d:\n%s", len(lines), stdout.String())
		}
		for i := 1; i < len(lines); i++ {
			if lines[i-1] > lines[i] {
				t.Errorf("lines not sorted: %q came before %q", lines[i-1], lines[i])
			}
		}
	})
}
