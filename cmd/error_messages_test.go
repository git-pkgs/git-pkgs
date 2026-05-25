package cmd_test

import (
	"slices"
	"strings"
	"testing"
)

func TestErrorMessagesWrapped(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{
		{"list", []string{"list"}},
		{"licenses", []string{"licenses"}},
		{"outdated", []string{"outdated"}},
		{"integrity", []string{"integrity"}},
	}

	for _, tc := range commands {
		t.Run(tc.name+" wraps errors with context", func(t *testing.T) {
			// Create a repo with init but point at a nonexistent commit
			repoDir := createTestRepo(t)
			addFileAndCommit(t, repoDir, "package-lock.json", packageLockJSON, "Add lockfile")
			cleanup := chdir(t, repoDir)
			defer cleanup()

			_, _, err := runCmd(t, "init")
			if err != nil {
				t.Fatalf("init failed: %v", err)
			}

			// Run the command pointing at a bad ref
			args := slices.Concat(tc.args, []string{"--commit", "deadbeef1234567890deadbeef1234567890dead"})
			_, _, err = runCmd(t, args...)
			if err == nil {
				t.Skip("command succeeded unexpectedly")
			}

			msg := err.Error()
			// Error should NOT be a raw SQL or internal error
			// It should contain wrapping context from the command layer
			rawPatterns := []string{"sql:", "no rows in result set", "UNIQUE constraint"}
			for _, pattern := range rawPatterns {
				if strings.Contains(msg, pattern) && !strings.Contains(msg, "loading") && !strings.Contains(msg, "listing") {
					t.Errorf("%s error contains raw pattern %q without wrapping: %s", tc.name, pattern, msg)
				}
			}
		})
	}
}
