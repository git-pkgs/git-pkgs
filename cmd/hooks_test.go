package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestDoUninstallHooks_AppendedLines(t *testing.T) {
	// Simulate a hook file where git-pkgs lines were appended to an existing hook
	existingContent := `#!/bin/bash
echo "my custom hook"
do_something

# git-pkgs hook
git pkgs reindex --quiet 2>/dev/null || true
`

	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}

	hookPath := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(hookPath, []byte(existingContent), 0755); err != nil {
		t.Fatal(err)
	}

	overrideHooks(t, hook{name: "post-commit", body: guardedHookBody})

	rootCmd := newTestCommand()
	if err := doUninstallHooks(rootCmd, hooksDir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading hook: %v", err)
	}

	result := string(content)
	if strings.Contains(result, "git-pkgs") {
		t.Errorf("expected git-pkgs lines to be removed, got:\n%s", result)
	}
	if strings.Contains(result, "git pkgs reindex") {
		t.Errorf("expected reindex line to be removed, got:\n%s", result)
	}
	if !strings.Contains(result, "my custom hook") {
		t.Error("expected original hook content to be preserved")
	}
	if !strings.Contains(result, "do_something") {
		t.Error("expected original hook content to be preserved")
	}
}

func TestDoUninstallHooks_GuardedAppendedLines(t *testing.T) {
	existingContent := "#!/bin/bash\necho hi\n\n# git-pkgs hook\n" + guardedHookBody + "\n"

	hooksDir := writeTestHook(t, "post-commit", existingContent)
	overrideHooks(t, hook{name: "post-commit", body: guardedHookBody})

	if err := doUninstallHooks(newTestCommand(), hooksDir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := readTestHook(t, hooksDir, "post-commit")
	if strings.Contains(result, "git pkgs reindex") || strings.Contains(result, "rebase-merge") {
		t.Errorf("expected git-pkgs lines to be removed, got:\n%s", result)
	}
	if !strings.Contains(result, "echo hi") {
		t.Error("expected original hook content to be preserved")
	}
}

func TestDoUninstallHooks_BlankLineBetweenMarkers(t *testing.T) {
	// Edge case: blank line between comment and command should still remove both
	existingContent := `#!/bin/bash
echo "my custom hook"

# git-pkgs hook

git pkgs reindex --quiet 2>/dev/null || true
`

	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}

	hookPath := filepath.Join(hooksDir, "post-commit")
	if err := os.WriteFile(hookPath, []byte(existingContent), 0755); err != nil {
		t.Fatal(err)
	}

	overrideHooks(t, hook{name: "post-commit", body: guardedHookBody})

	rootCmd := newTestCommand()
	if err := doUninstallHooks(rootCmd, hooksDir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("reading hook: %v", err)
	}

	result := string(content)
	if strings.Contains(result, "git-pkgs") {
		t.Errorf("expected git-pkgs lines to be removed, got:\n%s", result)
	}
	if strings.Contains(result, "git pkgs reindex") {
		t.Errorf("expected reindex line to be removed, got:\n%s", result)
	}
}

func TestWriteHook_UpgradesOldScript(t *testing.T) {
	oldScript := `#!/bin/sh
# git-pkgs post-commit/post-merge hook
# Updates the dependency database after commits/merges

git pkgs reindex --quiet 2>/dev/null || true
`
	h := hook{name: "post-commit", body: guardedHookBody}
	hooksDir := writeTestHook(t, "post-commit", oldScript)

	msg, err := writeHook(hooksDir, h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "updated" {
		t.Errorf("expected 'updated', got %q", msg)
	}

	result := readTestHook(t, hooksDir, "post-commit")
	if !strings.Contains(result, "rebase-merge") {
		t.Errorf("expected rebase guard in upgraded hook, got:\n%s", result)
	}

	msg, err = writeHook(hooksDir, h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "already installed" {
		t.Errorf("expected 'already installed' on second run, got %q", msg)
	}
}

func TestWriteHook_PostRewrite(t *testing.T) {
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}

	h := hook{name: "post-rewrite", body: postRewriteHookBody}
	if _, err := writeHook(hooksDir, h); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := readTestHook(t, hooksDir, "post-rewrite")
	if !strings.Contains(result, `[ "$1" = rebase ]`) {
		t.Errorf("expected rebase arg check, got:\n%s", result)
	}
	if strings.Contains(result, "rebase-merge") {
		t.Errorf("post-rewrite must not have directory guard, got:\n%s", result)
	}
}

func TestWriteHook_AppendsToForeignHook(t *testing.T) {
	hooksDir := writeTestHook(t, "post-commit", "#!/bin/bash\necho custom\n")

	h := hook{name: "post-commit", body: guardedHookBody}
	msg, err := writeHook(hooksDir, h)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != "appended to existing hook" {
		t.Errorf("expected append, got %q", msg)
	}

	result := readTestHook(t, hooksDir, "post-commit")
	if !strings.Contains(result, "echo custom") {
		t.Error("expected original content preserved")
	}
	if !strings.Contains(result, "rebase-merge") {
		t.Error("expected guarded snippet appended")
	}
}

func overrideHooks(t *testing.T, h ...hook) {
	t.Helper()
	orig := hooks
	hooks = h
	t.Cleanup(func() { hooks = orig })
}

func writeTestHook(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	hooksDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooksDir, name), []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	return hooksDir
}

func readTestHook(t *testing.T, hooksDir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(hooksDir, name))
	if err != nil {
		t.Fatalf("reading hook: %v", err)
	}
	return string(b)
}

func newTestCommand() *cobra.Command {
	return &cobra.Command{Use: "test"}
}
