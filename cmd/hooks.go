package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

const (
	hookDirPerm  = 0755
	hookFilePerm = 0755
)

const hookHeader = "#!/bin/sh\n# git-pkgs"

const guardedHookBody = `d="$(git rev-parse --git-dir)"; [ -d "$d/rebase-merge" ] || [ -d "$d/rebase-apply" ] || git pkgs reindex --quiet 2>/dev/null || true`

const postRewriteHookBody = `[ "$1" = rebase ] && git pkgs reindex --quiet 2>/dev/null || true`

type hook struct {
	name string
	body string
}

var hooks = []hook{
	{"post-commit", guardedHookBody},
	{"post-merge", guardedHookBody},
	{"post-rewrite", postRewriteHookBody},
}

func (h hook) script() string {
	return hookHeader + " " + h.name + " hook\n\n" + h.body + "\n"
}

func (h hook) snippet() string {
	return "\n# git-pkgs hook\n" + h.body + "\n"
}

func addHooksCmd(parent *cobra.Command) {
	hooksCmd := &cobra.Command{
		Use:   "hooks",
		Short: "Manage git hooks for automatic updates",
		Long: `Install or uninstall git hooks that automatically update the
dependency database after commits and merges.`,
		RunE: runHooks,
	}

	hooksCmd.Flags().Bool("install", false, "Install hooks")
	hooksCmd.Flags().Bool("uninstall", false, "Uninstall hooks")
	parent.AddCommand(hooksCmd)
}

func runHooks(cmd *cobra.Command, args []string) error {
	install, _ := cmd.Flags().GetBool("install")
	uninstall, _ := cmd.Flags().GetBool("uninstall")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	hooksDir := filepath.Join(repo.GitDir(), "hooks")

	if install && uninstall {
		return fmt.Errorf("cannot specify both --install and --uninstall")
	}

	if install {
		return doInstallHooks(cmd, hooksDir)
	}

	if uninstall {
		return doUninstallHooks(cmd, hooksDir)
	}

	// Show status
	return showHooksStatus(cmd, hooksDir)
}

func doInstallHooks(cmd *cobra.Command, hooksDir string) error {
	if err := os.MkdirAll(hooksDir, hookDirPerm); err != nil {
		return fmt.Errorf("creating hooks directory: %w", err)
	}

	for _, h := range hooks {
		msg, err := writeHook(hooksDir, h)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n", h.name, msg)
	}

	return nil
}

func writeHook(hooksDir string, h hook) (string, error) {
	hookPath := filepath.Join(hooksDir, h.name)

	content, err := os.ReadFile(hookPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("reading %s hook: %w", h.name, err)
		}
		if err := os.WriteFile(hookPath, []byte(h.script()), hookFilePerm); err != nil {
			return "", fmt.Errorf("writing %s hook: %w", h.name, err)
		}
		return "installed", nil
	}

	existing := string(content)

	if strings.HasPrefix(existing, hookHeader) {
		if existing == h.script() {
			return "already installed", nil
		}
		if err := os.WriteFile(hookPath, []byte(h.script()), hookFilePerm); err != nil {
			return "", fmt.Errorf("writing %s hook: %w", h.name, err)
		}
		return "updated", nil
	}

	if strings.Contains(existing, "git-pkgs") || strings.Contains(existing, "git pkgs reindex") {
		return "already installed", nil
	}

	f, err := os.OpenFile(hookPath, os.O_APPEND|os.O_WRONLY, hookFilePerm)
	if err != nil {
		return "", fmt.Errorf("opening %s hook: %w", h.name, err)
	}
	_, writeErr := f.WriteString(h.snippet())
	_ = f.Close()
	if writeErr != nil {
		return "", fmt.Errorf("appending to %s hook: %w", h.name, writeErr)
	}
	return "appended to existing hook", nil
}

func doUninstallHooks(cmd *cobra.Command, hooksDir string) error {
	for _, h := range hooks {
		hookPath := filepath.Join(hooksDir, h.name)

		content, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: not installed\n", h.name)
				continue
			}
			return fmt.Errorf("reading %s hook: %w", h.name, err)
		}

		if !strings.Contains(string(content), "git-pkgs") && !strings.Contains(string(content), "git pkgs reindex") {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: not a git-pkgs hook\n", h.name)
			continue
		}

		if strings.HasPrefix(string(content), hookHeader) {
			if err := os.Remove(hookPath); err != nil {
				return fmt.Errorf("removing %s hook: %w", h.name, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: removed\n", h.name)
		} else {
			lines := strings.Split(string(content), "\n")
			var newLines []string
			for _, line := range lines {
				if line == "# git-pkgs hook" ||
					strings.Contains(line, "git-pkgs post-commit") ||
					strings.Contains(line, "git pkgs reindex") {
					continue
				}
				newLines = append(newLines, line)
			}

			if err := os.WriteFile(hookPath, []byte(strings.Join(newLines, "\n")), hookFilePerm); err != nil {
				return fmt.Errorf("writing %s hook: %w", h.name, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: removed git-pkgs lines\n", h.name)
		}
	}

	return nil
}

func showHooksStatus(cmd *cobra.Command, hooksDir string) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Git hooks status:")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	anyInstalled := false

	for _, h := range hooks {
		hookPath := filepath.Join(hooksDir, h.name)

		content, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: not installed\n", h.name)
				continue
			}
			return fmt.Errorf("reading %s hook: %w", h.name, err)
		}

		if strings.Contains(string(content), "git-pkgs") || strings.Contains(string(content), "git pkgs") {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: installed\n", h.name)
			anyInstalled = true
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: exists (not git-pkgs)\n", h.name)
		}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if !anyInstalled {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Run 'git pkgs hooks --install' to enable automatic updates.")
	}

	return nil
}

// installHooks is called from init command
func installHooks(repo *git.Repository) error {
	hooksDir := filepath.Join(repo.GitDir(), "hooks")

	if err := os.MkdirAll(hooksDir, hookDirPerm); err != nil {
		return err
	}

	for _, h := range hooks {
		if _, err := writeHook(hooksDir, h); err != nil {
			return err
		}
	}

	return nil
}
