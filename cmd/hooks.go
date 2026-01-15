package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

const hookScript = `#!/bin/sh
# git-pkgs post-commit/post-merge hook
# Updates the dependency database after commits/merges

git pkgs update --quiet 2>/dev/null || true
`

var hookNames = []string{"post-commit", "post-merge"}

func init() {
	addHooksCmd(rootCmd)
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
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("creating hooks directory: %w", err)
	}

	for _, hookName := range hookNames {
		hookPath := filepath.Join(hooksDir, hookName)

		// Check if hook exists
		if _, err := os.Stat(hookPath); err == nil {
			// Read existing hook to check if it's ours
			content, readErr := os.ReadFile(hookPath)
			if readErr == nil && strings.Contains(string(content), "git-pkgs") {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: already installed\n", hookName)
				continue
			}

			// Existing hook that's not ours - append to it
			f, openErr := os.OpenFile(hookPath, os.O_APPEND|os.O_WRONLY, 0755)
			if openErr != nil {
				return fmt.Errorf("opening %s hook: %w", hookName, openErr)
			}

			_, writeErr := f.WriteString("\n# git-pkgs hook\ngit pkgs update --quiet 2>/dev/null || true\n")
			_ = f.Close()
			if writeErr != nil {
				return fmt.Errorf("appending to %s hook: %w", hookName, writeErr)
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: appended to existing hook\n", hookName)
		} else {
			// Create new hook
			if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
				return fmt.Errorf("writing %s hook: %w", hookName, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: installed\n", hookName)
		}
	}

	return nil
}

func doUninstallHooks(cmd *cobra.Command, hooksDir string) error {
	for _, hookName := range hookNames {
		hookPath := filepath.Join(hooksDir, hookName)

		content, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: not installed\n", hookName)
				continue
			}
			return fmt.Errorf("reading %s hook: %w", hookName, err)
		}

		if !strings.Contains(string(content), "git-pkgs") {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: not a git-pkgs hook\n", hookName)
			continue
		}

		// Check if it's our full hook or appended
		if strings.HasPrefix(string(content), "#!/bin/sh\n# git-pkgs") {
			// It's our hook - remove it
			if err := os.Remove(hookPath); err != nil {
				return fmt.Errorf("removing %s hook: %w", hookName, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: removed\n", hookName)
		} else {
			// It's appended to another hook - remove our lines
			lines := strings.Split(string(content), "\n")
			var newLines []string
			skipNext := false
			for _, line := range lines {
				if skipNext {
					skipNext = false
					continue
				}
				if line == "# git-pkgs hook" || strings.Contains(line, "git-pkgs post-commit") {
					skipNext = true
					continue
				}
				if strings.Contains(line, "git pkgs update") {
					continue
				}
				newLines = append(newLines, line)
			}

			if err := os.WriteFile(hookPath, []byte(strings.Join(newLines, "\n")), 0755); err != nil {
				return fmt.Errorf("writing %s hook: %w", hookName, err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s: removed git-pkgs lines\n", hookName)
		}
	}

	return nil
}

func showHooksStatus(cmd *cobra.Command, hooksDir string) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Git hooks status:")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	anyInstalled := false

	for _, hookName := range hookNames {
		hookPath := filepath.Join(hooksDir, hookName)

		content, err := os.ReadFile(hookPath)
		if err != nil {
			if os.IsNotExist(err) {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: not installed\n", hookName)
				continue
			}
			return fmt.Errorf("reading %s hook: %w", hookName, err)
		}

		if strings.Contains(string(content), "git-pkgs") || strings.Contains(string(content), "git pkgs") {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: installed\n", hookName)
			anyInstalled = true
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: exists (not git-pkgs)\n", hookName)
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

	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return err
	}

	for _, hookName := range hookNames {
		hookPath := filepath.Join(hooksDir, hookName)

		// Check if hook exists
		if _, err := os.Stat(hookPath); err == nil {
			content, readErr := os.ReadFile(hookPath)
			if readErr == nil && strings.Contains(string(content), "git-pkgs") {
				continue // Already installed
			}

			// Append to existing hook
			f, openErr := os.OpenFile(hookPath, os.O_APPEND|os.O_WRONLY, 0755)
			if openErr != nil {
				return openErr
			}
			_, writeErr := f.WriteString("\n# git-pkgs hook\ngit pkgs update --quiet 2>/dev/null || true\n")
			_ = f.Close()
			if writeErr != nil {
				return writeErr
			}
		} else {
			if err := os.WriteFile(hookPath, []byte(hookScript), 0755); err != nil {
				return err
			}
		}
	}

	return nil
}
