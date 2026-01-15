package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/git-pkgs/manifests"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

// Lockfile patterns for gitattributes
var lockfilePatterns = []string{
	"Gemfile.lock",
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
	"Cargo.lock",
	"Pipfile.lock",
	"poetry.lock",
	"composer.lock",
	"go.sum",
	"pubspec.lock",
	"Podfile.lock",
	"mix.lock",
	"packages.lock.json",
	"paket.lock",
	"*.resolved",
}

func init() {
	addDiffDriverCmd(rootCmd)
}

func addDiffDriverCmd(parent *cobra.Command) {
	diffDriverCmd := &cobra.Command{
		Use:   "diff-driver [file]",
		Short: "Git textconv driver for lockfile diffs",
		Long: `A git textconv driver that converts lockfiles to sorted dependency lists.
This makes lockfile diffs more readable by showing semantic changes.

Install with: git pkgs diff-driver --install
Then use 'git diff' normally - lockfiles will show sorted dependency lists.`,
		RunE: runDiffDriver,
	}

	diffDriverCmd.Flags().Bool("install", false, "Install diff driver in git config")
	diffDriverCmd.Flags().Bool("uninstall", false, "Remove diff driver from git config")
	parent.AddCommand(diffDriverCmd)
}

func runDiffDriver(cmd *cobra.Command, args []string) error {
	install, _ := cmd.Flags().GetBool("install")
	uninstall, _ := cmd.Flags().GetBool("uninstall")

	if install && uninstall {
		return fmt.Errorf("cannot specify both --install and --uninstall")
	}

	if install {
		return installDiffDriver(cmd)
	}

	if uninstall {
		return uninstallDiffDriver(cmd)
	}

	// If a file argument is provided, convert it
	if len(args) == 1 {
		return convertLockfile(cmd, args[0])
	}

	// Show usage
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Usage:")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  git pkgs diff-driver --install    Install the diff driver")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  git pkgs diff-driver --uninstall  Remove the diff driver")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  git pkgs diff-driver <file>       Convert a lockfile (internal use)")

	return nil
}

func installDiffDriver(cmd *cobra.Command) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	// Add to .git/config
	gitCmd := exec.Command("git", "config", "diff.git-pkgs.textconv", "git pkgs diff-driver")
	gitCmd.Dir = repo.WorkDir()
	if err := gitCmd.Run(); err != nil {
		return fmt.Errorf("setting git config: %w", err)
	}

	// Add to .gitattributes
	attrPath := filepath.Join(repo.WorkDir(), ".gitattributes")

	// Read existing file
	var existingLines []string
	if content, err := os.ReadFile(attrPath); err == nil {
		existingLines = strings.Split(string(content), "\n")
	}

	// Check if already configured
	hasGitPkgs := false
	for _, line := range existingLines {
		if strings.Contains(line, "diff=git-pkgs") {
			hasGitPkgs = true
			break
		}
	}

	if !hasGitPkgs {
		// Append lockfile patterns
		f, err := os.OpenFile(attrPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening .gitattributes: %w", err)
		}
		defer func() { _ = f.Close() }()

		_, _ = f.WriteString("\n# git-pkgs diff driver\n")
		for _, pattern := range lockfilePatterns {
			_, _ = fmt.Fprintf(f, "%s diff=git-pkgs\n", pattern)
		}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Diff driver installed.")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Lockfile diffs will now show sorted dependency lists.")
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Use 'git diff --no-textconv' to see raw diffs.")

	return nil
}

func uninstallDiffDriver(cmd *cobra.Command) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	// Remove from .git/config
	gitCmd := exec.Command("git", "config", "--unset", "diff.git-pkgs.textconv")
	gitCmd.Dir = repo.WorkDir()
	_ = gitCmd.Run() // Ignore error if not set

	// Remove from .gitattributes
	attrPath := filepath.Join(repo.WorkDir(), ".gitattributes")
	content, err := os.ReadFile(attrPath)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Diff driver uninstalled.")
			return nil
		}
		return fmt.Errorf("reading .gitattributes: %w", err)
	}

	var newLines []string
	inGitPkgsSection := false
	for _, line := range strings.Split(string(content), "\n") {
		if line == "# git-pkgs diff driver" {
			inGitPkgsSection = true
			continue
		}
		if inGitPkgsSection && strings.Contains(line, "diff=git-pkgs") {
			continue
		}
		if inGitPkgsSection && line == "" {
			inGitPkgsSection = false
			continue
		}
		inGitPkgsSection = false
		newLines = append(newLines, line)
	}

	if err := os.WriteFile(attrPath, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return fmt.Errorf("writing .gitattributes: %w", err)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Diff driver uninstalled.")

	return nil
}

func convertLockfile(cmd *cobra.Command, filePath string) error {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Try to parse with manifests library
	result, err := manifests.Parse(filepath.Base(filePath), content)
	if err != nil || result == nil || len(result.Dependencies) == 0 {
		// Fall back to just outputting the file as-is
		_, _ = cmd.OutOrStdout().Write(content)
		return nil
	}

	// Sort dependencies by name
	deps := result.Dependencies
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})

	// Output sorted list
	w := bufio.NewWriter(cmd.OutOrStdout())
	for _, dep := range deps {
		line := dep.Name
		if dep.Version != "" {
			line += " " + dep.Version
		}
		_, _ = fmt.Fprintln(w, line)
	}
	return w.Flush()
}
