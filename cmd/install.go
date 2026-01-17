package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/git-pkgs/managers"
	"github.com/spf13/cobra"
)

func init() {
	addInstallCmd(rootCmd)
}

const defaultInstallTimeout = 10 * time.Minute

func addInstallCmd(parent *cobra.Command) {
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install dependencies from lockfile",
		Long: `Install dependencies using the detected package manager.
Detects the package manager from lockfiles in the current directory
and runs the appropriate install command.

Examples:
  git-pkgs install              # install dependencies
  git-pkgs install --frozen     # fail if lockfile would change (CI mode)
  git-pkgs install -e npm       # only install npm ecosystem
  git-pkgs install -m pnpm      # force pnpm`,
		RunE: runInstall,
	}

	installCmd.Flags().Bool("frozen", false, "Fail if lockfile would change (CI mode)")
	installCmd.Flags().StringP("manager", "m", "", "Override detected package manager (takes precedence over -e)")
	installCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	installCmd.Flags().Bool("dry-run", false, "Show what would be run without executing")
	installCmd.Flags().StringArrayP("extra", "x", nil, "Extra arguments to pass to package manager")
	installCmd.Flags().DurationP("timeout", "t", defaultInstallTimeout, "Timeout for install operation")
	parent.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	frozen, _ := cmd.Flags().GetBool("frozen")
	managerOverride, _ := cmd.Flags().GetString("manager")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	quiet, _ := cmd.Flags().GetBool("quiet")
	extra, _ := cmd.Flags().GetStringArray("extra")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	dir, err := getWorkingDir()
	if err != nil {
		return err
	}

	detected, err := DetectManagers(dir)
	if err != nil {
		return fmt.Errorf("detecting package managers: %w", err)
	}

	if len(detected) == 0 {
		return fmt.Errorf("no package manager detected in %s", dir)
	}

	// Filter by ecosystem if specified
	if ecosystem != "" {
		detected = FilterByEcosystem(detected, ecosystem)
		if len(detected) == 0 {
			return fmt.Errorf("no %s package manager detected", ecosystem)
		}
	}

	// Override manager if specified
	if managerOverride != "" {
		detected = []DetectedManager{{Name: managerOverride}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, mgr := range detected {
		if !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Detected: %s", mgr.Name)
			if mgr.Lockfile != "" {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), " (%s)", mgr.Lockfile)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}

		input := managers.CommandInput{
			Flags: map[string]any{
				"frozen": frozen,
			},
			Extra: extra,
		}

		builtCmds, err := BuildCommands(mgr.Name, "install", input)
		if err != nil {
			return fmt.Errorf("building command for %s: %w", mgr.Name, err)
		}

		if dryRun {
			for _, c := range builtCmds {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would run: %v\n", c)
			}
			continue
		}

		if !quiet {
			for _, c := range builtCmds {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Running: %v\n", c)
			}
		}

		if err := RunManagerCommands(ctx, dir, mgr.Name, "install", input); err != nil {
			return fmt.Errorf("%s install failed: %w", mgr.Name, err)
		}
	}

	return nil
}
