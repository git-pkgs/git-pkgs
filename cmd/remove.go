package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/git-pkgs/managers"
	"github.com/spf13/cobra"
)

func init() {
	addRemoveCmd(rootCmd)
}

const defaultRemoveTimeout = 5 * time.Minute

func addRemoveCmd(parent *cobra.Command) {
	removeCmd := &cobra.Command{
		Use:   "remove <package>",
		Short: "Remove a dependency",
		Long: `Remove a package dependency using the detected package manager.
Detects the package manager from lockfiles in the current directory
and runs the appropriate remove command.

Examples:
  git-pkgs remove lodash
  git-pkgs remove rails
  git-pkgs remove lodash -e npm`,
		Args: cobra.ExactArgs(1),
		RunE: runRemove,
	}

	removeCmd.Flags().StringP("manager", "m", "", "Override detected package manager (takes precedence over -e)")
	removeCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	removeCmd.Flags().Bool("dry-run", false, "Show what would be run without executing")
	removeCmd.Flags().StringArrayP("extra", "x", nil, "Extra arguments to pass to package manager")
	removeCmd.Flags().DurationP("timeout", "t", defaultRemoveTimeout, "Timeout for remove operation")
	parent.AddCommand(removeCmd)
}

func runRemove(cmd *cobra.Command, args []string) error {
	pkg := args[0]

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

	var mgr *DetectedManager
	if managerOverride != "" {
		mgr = &DetectedManager{Name: managerOverride}
	} else {
		detected, err := DetectManagers(dir)
		if err != nil {
			return fmt.Errorf("detecting package managers: %w", err)
		}
		if ecosystem != "" {
			detected = FilterByEcosystem(detected, ecosystem)
			if len(detected) == 0 {
				return fmt.Errorf("no %s package manager detected", ecosystem)
			}
		}
		mgr, err = PromptForManager(detected, cmd.OutOrStdout(), os.Stdin)
		if err != nil {
			return err
		}
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Detected: %s", mgr.Name)
		if mgr.Lockfile != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), " (%s)", mgr.Lockfile)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	input := managers.CommandInput{
		Args: map[string]string{
			"package": pkg,
		},
		Extra: extra,
	}

	builtCmds, err := BuildCommands(mgr.Name, "remove", input)
	if err != nil {
		return fmt.Errorf("building command: %w", err)
	}

	if dryRun {
		for _, c := range builtCmds {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would run: %v\n", c)
		}
		return nil
	}

	if !quiet {
		for _, c := range builtCmds {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Running: %v\n", c)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := RunManagerCommands(ctx, dir, mgr.Name, "remove", input); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}

	return nil
}
