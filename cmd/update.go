package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/git-pkgs/managers"
	"github.com/spf13/cobra"
)

const defaultUpdateTimeout = 10 * time.Minute

func addUpdateCmd(parent *cobra.Command) {
	updateCmd := &cobra.Command{
		Use:   "update [package]",
		Short: "Update dependencies",
		Long: `Update dependencies using the detected package manager.
If a package name is provided, only that package is updated.
Otherwise, all dependencies are updated.

Examples:
  git-pkgs update              # update all dependencies
  git-pkgs update lodash       # update specific package
  git-pkgs update -e npm       # only update npm ecosystem
  git-pkgs update --all        # update all (for managers that need explicit flag)`,
		Args: cobra.MaximumNArgs(1),
		RunE: runUpdate,
	}

	updateCmd.Flags().StringP("manager", "m", "", "Override detected package manager (takes precedence over -e)")
	updateCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	updateCmd.Flags().Bool("all", false, "Update all dependencies (for managers like mix that require explicit --all)")
	updateCmd.Flags().Bool("dry-run", false, "Show what would be run without executing")
	updateCmd.Flags().StringArrayP("extra", "x", nil, "Extra arguments to pass to package manager")
	updateCmd.Flags().DurationP("timeout", "t", defaultUpdateTimeout, "Timeout for update operation")
	parent.AddCommand(updateCmd)
}

func runUpdate(cmd *cobra.Command, args []string) error {
	var pkg string
	if len(args) > 0 {
		pkg = args[0]
	}

	managerOverride, _ := cmd.Flags().GetString("manager")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	all, _ := cmd.Flags().GetBool("all")
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
		Args: map[string]string{},
		Flags: map[string]any{
			"all": all,
		},
		Extra: extra,
	}

	if pkg != "" {
		input.Args["package"] = pkg
	}

	builtCmds, err := BuildCommands(mgr.Name, "update", input)
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

	if err := RunManagerCommands(ctx, dir, mgr.Name, "update", input); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	return nil
}
