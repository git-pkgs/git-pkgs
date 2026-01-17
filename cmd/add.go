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
	addAddCmd(rootCmd)
}

const defaultAddTimeout = 5 * time.Minute

func addAddCmd(parent *cobra.Command) {
	addCmd := &cobra.Command{
		Use:   "add <package> [version]",
		Short: "Add a dependency",
		Long: `Add a package dependency using the detected package manager.
Detects the package manager from lockfiles in the current directory
and runs the appropriate add command.

Examples:
  git-pkgs add lodash
  git-pkgs add lodash 4.17.21
  git-pkgs add rails --dev
  git-pkgs add lodash -e npm`,
		Args: cobra.RangeArgs(1, 2),
		RunE: runAdd,
	}

	addCmd.Flags().BoolP("dev", "D", false, "Add as development dependency")
	addCmd.Flags().StringP("manager", "m", "", "Override detected package manager (takes precedence over -e)")
	addCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	addCmd.Flags().Bool("dry-run", false, "Show what would be run without executing")
	addCmd.Flags().StringArrayP("extra", "x", nil, "Extra arguments to pass to package manager")
	addCmd.Flags().DurationP("timeout", "t", defaultAddTimeout, "Timeout for add operation")
	parent.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	pkg := args[0]
	var version string
	if len(args) > 1 {
		version = args[1]
	}

	dev, _ := cmd.Flags().GetBool("dev")
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
		Flags: map[string]any{
			"dev": dev,
		},
		Extra: extra,
	}

	if version != "" {
		input.Args["version"] = version
	}

	builtCmds, err := BuildCommands(mgr.Name, "add", input)
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

	if err := RunManagerCommands(ctx, dir, mgr.Name, "add", input); err != nil {
		return fmt.Errorf("add failed: %w", err)
	}

	return nil
}
