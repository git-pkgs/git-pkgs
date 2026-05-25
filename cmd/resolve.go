package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/git-pkgs/managers"
	"github.com/git-pkgs/resolve"
	_ "github.com/git-pkgs/resolve/parsers"
	"github.com/spf13/cobra"
)

const defaultResolveTimeout = 5 * time.Minute

func addResolveCmd(parent *cobra.Command) {
	resolveCmd := &cobra.Command{
		Use:   "resolve",
		Short: "Print parsed dependency graph from the local package manager",
		Long: `Run the detected package manager's dependency graph command, parse
the output into a normalized dependency tree with PURLs, and print
the result.

Assumes dependencies are already installed. Run 'git-pkgs install' first
if needed.

Examples:
  git-pkgs resolve              # resolve dependencies (tree output)
  git-pkgs resolve -f json      # output as JSON
  git-pkgs resolve -e go        # only resolve Go ecosystem
  git-pkgs resolve -m cargo     # force cargo
  git-pkgs resolve --raw        # print raw manager output`,
		RunE: runResolve,
	}

	resolveCmd.Flags().StringP("manager", "m", "", "Override detected package manager (takes precedence over -e)")
	resolveCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	resolveCmd.Flags().Bool("dry-run", false, "Show what would be run without executing")
	resolveCmd.Flags().Bool("raw", false, "Print raw manager output instead of parsed JSON")
	resolveCmd.Flags().StringArrayP("extra", "x", nil, "Extra arguments to pass to package manager")
	resolveCmd.Flags().DurationP("timeout", "t", defaultResolveTimeout, "Timeout for resolve operation")
	resolveCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(resolveCmd)
}

func runResolve(cmd *cobra.Command, args []string) error {
	managerOverride, _ := cmd.Flags().GetString("manager")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	raw, _ := cmd.Flags().GetBool("raw")
	quiet, _ := cmd.Flags().GetBool("quiet")
	extra, _ := cmd.Flags().GetStringArray("extra")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	format, _ := cmd.Flags().GetString("format")

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

	if ecosystem != "" {
		detected = FilterByEcosystem(detected, ecosystem)
		if len(detected) == 0 {
			return fmt.Errorf("no %s package manager detected", ecosystem)
		}
	}

	if managerOverride != "" {
		detected = []DetectedManager{{Name: managerOverride}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, mgr := range detected {
		input := managers.CommandInput{
			Extra: extra,
		}

		builtCmds, err := BuildCommands(mgr.Name, "resolve", input)
		if err != nil {
			if !quiet {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Skipping %s: resolve not supported\n", mgr.Name)
			}
			continue
		}

		if !quiet {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Detected: %s", mgr.Name)
			if mgr.Lockfile != "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), " (%s)", mgr.Lockfile)
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr())
		}

		if dryRun {
			for _, c := range builtCmds {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Would run: %v\n", c)
			}
			continue
		}

		if !quiet {
			for _, c := range builtCmds {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Running: %v\n", c)
			}
		}

		if raw {
			if err := RunManagerCommands(ctx, dir, mgr.Name, "resolve", input, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
				return fmt.Errorf("%s resolve failed: %w", mgr.Name, err)
			}
			continue
		}

		var stdout bytes.Buffer
		if err := RunManagerCommands(ctx, dir, mgr.Name, "resolve", input, &stdout, cmd.ErrOrStderr()); err != nil {
			return fmt.Errorf("%s resolve failed: %w", mgr.Name, err)
		}

		result, err := resolve.Parse(mgr.Name, stdout.Bytes())
		if err != nil {
			return fmt.Errorf("%s: %w", mgr.Name, err)
		}

		switch format {
		case formatJSON:
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			if err := enc.Encode(result); err != nil {
				return fmt.Errorf("encoding result: %w", err)
			}
		default:
			writeResolveTree(cmd.OutOrStdout(), result)
		}
	}

	return nil
}

func writeResolveTree(w io.Writer, result *resolve.Result) {
	_, _ = fmt.Fprintf(w, "%s (%s)\n", result.Manager, result.Ecosystem)
	for i, dep := range result.Direct {
		last := i == len(result.Direct)-1
		writeResolveDep(w, dep, "", last)
	}
}

func writeResolveDep(w io.Writer, dep *resolve.Dep, prefix string, last bool) {
	connector := "├── "
	if last {
		connector = "└── "
	}
	_, _ = fmt.Fprintf(w, "%s%s%s@%s\n", prefix, connector, dep.Name, dep.Version)

	childPrefix := prefix + "│   "
	if last {
		childPrefix = prefix + "    "
	}
	for i, child := range dep.Deps {
		writeResolveDep(w, child, childPrefix, i == len(dep.Deps)-1)
	}
}
