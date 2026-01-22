package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/git-pkgs/managers"
	"github.com/git-pkgs/managers/definitions"
	"github.com/spf13/cobra"
)

type PathNotSupportedError struct {
	Manager string
}

func (e *PathNotSupportedError) Error() string {
	return fmt.Sprintf("%s does not support the path operation. See 'git-pkgs browse --help' for supported managers.", e.Manager)
}

func (e *PathNotSupportedError) ExitCode() int {
	return 2
}

func init() {
	addBrowseCmd(rootCmd)
}

const defaultBrowseTimeout = 30 * time.Second

func addBrowseCmd(parent *cobra.Command) {
	browseCmd := &cobra.Command{
		Use:   "browse <package>",
		Short: "Open installed package source in editor",
		Long: `Open the source code of an installed package in your editor.

Detects the package manager from lockfiles in the current directory,
finds where the package is installed, and opens it in $EDITOR.

Examples:
  git-pkgs browse lodash           # open in $EDITOR
  git-pkgs browse lodash --path    # just print the path
  git-pkgs browse lodash --open    # open in file browser
  git-pkgs browse lodash -e npm    # specify ecosystem
  git-pkgs browse serde -m cargo   # specify manager`,
		Args: cobra.ExactArgs(1),
		RunE: runBrowse,
	}

	browseCmd.Flags().StringP("manager", "m", "", "Override detected package manager")
	browseCmd.Flags().StringP("ecosystem", "e", "", "Filter to specific ecosystem")
	browseCmd.Flags().Bool("path", false, "Print path instead of opening editor")
	browseCmd.Flags().Bool("open", false, "Open in file browser instead of editor")
	browseCmd.Flags().DurationP("timeout", "t", defaultBrowseTimeout, "Timeout for path lookup")
	parent.AddCommand(browseCmd)
}

func runBrowse(cmd *cobra.Command, args []string) error {
	pkg := args[0]
	managerOverride, _ := cmd.Flags().GetString("manager")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	printPath, _ := cmd.Flags().GetBool("path")
	openInBrowser, _ := cmd.Flags().GetBool("open")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	dir, err := getWorkingDir()
	if err != nil {
		return err
	}

	var managerName string

	if managerOverride != "" {
		managerName = managerOverride
	} else {
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

		if len(detected) > 1 {
			selected, err := PromptForManager(detected, cmd.OutOrStdout(), os.Stdin)
			if err != nil {
				return err
			}
			managerName = selected.Name
		} else {
			managerName = detected[0].Name
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	mgr, err := createManager(dir, managerName)
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	if !mgr.Supports(managers.CapPath) {
		return &PathNotSupportedError{Manager: managerName}
	}

	result, err := mgr.Path(ctx, pkg)
	if err != nil {
		return fmt.Errorf("getting path for %s: %w", pkg, err)
	}

	path := result.Path
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}

	if printPath {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), path)
		return nil
	}

	if openInBrowser {
		return openInFileBrowser(path)
	}

	return openInEditor(path)
}

func createManager(dir, managerName string) (managers.Manager, error) {
	translator, err := getTranslator()
	if err != nil {
		return nil, err
	}

	defs, err := definitions.LoadEmbedded()
	if err != nil {
		return nil, fmt.Errorf("loading definitions: %w", err)
	}

	detector := managers.NewDetector(translator, managers.NewExecRunner())
	for _, def := range defs {
		detector.Register(def)
	}

	return detector.Detect(dir, managers.DetectOptions{Manager: managerName})
}

func openInEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		return fmt.Errorf("no editor configured. Set $EDITOR or use --path to print the path")
	}

	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func openInFileBrowser(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}
