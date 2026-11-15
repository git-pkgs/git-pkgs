package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/git-pkgs/managers"
	"github.com/git-pkgs/managers/definitions"
	"github.com/mattn/go-isatty"
)

var (
	managerTranslator     *managers.Translator
	managerDetector       *managers.Detector
	managerTranslatorOnce sync.Once
	managerTranslatorErr  error
)

func getTranslator() (*managers.Translator, error) {
	managerTranslatorOnce.Do(func() {
		managerTranslator = managers.NewTranslator()
		defs, err := definitions.LoadEmbedded()
		if err != nil {
			managerTranslatorErr = fmt.Errorf("loading package manager definitions: %w", err)
			return
		}
		managerDetector = managers.NewDetector(managerTranslator, nil)
		for _, def := range defs {
			managerDetector.Register(def)
		}
	})
	return managerTranslator, managerTranslatorErr
}

func getDetector() (*managers.Detector, error) {
	_, err := getTranslator()
	return managerDetector, err
}

// DetectedManager holds info about a detected package manager
type DetectedManager struct {
	Name      string
	Ecosystem string
	Lockfile  string
}

// DetectManagers finds all package managers in the given directory.
// For each ecosystem, checks lockfiles first (in priority order), then falls back
// to the default manager if only a manifest file exists.
func DetectManagers(dir string) ([]DetectedManager, error) {
	detector, err := getDetector()
	if err != nil {
		return nil, err
	}
	matches, err := detector.DetectAllFS(os.DirFS(dir), ".", managers.FileDetectOptions{
		OnConflict: managers.ConflictUseFirst,
		Policy:     managers.GitPkgsFileDetectionPolicy(),
	})
	if err != nil {
		return nil, err
	}

	var detected []DetectedManager
	for _, match := range matches {
		detected = append(detected, DetectedManager{
			Name:      match.Manager,
			Ecosystem: match.Ecosystem,
			Lockfile:  match.Lockfile,
		})
	}

	return detected, nil
}

// FilterByEcosystem filters detected managers to those matching the ecosystem
func FilterByEcosystem(detected []DetectedManager, ecosystem string) []DetectedManager {
	validManagers := ecosystemToManagers(ecosystem)
	if validManagers == nil {
		return nil
	}

	validSet := make(map[string]bool)
	for _, m := range validManagers {
		validSet[m] = true
	}

	var filtered []DetectedManager
	for _, d := range detected {
		if validSet[d.Name] {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

// ecosystemToManagers maps ecosystems to possible manager names
func ecosystemToManagers(ecosystem string) []string {
	switch ecosystem {
	case ecosystemNPM:
		return []string{ecosystemNPM, "pnpm", "yarn", "bun"}
	case "rubygems", "gem":
		return []string{"bundler"}
	case "cargo":
		return []string{"cargo"}
	case "go", "golang":
		return []string{"gomod"}
	case "pypi":
		return []string{"uv", "poetry"}
	case "packagist", "composer":
		return []string{"composer"}
	case "hex":
		return []string{"mix"}
	case "pub":
		return []string{"pub"}
	case "cocoapods":
		return []string{"cocoapods"}
	default:
		return nil
	}
}

// PromptForManager asks the user to select a package manager when multiple are detected.
// Returns the selected manager, or an error if not running interactively or user cancels.
func PromptForManager(detected []DetectedManager, out io.Writer, in io.Reader) (*DetectedManager, error) {
	if len(detected) == 0 {
		return nil, fmt.Errorf("no package manager detected")
	}
	if len(detected) == 1 {
		return &detected[0], nil
	}

	// Check if stdin is a terminal
	if f, ok := in.(*os.File); ok {
		if !isatty.IsTerminal(f.Fd()) && !isatty.IsCygwinTerminal(f.Fd()) {
			return nil, fmt.Errorf("multiple package managers detected (%s); use -m or -e to specify which one", managerNames(detected))
		}
	}

	_, _ = fmt.Fprintln(out, "Multiple package managers detected:")
	for i, mgr := range detected {
		if mgr.Lockfile != "" {
			_, _ = fmt.Fprintf(out, "  [%d] %s (%s)\n", i+1, mgr.Name, mgr.Lockfile)
		} else {
			_, _ = fmt.Fprintf(out, "  [%d] %s\n", i+1, mgr.Name)
		}
	}
	_, _ = fmt.Fprintf(out, "Select [1-%d]: ", len(detected))

	reader := bufio.NewReader(in)
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	input = strings.TrimSpace(input)
	choice, err := strconv.Atoi(input)
	if err != nil || choice < 1 || choice > len(detected) {
		return nil, fmt.Errorf("invalid selection: %s", input)
	}

	return &detected[choice-1], nil
}

func managerNames(detected []DetectedManager) string {
	names := make([]string, len(detected))
	for i, m := range detected {
		names[i] = m.Name
	}
	return strings.Join(names, ", ")
}

// RunManagerCommands builds and executes multiple package manager commands (for chained operations)
func RunManagerCommands(ctx context.Context, dir, managerName, operation string, input managers.CommandInput, stdout, stderr io.Writer) error {
	translator, err := getTranslator()
	if err != nil {
		return err
	}
	cmds, err := translator.BuildCommands(managerName, operation, input)
	if err != nil {
		return err
	}

	runner := managers.NewExecRunner()
	for _, cmd := range cmds {
		result, err := runner.Run(ctx, dir, cmd...)
		if err != nil {
			return err
		}

		if result.Stdout != "" {
			_, _ = io.WriteString(stdout, result.Stdout)
		}
		if result.Stderr != "" {
			_, _ = io.WriteString(stderr, result.Stderr)
		}

		if result.ExitCode != 0 {
			return fmt.Errorf("command failed with exit code %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
		}
	}

	return nil
}

// BuildCommands builds package manager commands without executing them
func BuildCommands(managerName, operation string, input managers.CommandInput) ([][]string, error) {
	translator, err := getTranslator()
	if err != nil {
		return nil, err
	}
	return translator.BuildCommands(managerName, operation, input)
}

func getWorkingDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	return filepath.Clean(dir), nil
}
