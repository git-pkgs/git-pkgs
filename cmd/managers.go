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
		for _, def := range defs {
			managerTranslator.Register(def)
		}
	})
	return managerTranslator, managerTranslatorErr
}

// lockfileMapping maps a lockfile to its package manager
type lockfileMapping struct {
	File    string
	Manager string
}

// ecosystemConfig defines detection rules for a single ecosystem
type ecosystemConfig struct {
	Ecosystem string
	Manifest  string
	Default   string              // default manager when only manifest exists
	Lockfiles []lockfileMapping   // in priority order (first match wins)
}

// ecosystems defines detection rules organized by ecosystem/purl type.
// Order matters: first ecosystem match wins for a given directory.
var ecosystemConfigs = []ecosystemConfig{
	{
		Ecosystem: "npm",
		Manifest:  "package.json",
		Default:   "npm",
		Lockfiles: []lockfileMapping{
			{"bun.lock", "bun"},
			{"pnpm-lock.yaml", "pnpm"},
			{"yarn.lock", "yarn"},
			{"package-lock.json", "npm"},
		},
	},
	{
		Ecosystem: "rubygems",
		Manifest:  "Gemfile",
		Default:   "bundler",
		Lockfiles: []lockfileMapping{
			{"Gemfile.lock", "bundler"},
		},
	},
	{
		Ecosystem: "cargo",
		Manifest:  "Cargo.toml",
		Default:   "cargo",
		Lockfiles: []lockfileMapping{
			{"Cargo.lock", "cargo"},
		},
	},
	{
		Ecosystem: "go",
		Manifest:  "go.mod",
		Default:   "gomod",
		Lockfiles: []lockfileMapping{
			{"go.sum", "gomod"},
		},
	},
	{
		Ecosystem: "pypi",
		Manifest:  "pyproject.toml",
		Default:   "uv",
		Lockfiles: []lockfileMapping{
			{"uv.lock", "uv"},
			{"poetry.lock", "poetry"},
		},
	},
	{
		Ecosystem: "packagist",
		Manifest:  "composer.json",
		Default:   "composer",
		Lockfiles: []lockfileMapping{
			{"composer.lock", "composer"},
		},
	},
	{
		Ecosystem: "hex",
		Manifest:  "mix.exs",
		Default:   "mix",
		Lockfiles: []lockfileMapping{
			{"mix.lock", "mix"},
		},
	},
	{
		Ecosystem: "pub",
		Manifest:  "pubspec.yaml",
		Default:   "pub",
		Lockfiles: []lockfileMapping{
			{"pubspec.lock", "pub"},
		},
	},
	{
		Ecosystem: "cocoapods",
		Manifest:  "Podfile",
		Default:   "cocoapods",
		Lockfiles: []lockfileMapping{
			{"Podfile.lock", "cocoapods"},
		},
	},
	// Additional ecosystems from manifests library (detection only, commands may not be supported)
	{
		Ecosystem: "maven",
		Manifest:  "pom.xml",
		Default:   "maven",
		Lockfiles: []lockfileMapping{
			{"gradle.lockfile", "gradle"},
		},
	},
	{
		Ecosystem: "nuget",
		Manifest:  "packages.config",
		Default:   "nuget",
		Lockfiles: []lockfileMapping{
			{"packages.lock.json", "nuget"},
			{"project.assets.json", "nuget"},
		},
	},
	{
		Ecosystem: "swift",
		Manifest:  "Package.swift",
		Default:   "swift",
		Lockfiles: []lockfileMapping{
			{"Package.resolved", "swift"},
		},
	},
	{
		Ecosystem: "deno",
		Manifest:  "deno.json",
		Default:   "deno",
		Lockfiles: []lockfileMapping{
			{"deno.lock", "deno"},
		},
	},
	{
		Ecosystem: "hackage",
		Manifest:  "",  // uses suffix match *.cabal
		Default:   "cabal",
		Lockfiles: []lockfileMapping{
			{"cabal.project.freeze", "cabal"},
			{"stack.yaml.lock", "stack"},
		},
	},
	{
		Ecosystem: "crystal",
		Manifest:  "shard.yml",
		Default:   "shards",
		Lockfiles: []lockfileMapping{
			{"shard.lock", "shards"},
		},
	},
	{
		Ecosystem: "julia",
		Manifest:  "Project.toml",
		Default:   "pkg",
		Lockfiles: []lockfileMapping{
			{"Manifest.toml", "pkg"},
		},
	},
	{
		Ecosystem: "conan",
		Manifest:  "conanfile.txt",
		Default:   "conan",
		Lockfiles: []lockfileMapping{
			{"conan.lock", "conan"},
		},
	},
	{
		Ecosystem: "vcpkg",
		Manifest:  "vcpkg.json",
		Default:   "vcpkg",
		Lockfiles: []lockfileMapping{},
	},
	{
		Ecosystem: "carthage",
		Manifest:  "Cartfile",
		Default:   "carthage",
		Lockfiles: []lockfileMapping{
			{"Cartfile.resolved", "carthage"},
		},
	},
	{
		Ecosystem: "cpan",
		Manifest:  "cpanfile",
		Default:   "cpanm",
		Lockfiles: []lockfileMapping{
			{"cpanfile.snapshot", "cpanm"},
		},
	},
	{
		Ecosystem: "cran",
		Manifest:  "DESCRIPTION",
		Default:   "renv",
		Lockfiles: []lockfileMapping{
			{"renv.lock", "renv"},
		},
	},
	{
		Ecosystem: "clojars",
		Manifest:  "project.clj",
		Default:   "lein",
		Lockfiles: []lockfileMapping{},
	},
	{
		Ecosystem: "elm",
		Manifest:  "elm.json",
		Default:   "elm",
		Lockfiles: []lockfileMapping{},
	},
	{
		Ecosystem: "dub",
		Manifest:  "dub.json",
		Default:   "dub",
		Lockfiles: []lockfileMapping{},
	},
	{
		Ecosystem: "haxelib",
		Manifest:  "haxelib.json",
		Default:   "haxelib",
		Lockfiles: []lockfileMapping{},
	},
	{
		Ecosystem: "nix",
		Manifest:  "flake.nix",
		Default:   "nix",
		Lockfiles: []lockfileMapping{
			{"flake.lock", "nix"},
		},
	},
	{
		Ecosystem: "conda",
		Manifest:  "environment.yml",
		Default:   "conda",
		Lockfiles: []lockfileMapping{},
	},
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	fileSet := make(map[string]bool)
	for _, e := range entries {
		if !e.IsDir() {
			fileSet[e.Name()] = true
		}
	}

	var detected []DetectedManager

	for _, eco := range ecosystemConfigs {
		// Try lockfiles first (in priority order)
		var found bool
		for _, lf := range eco.Lockfiles {
			if fileSet[lf.File] {
				detected = append(detected, DetectedManager{
					Name:      lf.Manager,
					Ecosystem: eco.Ecosystem,
					Lockfile:  lf.File,
				})
				found = true
				break // first lockfile wins for this ecosystem
			}
		}

		// Fall back to manifest with default manager
		if !found && fileSet[eco.Manifest] {
			detected = append(detected, DetectedManager{
				Name:      eco.Default,
				Ecosystem: eco.Ecosystem,
				Lockfile:  "", // no lockfile yet
			})
		}
	}

	return detected, nil
}

// DetectManager finds the primary package manager in the given directory
func DetectManager(dir string) (*DetectedManager, error) {
	mgrs, err := DetectManagers(dir)
	if err != nil {
		return nil, err
	}
	if len(mgrs) == 0 {
		return nil, fmt.Errorf("no package manager detected")
	}
	return &mgrs[0], nil
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
	case "npm":
		return []string{"npm", "pnpm", "yarn", "bun"}
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

// RunManagerCommand builds and executes a package manager command
func RunManagerCommand(ctx context.Context, dir, managerName, operation string, input managers.CommandInput) error {
	translator, err := getTranslator()
	if err != nil {
		return err
	}
	cmd, err := translator.BuildCommand(managerName, operation, input)
	if err != nil {
		return err
	}

	runner := managers.NewExecRunner()
	result, err := runner.Run(ctx, dir, cmd...)
	if err != nil {
		return err
	}

	if result.Stdout != "" {
		_, _ = os.Stdout.WriteString(result.Stdout)
	}
	if result.Stderr != "" {
		_, _ = os.Stderr.WriteString(result.Stderr)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("command failed with exit code %d", result.ExitCode)
	}

	return nil
}

// RunManagerCommands builds and executes multiple package manager commands (for chained operations)
func RunManagerCommands(ctx context.Context, dir, managerName, operation string, input managers.CommandInput) error {
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
			_, _ = os.Stdout.WriteString(result.Stdout)
		}
		if result.Stderr != "" {
			_, _ = os.Stderr.WriteString(result.Stderr)
		}

		if result.ExitCode != 0 {
			return fmt.Errorf("command failed with exit code %d", result.ExitCode)
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
