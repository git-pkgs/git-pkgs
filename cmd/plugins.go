package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const pluginPrefix = "git-pkgs-"

type plugin struct {
	Name string
	Path string
}

func discoverPlugins(builtinNames map[string]bool) []plugin {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	seen := make(map[string]bool)
	var plugins []plugin

	for _, dir := range filepath.SplitList(pathEnv) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, pluginPrefix) {
				continue
			}

			// On Windows, executability is determined by extension, not file mode.
			if runtime.GOOS != osWindows {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				if info.Mode()&0111 == 0 {
					continue
				}
			}

			subcommand := strings.TrimPrefix(name, pluginPrefix)
			if runtime.GOOS == osWindows {
				ext := strings.ToLower(filepath.Ext(subcommand))
				if ext == ".exe" || ext == ".bat" || ext == ".cmd" {
					subcommand = strings.TrimSuffix(subcommand, filepath.Ext(subcommand))
				}
			}
			if subcommand == "" {
				continue
			}

			if builtinNames[subcommand] {
				continue
			}

			if seen[subcommand] {
				continue
			}
			seen[subcommand] = true

			plugins = append(plugins, plugin{
				Name: subcommand,
				Path: filepath.Join(dir, name),
			})
		}
	}

	return plugins
}

func builtinCommandNames(root *cobra.Command) map[string]bool {
	names := make(map[string]bool)
	for _, cmd := range root.Commands() {
		names[cmd.Name()] = true
	}
	return names
}

func addPluginCmds(parent *cobra.Command) {
	plugins := discoverPlugins(builtinCommandNames(parent))
	if len(plugins) == 0 {
		return
	}

	parent.AddGroup(&cobra.Group{
		ID:    "plugins",
		Title: "Plugin commands:",
	})

	for _, p := range plugins {
		pluginPath := p.Path
		pluginCmd := &cobra.Command{
			Use:                p.Name,
			Short:              fmt.Sprintf("[plugin] git-pkgs-%s", p.Name),
			DisableFlagParsing: true,
			GroupID:            "plugins",
			SilenceErrors:      true,
			SilenceUsage:       true,
			PersistentPreRun:   func(cmd *cobra.Command, args []string) {},
			PersistentPostRun:  func(cmd *cobra.Command, args []string) {},
			RunE: func(cmd *cobra.Command, args []string) error {
				c := exec.Command(pluginPath, args...)
				c.Stdin = os.Stdin
				c.Stdout = os.Stdout
				c.Stderr = os.Stderr
				return c.Run()
			},
		}
		parent.AddCommand(pluginCmd)
	}
}
