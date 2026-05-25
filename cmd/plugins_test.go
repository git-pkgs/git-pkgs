package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiscoverPlugins_FindsExecutables(t *testing.T) {
	dir := t.TempDir()

	writePlugin(t, dir, "git-pkgs-hello")
	writePlugin(t, dir, "git-pkgs-world")

	t.Setenv("PATH", dir)

	plugins := discoverPlugins(map[string]bool{})
	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}

	names := map[string]bool{}
	for _, p := range plugins {
		names[p.Name] = true
	}
	if !names["hello"] || !names["world"] {
		t.Errorf("expected hello and world plugins, got %v", names)
	}
}

func TestDiscoverPlugins_SkipsNonExecutable(t *testing.T) {
	if runtime.GOOS == osWindows {
		t.Skip("executable bit not relevant on Windows")
	}

	dir := t.TempDir()

	path := filepath.Join(dir, "git-pkgs-noexec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir)

	plugins := discoverPlugins(map[string]bool{})
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestDiscoverPlugins_SkipsBuiltinCollisions(t *testing.T) {
	dir := t.TempDir()

	writePlugin(t, dir, "git-pkgs-init")
	writePlugin(t, dir, "git-pkgs-custom")

	t.Setenv("PATH", dir)

	builtins := map[string]bool{"init": true}
	plugins := discoverPlugins(builtins)
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Name != "custom" {
		t.Errorf("expected custom, got %s", plugins[0].Name)
	}
}

func TestDiscoverPlugins_FirstPathWins(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	writePlugin(t, dir1, "git-pkgs-dup")
	writePlugin(t, dir2, "git-pkgs-dup")

	t.Setenv("PATH", dir1+string(os.PathListSeparator)+dir2)

	plugins := discoverPlugins(map[string]bool{})
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}
	if plugins[0].Path != filepath.Join(dir1, "git-pkgs-dup") {
		t.Errorf("expected first path to win, got %s", plugins[0].Path)
	}
}

func TestDiscoverPlugins_IgnoresDirectories(t *testing.T) {
	dir := t.TempDir()

	if err := os.Mkdir(filepath.Join(dir, "git-pkgs-subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir)

	plugins := discoverPlugins(map[string]bool{})
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(plugins))
	}
}

func TestPluginAppearsAsSubcommand(t *testing.T) {
	dir := t.TempDir()
	writePlugin(t, dir, "git-pkgs-myplugin")

	t.Setenv("PATH", dir)

	root := NewRootCmd()
	found := false
	for _, cmd := range root.Commands() {
		if cmd.Name() == "myplugin" {
			found = true
			if cmd.Short != "[plugin] git-pkgs-myplugin" {
				t.Errorf("unexpected Short: %s", cmd.Short)
			}
			if !cmd.DisableFlagParsing {
				t.Error("expected DisableFlagParsing to be true")
			}
			if cmd.GroupID != "plugins" {
				t.Errorf("expected GroupID plugins, got %s", cmd.GroupID)
			}
			break
		}
	}
	if !found {
		t.Error("myplugin subcommand not found on root command")
	}
}

func TestPluginExecsWithArgs(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "args.txt")

	var pluginName string
	var script string
	if runtime.GOOS == osWindows {
		pluginName = "git-pkgs-echo.bat"
		script = "@echo off\r\necho %* > " + outFile + "\r\n"
	} else {
		pluginName = "git-pkgs-echo"
		script = "#!/bin/sh\necho \"$@\" > " + outFile + "\n"
	}
	pluginPath := filepath.Join(dir, pluginName)
	if err := os.WriteFile(pluginPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", dir)

	root := NewRootCmd()
	root.SetArgs([]string{"echo", "foo", "--bar", "baz"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	expected := "foo --bar baz\n"
	if runtime.GOOS == osWindows {
		expected = "foo --bar baz \r\n"
	}
	if string(got) != expected {
		t.Errorf("expected %q, got %q", expected, string(got))
	}
}

func writePlugin(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
}
