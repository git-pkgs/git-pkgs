package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpJSONRoot(t *testing.T) {
	doc := runHelpJSON(t, "help", "--format", "json")

	if doc.Name != "git-pkgs" {
		t.Fatalf("name = %q, want git-pkgs", doc.Name)
	}
	if doc.CommandPath != "git-pkgs" {
		t.Fatalf("command_path = %q, want git-pkgs", doc.CommandPath)
	}
	if !hasHelpCommand(doc, "list") {
		t.Fatalf("root JSON help missing list command")
	}
	if !hasHelpCommand(doc, "help") {
		t.Fatalf("root JSON help missing help command")
	}
	if !hasHelpFlag(doc.PersistentFlags, "color", "string") {
		t.Fatalf("root JSON help missing persistent color flag")
	}
}

func TestHelpJSONSpecificCommand(t *testing.T) {
	doc := runHelpJSON(t, "help", "list", "--format", "json")

	if doc.Name != "list" {
		t.Fatalf("name = %q, want list", doc.Name)
	}
	if doc.CommandPath != "git-pkgs list" {
		t.Fatalf("command_path = %q, want git-pkgs list", doc.CommandPath)
	}
	if !hasHelpFlag(doc.Flags, "format", "string") {
		t.Fatalf("list JSON help missing format flag")
	}
	if !hasHelpFlag(doc.Flags, "ecosystem", "string") {
		t.Fatalf("list JSON help missing ecosystem flag")
	}
	if !hasHelpFlag(doc.InheritedFlags, "quiet", "bool") {
		t.Fatalf("list JSON help missing inherited quiet flag")
	}
}

func TestHelpJSONIncludesEmptyStringDefaults(t *testing.T) {
	output := runHelpJSONOutput(t, "help", "list", "--format", "json")

	var raw struct {
		Flags []map[string]any `json:"flags"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		t.Fatalf("unmarshal help JSON: %v\noutput:\n%s", err, string(output))
	}

	for _, flag := range raw.Flags {
		if flag["name"] != "ecosystem" {
			continue
		}
		defaultValue, ok := flag["default"]
		if !ok {
			t.Fatalf("ecosystem flag missing default key: %#v", flag)
		}
		if defaultValue != "" {
			t.Fatalf("ecosystem default = %#v, want empty string", defaultValue)
		}
		return
	}
	t.Fatal("list JSON help missing ecosystem flag")
}

func TestHelpJSONRejectsUnsupportedFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	root := NewRootCmd()
	root.SetArgs([]string{"help", "--format", "yaml"})
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	err := root.Execute()
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
	if !strings.Contains(err.Error(), `unsupported format "yaml"; supported formats: text, json`) {
		t.Fatalf("error = %v", err)
	}
}

func TestHelpJSONIncludesPlugins(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "git-pkgs-hello")
	if err := os.WriteFile(pluginPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	t.Setenv("PATH", dir)

	doc := runHelpJSON(t, "help", "--format", "json")
	pluginDoc, ok := findHelpCommand(doc, "hello")
	if !ok {
		t.Fatal("root JSON help missing plugin command")
	}
	if pluginDoc.Short != "[plugin] git-pkgs-hello" {
		t.Fatalf("plugin short = %q", pluginDoc.Short)
	}
}

func runHelpJSON(t *testing.T, args ...string) helpCommandDoc {
	t.Helper()
	output := runHelpJSONOutput(t, args...)

	var doc helpCommandDoc
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("unmarshal help JSON: %v\noutput:\n%s", err, string(output))
	}
	return doc
}

func runHelpJSONOutput(t *testing.T, args ...string) []byte {
	t.Helper()
	var stdout, stderr bytes.Buffer
	root := NewRootCmd()
	root.SetArgs(args)
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("%v failed: %v\nstderr: %s", args, err, stderr.String())
	}

	return stdout.Bytes()
}

func hasHelpCommand(doc helpCommandDoc, name string) bool {
	_, ok := findHelpCommand(doc, name)
	return ok
}

func findHelpCommand(doc helpCommandDoc, name string) (helpCommandDoc, bool) {
	for _, child := range doc.Subcommands {
		if child.Name == name {
			return child, true
		}
	}
	return helpCommandDoc{}, false
}

func hasHelpFlag(flags []helpFlagDoc, name, flagType string) bool {
	for _, flag := range flags {
		if flag.Name == name && flag.Type == flagType {
			return true
		}
	}
	return false
}
