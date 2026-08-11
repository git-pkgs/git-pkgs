package cmd_test

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
)

func BenchmarkLicensesCommand(b *testing.B) {
	b.Setenv("GIT_PKGS_DB", "")
	restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
		"pkg:npm/express": {Ecosystem: "npm", Name: "express", License: "MIT"},
		"pkg:npm/jest":    {Ecosystem: "npm", Name: "jest", License: "MIT"},
		"pkg:npm/lodash":  {Ecosystem: "npm", Name: "lodash", License: "BSD-3-Clause"},
	})
	defer restore()

	repoDir := benchmarkLicenseRepository(b)
	previousDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.Chdir(previousDir) })

	runBenchmarkLicenseCommand(b, "init")
	runBenchmarkLicenseCommand(b, "licenses", "--format", "json")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchmarkLicenseCommand(b, "licenses", "--offline", "--format", "json")
	}
}

func benchmarkLicenseRepository(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	benchmarkGit(b, dir, "init", "--initial-branch=main")
	benchmarkGit(b, dir, "config", "user.email", "test@example.com")
	benchmarkGit(b, dir, "config", "user.name", "Test User")
	benchmarkGit(b, dir, "config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(packageJSON), 0o644); err != nil {
		b.Fatal(err)
	}
	benchmarkGit(b, dir, "add", "package.json")
	benchmarkGit(b, dir, "commit", "-m", "Add package.json")
	return dir
}

func benchmarkGit(b *testing.B, dir string, args ...string) {
	b.Helper()
	commandArgs := append([]string{"-C", dir}, args...)
	command := exec.Command("git", commandArgs...)
	if output, err := command.CombinedOutput(); err != nil {
		b.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func runBenchmarkLicenseCommand(b *testing.B, args ...string) {
	b.Helper()
	root := cmd.NewRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err != nil {
		b.Fatalf("git pkgs %v: %v", args, err)
	}
}
