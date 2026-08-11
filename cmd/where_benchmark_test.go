package cmd_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func BenchmarkWhereCommand(b *testing.B) {
	repoDir := benchmarkWhereRepository(b)
	previousDir, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.Chdir(previousDir) })

	runBenchmarkWhereCommand(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchmarkWhereCommand(b)
	}
}

func benchmarkWhereRepository(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	benchmarkWhereGit(b, dir, "init", "--initial-branch=main")
	benchmarkWhereWriteFile(b, dir, ".gitignore", "ignored/\n")

	const manifest = `{"dependencies":{"lodash":"4.17.21","express":"4.21.2"}}`
	for i := range 40 {
		packageDir := filepath.Join("packages", fmt.Sprintf("package-%02d", i))
		benchmarkWhereWriteFile(b, dir, filepath.Join(packageDir, "package.json"), manifest)
		benchmarkWhereWriteFile(b, dir, filepath.Join(packageDir, "README.md"), "package documentation")
	}
	for i := range 20 {
		ignoredDir := filepath.Join("ignored", fmt.Sprintf("package-%02d", i))
		benchmarkWhereWriteFile(b, dir, filepath.Join(ignoredDir, "package.json"), manifest)
	}
	return dir
}

func benchmarkWhereWriteFile(b *testing.B, dir, name, content string) {
	b.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		b.Fatal(err)
	}
}

func benchmarkWhereGit(b *testing.B, dir string, args ...string) {
	b.Helper()
	commandArgs := append([]string{"-C", dir}, args...)
	command := exec.Command("git", commandArgs...)
	if output, err := command.CombinedOutput(); err != nil {
		b.Fatalf("git %v: %v: %s", args, err, output)
	}
}

func runBenchmarkWhereCommand(b *testing.B) {
	b.Helper()
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"where", "lodash", "--format", "json"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err != nil {
		b.Fatalf("git pkgs where: %v", err)
	}
}
