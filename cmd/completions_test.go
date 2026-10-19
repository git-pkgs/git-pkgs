package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestZshCompletion(t *testing.T) {
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	implementations := findZshGitCompletions(t, zsh)
	if len(implementations) == 0 {
		t.Skip("Git completion scripts are not installed")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "git-pkgs")
	build := exec.Command("go", "build", "-o", binary, "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build git-pkgs: %v\n%s", err, output)
	}
	generate := exec.Command(binary, "completion", "zsh")
	script, err := generate.Output()
	if err != nil {
		t.Fatalf("generate completion: %v", err)
	}
	completion := filepath.Join(dir, "_git-pkgs")
	if err := os.WriteFile(completion, script, 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct{ input, want string }{
		{"git pkgs comp", "git pkgs completion "},
		{"git-pkgs comp", "git-pkgs completion "},
		{"git pkgs completion z", "git pkgs completion zsh "},
		{"git pkgs list --for", "git pkgs list --format "},
		{"git -C /tmp pkgs comp", "git -C /tmp pkgs completion "},
		{"git pkgs zzcompletion", "git pkgs zzcompletion"},
		{"git pkgs comp --help" + strings.Repeat("\x02", len(" --help")), "git pkgs completion  --help"},
		{"git statu", "git status "},
	}
	var inputs []string
	for _, tt := range tests {
		inputs = append(inputs, tt.input)
	}
	for name, gitCompletion := range implementations {
		for _, mode := range []string{"source", "autoload"} {
			if name == "git" && mode == "autoload" {
				continue // Git's hook must be sourced before its first use.
			}
			t.Run(name+"/"+mode, func(t *testing.T) {
				lines := runZshCompletion(t, zsh, completion, gitCompletion, mode, inputs)
				if len(lines) != len(tests) {
					t.Fatalf("got %d results, want %d: %q", len(lines), len(tests), lines)
				}
				for i, tt := range tests {
					if lines[i] != tt.want {
						t.Errorf("completing %q: got %q, want %q", tt.input, lines[i], tt.want)
					}
				}
			})
		}
	}
}

func runZshCompletion(t *testing.T, zsh, completion, gitCompletion, mode string, inputs []string) []string {
	t.Helper()
	harness, err := filepath.Abs("testdata/zsh-completion.zsh")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	input := filepath.Join(work, "input")
	result := filepath.Join(work, "result")
	if err := os.WriteFile(input, []byte(strings.Join(inputs, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "zzcompletion-file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, zsh, "-f", harness)
	probe.Dir = work
	probe.Env = append(os.Environ(),
		"PATH="+filepath.Dir(completion)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TERM=xterm", "PKGS_ZSH="+zsh, "PKGS_COMPLETION="+completion,
		"PKGS_GIT_COMPLETION="+gitCompletion, "PKGS_LOAD_MODE="+mode,
		"PKGS_INPUT="+input, "PKGS_RESULT="+result)
	if output, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("interactive completion: %v\n%s", err, output)
	}
	output, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
}

func findZshGitCompletions(t *testing.T, zsh string) map[string]string {
	t.Helper()
	output, err := exec.Command(zsh, "-f", "-c", "print -rl -- $^fpath/_git(N)").Output()
	if err != nil {
		t.Fatal(err)
	}
	candidates := strings.Fields(string(output))
	if gitPath, err := exec.Command("git", "--exec-path").Output(); err == nil {
		prefix := filepath.Dir(filepath.Dir(strings.TrimSpace(string(gitPath))))
		candidates = append(candidates, filepath.Join(prefix, "share/zsh/site-functions/_git"))
	}
	candidates = append(candidates,
		"/usr/share/git/completion/git-completion.zsh",
		"/usr/share/doc/git/contrib/completion/git-completion.zsh")
	implementations := make(map[string]string)
	for _, path := range candidates {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(string(content), "__git_zsh_main"):
			implementations["git"] = path
		case strings.Contains(string(content), "_git_commands"):
			implementations["zsh"] = path
		}
	}
	return implementations
}
