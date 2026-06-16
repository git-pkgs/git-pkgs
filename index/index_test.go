package index_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"

	"github.com/git-pkgs/git-pkgs/index"
)

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func head(t *testing.T, dir string) plumbing.Hash {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	return plumbing.NewHash(strings.TrimSpace(string(out)))
}

// makeBareRepo creates a bare repo at <tmp>/bare.git and a working repo at
// <tmp>/work that pushes into it. Returns the bare path.
func makeBareRepo(t *testing.T) (barePath, workPath string) {
	t.Helper()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	barePath = filepath.Join(tmp, "bare.git")
	workPath = filepath.Join(tmp, "work")
	runGit(t, tmp, "init", "--bare", barePath)
	runGit(t, tmp, "clone", barePath, workPath)
	runGit(t, workPath, "config", "user.email", "test@example.com")
	runGit(t, workPath, "config", "user.name", "Test")
	runGit(t, workPath, "config", "commit.gpgsign", "false")
	runGit(t, workPath, "config", "tag.gpgsign", "false")
	return barePath, workPath
}

func writeFile(t *testing.T, dir, path, content string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const goModTwoDeps = `module example.com/demo

go 1.26

require (
	github.com/spf13/cobra v1.8.0
	github.com/stretchr/testify v1.9.0
)
`

const goModBumpedCobra = `module example.com/demo

go 1.26

require (
	github.com/spf13/cobra v1.9.0
	github.com/stretchr/testify v1.9.0
)
`

func TestOpen_Bare(t *testing.T) {
	bare, work := makeBareRepo(t)
	writeFile(t, work, "go.mod", goModTwoDeps)
	runGit(t, work, "add", "go.mod")
	runGit(t, work, "commit", "-m", "add deps")
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")

	// HEAD is in the working repo; resolve there.
	tip := head(t, work)

	idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = idx.Close() }()

	if err := idx.Reindex(context.Background(), "main", plumbing.ZeroHash, tip); err != nil {
		t.Fatalf("reindex: %v", err)
	}

	deps, err := idx.List("main", tip.String())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps, got %d: %#v", len(deps), deps)
	}
	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	if !names["github.com/spf13/cobra"] || !names["github.com/stretchr/testify"] {
		t.Fatalf("missing expected names: %v", deps)
	}
}

func TestReindex_Incremental(t *testing.T) {
	bare, work := makeBareRepo(t)
	writeFile(t, work, "go.mod", goModTwoDeps)
	runGit(t, work, "add", "go.mod")
	runGit(t, work, "commit", "-m", "add deps")
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	tip1 := head(t, work)

	idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idx.Close() }()

	if err := idx.Reindex(context.Background(), "main", plumbing.ZeroHash, tip1); err != nil {
		t.Fatalf("reindex 1: %v", err)
	}

	writeFile(t, work, "go.mod", goModBumpedCobra)
	runGit(t, work, "commit", "-am", "bump cobra")
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	tip2 := head(t, work)

	if err := idx.Reindex(context.Background(), "main", tip1, tip2); err != nil {
		t.Fatalf("reindex 2: %v", err)
	}

	changes, err := idx.Show(tip2.String())
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d: %#v", len(changes), changes)
	}
	if changes[0].ChangeType != "modified" {
		t.Fatalf("want modified, got %q", changes[0].ChangeType)
	}

	deps, err := idx.List("main", tip2.String())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(deps) != 2 {
		t.Fatalf("want 2 deps after bump, got %d", len(deps))
	}
}

func TestReindex_Cancel(t *testing.T) {
	bare, work := makeBareRepo(t)
	writeFile(t, work, "go.mod", goModTwoDeps)
	runGit(t, work, "add", "go.mod")
	runGit(t, work, "commit", "-m", "c0")
	for i := 1; i < 20; i++ {
		writeFile(t, work, "filler", string(rune('a'+i)))
		runGit(t, work, "add", "filler")
		runGit(t, work, "commit", "-m", "filler")
	}
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	tip := head(t, work)

	ctx, cancel := context.WithCancel(context.Background())
	idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{
		Progress: func(done, _ int) {
			if done == 1 {
				cancel()
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idx.Close() }()

	err = idx.Reindex(ctx, "main", plumbing.ZeroHash, tip)
	if err == nil {
		t.Fatalf("want cancellation error, got nil")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Fatalf("want context error, got %v", err)
	}
}

func TestReindex_HostilePom(t *testing.T) {
	bare, work := makeBareRepo(t)
	const evil = `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>x</groupId>
  <artifactId>x</artifactId>
  <version>1</version>
  <parent>
    <groupId>p</groupId>
    <artifactId>p</artifactId>
    <version>1</version>
    <relativePath>../../../../etc/hostname</relativePath>
  </parent>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13</version>
    </dependency>
  </dependencies>
</project>
`
	writeFile(t, work, "pom.xml", evil)
	runGit(t, work, "add", "pom.xml")
	runGit(t, work, "commit", "-m", "hostile pom")
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	tip := head(t, work)

	idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idx.Close() }()

	if err := idx.Reindex(context.Background(), "main", plumbing.ZeroHash, tip); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	deps, err := idx.List("main", tip.String())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, d := range deps {
		if strings.Contains(strings.ToLower(d.Name), "hostname") {
			t.Fatalf("dep mentions hostname: %v", d)
		}
	}
}

func TestReindex_Caps(t *testing.T) {
	bare, work := makeBareRepo(t)
	// Build a large package.json with 50 deps; cap at 10.
	var sb strings.Builder
	sb.WriteString(`{"name":"x","version":"1.0.0","dependencies":{`)
	for i := 0; i < 50; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"pkg`)
		sb.WriteString(strings.Repeat("a", 1))
		// We need distinct names.
		sb.WriteString(strings.Repeat(string(rune('a'+i%26)), 1))
		sb.WriteString(string(rune('A' + i%26)))
		sb.WriteString(`":"^1.0.0"`)
	}
	sb.WriteString(`}}`)
	writeFile(t, work, "package.json", sb.String())
	runGit(t, work, "add", "package.json")
	runGit(t, work, "commit", "-m", "many deps")
	runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
	tip := head(t, work)

	idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{
		MaxDepsPerManifest: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = idx.Close() }()

	if err := idx.Reindex(context.Background(), "main", plumbing.ZeroHash, tip); err != nil {
		t.Fatalf("reindex: %v", err)
	}
	deps, err := idx.List("main", tip.String())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(deps) > 10 {
		t.Fatalf("cap not applied: got %d deps", len(deps))
	}
}

func TestConcurrentOpen(t *testing.T) {
	const N = 10
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bare, work := makeBareRepo(t)
			writeFile(t, work, "go.mod", goModTwoDeps)
			runGit(t, work, "add", "go.mod")
			runGit(t, work, "commit", "-m", "add deps")
			runGit(t, work, "push", "origin", "HEAD:refs/heads/main")
			tip := head(t, work)
			idx, err := index.Open(bare, filepath.Join(bare, "pkgs.sqlite3"), index.Options{})
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			defer func() { _ = idx.Close() }()
			if err := idx.Reindex(context.Background(), "main", plumbing.ZeroHash, tip); err != nil {
				t.Errorf("reindex: %v", err)
			}
		}()
	}
	wg.Wait()
}
