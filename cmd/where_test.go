package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSearchFileForPackage(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		packageName string
		wantLines   []int
	}{
		{
			name:        "matches package name in dependency line",
			content:     `    "six": "^1.0.0",`,
			packageName: "six",
			wantLines:   []int{1},
		},
		{
			name:        "does not match inside integrity hash",
			content:     `      "integrity": "sha512-abc123SIxia456def==",`,
			packageName: "six",
			wantLines:   nil,
		},
		{
			name: "matches real dependency but not hash containing same text",
			content: `{
  "node_modules/six": {
    "version": "1.16.0",
    "resolved": "https://registry.npmjs.org/six/-/six-1.16.0.tgz",
    "integrity": "sha512-ySIxiAbcSIxcdefgSIxyz=="
  }
}`,
			packageName: "six",
			wantLines:   []int{2, 4},
		},
		{
			name:        "case insensitive match",
			content:     `    "Six": "^2.0.0",`,
			packageName: "six",
			wantLines:   []int{1},
		},
		{
			name:        "matches with special regex characters in name",
			content:     `    "@scope/my.pkg": "^1.0.0",`,
			packageName: "@scope/my.pkg",
			wantLines:   []int{1},
		},
		{
			name:        "no match when package name is substring of another word",
			content:     `    "sixteenth": "^1.0.0",`,
			packageName: "six",
			wantLines:   nil,
		},
		{
			name:        "no match when package name is hyphenated substring",
			content:     `    "my-left-pad": "1.0.0",`,
			packageName: "left-pad",
			wantLines:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "package-lock.json")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()

			matches, err := searchFileForPackage(root, "package-lock.json", "package-lock.json", tt.packageName, "npm", 0)
			if err != nil {
				t.Fatal(err)
			}

			if len(matches) != len(tt.wantLines) {
				t.Fatalf("got %d matches, want %d", len(matches), len(tt.wantLines))
			}

			for i, m := range matches {
				if m.LineNumber != tt.wantLines[i] {
					t.Errorf("match %d: got line %d, want %d", i, m.LineNumber, tt.wantLines[i])
				}
			}
		})
	}
}

func TestOutputWhereTextContextNearEOFUsesOriginalLineNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package.json")
	content := strings.Join([]string{
		"{",
		`  "scripts": {},`,
		`  "devDependencies": {},`,
		`  "dependencies": {`,
		`    "other": "1.0.0",`,
		`    "left-pad": "1.3.0"`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	matches, err := searchFileForPackage(root, "package.json", "package.json", "left-pad", "npm", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := outputWhereText(cmd, matches, true); err != nil {
		t.Fatal(err)
	}

	got := out.String()
	if !strings.Contains(got, `     5:     "other": "1.0.0",`) {
		t.Fatalf("context output did not preserve preceding line number:\n%s", got)
	}
	if !strings.Contains(got, `>    6:     "left-pad": "1.3.0"`) {
		t.Fatalf("context output did not mark the matched line:\n%s", got)
	}
}

func TestSearchFileForPackageRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevation on windows")
	}

	repoDir := t.TempDir()

	// Place a real manifest inside the repo
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(`{"dependencies":{"lodash":"^4.17.21"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a manifest outside the repo
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"dependencies":{"escaped-marker":"1.0.0"}}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a symlink inside the repo pointing to the outside manifest
	link := filepath.Join(repoDir, "requirements.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	root, err := os.OpenRoot(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	// Opening the symlink through os.Root should fail because it escapes the root
	_, err = searchFileForPackage(root, "requirements.txt", "requirements.txt", "escaped-marker", "pip", 0)
	if err == nil {
		t.Fatal("expected error opening symlink that escapes repo root, got nil")
	}

	// The real file inside the repo should still work
	matches, err := searchFileForPackage(root, "package.json", "package.json", "lodash", "npm", 0)
	if err != nil {
		t.Fatalf("unexpected error reading real file: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match for lodash, got %d", len(matches))
	}
}
