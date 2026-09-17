package cmd_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/git-pkgs/enrichment"
	"github.com/git-pkgs/git-pkgs/cmd"
)

type changelogTransport struct{}

func (changelogTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "raw.githubusercontent.com" {
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("## [4.17.21]\n\nLatest fix\n\n## [4.17.20]\n\nInstalled change\n\n## [3.10.1]\n\nOld change\n")), Request: req}, nil
}

func TestChangelogFromVersion(t *testing.T) {
	restore := setMockEnrichment(map[string]*enrichment.PackageInfo{
		"pkg:npm/lodash": {LatestVersion: "4.17.21", Repository: "https://github.com/lodash/lodash", ChangelogFilename: "CHANGELOG.md"},
	})
	defer restore()
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: changelogTransport{}}
	defer func() { http.DefaultClient = original }()
	for _, tt := range []struct {
		name         string
		versions     []string
		arg          string
		flags        []string
		want         string
		ambiguous    bool
		outside      bool
		empty        bool
		otherPackage bool
	}{
		{name: "installed", versions: []string{"4.17.20"}, want: "4.17.20"},
		{name: "duplicate occurrences", versions: []string{"4.17.20", "4.17.20"}, want: "4.17.20"},
		{name: "explicit wins", versions: []string{"3.10.1", "4.17.20"}, arg: "pkg:npm/lodash@3.10.1", flags: []string{"--from", "4.17.20"}, want: "4.17.20"},
		{name: "purl wins", versions: []string{"3.10.1", "4.17.20"}, arg: "pkg:npm/lodash@4.17.20", want: "4.17.20"},
		{name: "unresolved manifest"},
		{name: "package not installed", versions: []string{"4.17.20"}, otherPackage: true},
		{name: "empty repository", empty: true},
		{name: "ambiguous", versions: []string{"3.10.1", "4.17.20"}, ambiguous: true},
		{name: "explicit open bound", versions: []string{"4.17.20"}, flags: []string{"--from="}},
		{name: "outside repository", outside: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if !tt.outside {
				dir = createTestRepo(t)
				if !tt.empty {
					addFileAndCommit(t, dir, "package.json", `{"name":"test","dependencies":{"lodash":"^4.17.0"}}`, "add manifest")
				}
				if len(tt.versions) > 0 {
					lockfile := outdatedLockfile(tt.versions...)
					if tt.otherPackage {
						lockfile = strings.ReplaceAll(lockfile, "lodash", "another-package")
					}
					addFileAndCommit(t, dir, "package-lock.json", lockfile, "add lockfile")
					addFileAndCommit(t, dir, "app/package-lock.json", lockfile, "add another lockfile")
				}
			}
			cleanup := chdir(t, dir)
			defer cleanup()
			arg := tt.arg
			if arg == "" {
				arg = "lodash"
			}
			for _, format := range []string{"json", "text"} {
				args := append([]string{"changelog", arg, "-e", "npm", "--format", format}, tt.flags...)
				stdout, _, err := runCmd(t, args...)
				if tt.ambiguous {
					if err == nil {
						t.Fatal("expected ambiguous installed-version error")
					}
					for _, fragment := range []string{"3.10.1", "4.17.20", "package-lock.json", "app/package-lock.json", "--from"} {
						if !strings.Contains(err.Error(), fragment) {
							t.Errorf("error %q missing %q", err, fragment)
						}
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if format == "json" {
					var result cmd.ChangelogResult
					if err := json.Unmarshal([]byte(stdout), &result); err != nil {
						t.Fatal(err)
					}
					if result.From != tt.want {
						t.Errorf("from = %q; want %q", result.From, tt.want)
					}
				}
				if tt.want == "4.17.20" && (strings.Contains(stdout, "Installed change") || strings.Contains(stdout, "Old change")) {
					t.Errorf("output includes changes before the lower bound: %s", stdout)
				}
				if !strings.Contains(stdout, "Latest fix") {
					t.Errorf("missing latest entry: %s", stdout)
				}
			}
		})
	}
}
