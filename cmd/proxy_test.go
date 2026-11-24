package cmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/cmd"
)

const warmPackageJSON = `{"name":"example","dependencies":{"direct":"^1.0.0","unlocked":"*"}}`
const warmPackageLock = `{
  "name":"example","lockfileVersion":3,
  "packages":{
    "":{"name":"example","dependencies":{"direct":"^1.0.0"}},
    "node_modules/direct":{"version":"1.2.3"},
    "node_modules/transitive":{"version":"2.3.4","dev":true},
    "node_modules/direct/node_modules/transitive":{"version":"2.3.4","dev":true}
  }
}`

func setupProxyWarmRepo(t *testing.T) string {
	t.Helper()
	repo := createTestRepo(t)
	addFileAndCommit(t, repo, "package.json", warmPackageJSON, "Add manifest")
	addFileAndCommit(t, repo, "package-lock.json", warmPackageLock, "Lock dependencies")
	t.Chdir(repo)
	t.Setenv("PROXY_URL", "")
	return repo
}

func TestProxyWarmSubmitsResolvedVersions(t *testing.T) {
	setupProxyWarmRepo(t)
	var submitted []string
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing user agent")
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /prefix/api/mirror":
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("missing JSON content type")
			}
			var body struct {
				PURLs []string `json:"purls"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			submitted = body.PURLs
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, `{"id":"mirror-test"}`)
		case "GET /prefix/api/mirror/mirror-test":
			if polls.Add(1) == 1 {
				_, _ = fmt.Fprint(w, `{"state":"running","progress":{"total":2}}`)
			} else {
				_, _ = fmt.Fprint(w, `{"state":"complete","progress":{"total":2,"completed":1,"skipped":1}}`)
			}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	stdout, stderr, err := runCmd(t, "proxy", "warm", "--url", server.URL+"/prefix/")
	if err != nil {
		t.Fatalf("warm: %v\n%s", err, stderr)
	}
	want := []string{"pkg:npm/direct@1.2.3", "pkg:npm/transitive@2.3.4"}
	if !reflect.DeepEqual(submitted, want) {
		t.Errorf("submitted = %v, want %v", submitted, want)
	}
	if !strings.Contains(stdout, "1 downloaded, 1 already cached, 0 failed (2 total)") {
		t.Errorf("summary: %s", stdout)
	}
	if !strings.Contains(stderr, "Skipping unlocked (package.json): no resolved version") || !strings.Contains(stderr, "running:") {
		t.Errorf("diagnostics: %s", stderr)
	}
	if strings.Contains(stderr, "Skipping direct") {
		t.Errorf("resolved manifest declaration was reported as skipped: %s", stderr)
	}
}

func TestProxyWarmDryRunAndFilters(t *testing.T) {
	repo := setupProxyWarmRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "package-lock.json"), []byte(strings.ReplaceAll(warmPackageLock, "1.2.3", "9.9.9")), 0o644); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "dry-run contacted the proxy", http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("PROXY_URL", server.URL)
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"HEAD ignores working tree", nil, "pkg:npm/direct@1.2.3\npkg:npm/transitive@2.3.4\n"},
		{"ecosystem case insensitive", []string{"-e", "NPM"}, "pkg:npm/direct@1.2.3\npkg:npm/transitive@2.3.4\n"},
		{"manifest", []string{"-m", "package-lock.json"}, "pkg:npm/direct@1.2.3\npkg:npm/transitive@2.3.4\n"},
		{"development", []string{"-t", "development"}, "pkg:npm/transitive@2.3.4\n"},
		{"historical revision", []string{"--commit", "HEAD~1"}, "No resolved package versions to warm.\n"},
		{"empty selection", []string{"-e", "cargo"}, "No resolved package versions to warm.\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"proxy", "warm", "--dry-run"}, tt.args...)
			stdout, stderr, err := runCmd(t, args...)
			if err != nil || stdout != tt.want {
				t.Fatalf("stdout = %q, want %q; err = %v\n%s", stdout, tt.want, err, stderr)
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatal("dry-run made network requests")
	}
}

func TestProxyWarmJobFailures(t *testing.T) {
	setupProxyWarmRepo(t)
	for _, tt := range []struct {
		name   string
		status int
		post   string
		job    string
		want   string
	}{
		{"disabled API", 404, "", "", "enable mirror_api"},
		{"unauthorized", 401, "", "", "HTTP 401"},
		{"redirect", 307, "", "", "HTTP 307"},
		{"invalid response", 202, "not JSON", "", "invalid proxy response"},
		{"missing ID", 202, `{}`, "", "invalid mirror job ID"},
		{"invalid ID", 202, `{"id":"../elsewhere"}`, "", "invalid mirror job ID"},
		{"unknown state", 202, `{"id":"job"}`, `{}`, "unknown mirror job state"},
		{"partial failure", 202, `{"id":"job"}`, `{"state":"complete","progress":{"total":2,"completed":1,"failed":1,"errors":[{"ecosystem":"npm","name":"transitive","version":"2.3.4","error":"blocked"}]}}`, "1 package versions failed"},
		{"failed job", 202, `{"id":"job"}`, `{"state":"failed","error":"cannot enumerate packages"}`, "cannot enumerate packages"},
		{"canceled job", 202, `{"id":"job"}`, `{"state":"canceled"}`, "canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(tt.status)
					_, _ = fmt.Fprint(w, tt.post)
				} else {
					_, _ = fmt.Fprint(w, tt.job)
				}
			}))
			defer server.Close()
			t.Setenv("PROXY_URL", server.URL)
			_, stderr, err := runCmd(t, "proxy", "warm", "--quiet")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if tt.name == "partial failure" && !strings.Contains(stderr, "npm/transitive@2.3.4: blocked") {
				t.Errorf("missing package error: %s", stderr)
			}
		})
	}
}

func TestProxyWarmCancellation(t *testing.T) {
	setupProxyWarmRepo(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, `{"id":"job"}`)
		} else {
			cancel()
			_, _ = fmt.Fprint(w, `{"state":"running"}`)
		}
	}))
	defer server.Close()
	var output bytes.Buffer
	root := cmd.NewRootCmd()
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{"proxy", "warm", "--url", server.URL})
	err := root.ExecuteContext(ctx)
	if err == nil || !strings.Contains(err.Error(), "context canceled") || !strings.Contains(err.Error(), "job") {
		t.Fatalf("err = %v", err)
	}
}

func TestProxyWarmTimeout(t *testing.T) {
	setupProxyWarmRepo(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	start := time.Now()
	_, _, err := runCmd(t, "proxy", "warm", "--url", server.URL, "--timeout", "50ms")
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("request did not respect timeout")
	}
}

func TestProxyWarmOtherSources(t *testing.T) {
	for _, tt := range []struct {
		name    string
		path    string
		content string
		want    string
		skipped string
	}{
		{"Go pins", "go.mod", "module example.test/app\n\ngo 1.23\n\nrequire example.test/dependency v1.2.3\n", "pkg:golang/example.test/dependency@v1.2.3\n", ""},
		{"Maven pin and range", "pom.xml", `<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>pinned</artifactId><version>1.2.3</version></dependency><dependency><groupId>example</groupId><artifactId>ranged</artifactId><version>[1.0,2.0)</version></dependency></dependencies></project>`, "pkg:maven/example/pinned@1.2.3\n", "Skipping example:ranged"},
		{"local Ruby source", "Gemfile.lock", "PATH\n  remote: vendor/local\n  specs:\n    local (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  local!\n  rake\n", "pkg:gem/rake@13.0.6\n", "local source has no registry artifact"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := createTestRepo(t)
			addFileAndCommit(t, repo, tt.path, tt.content, "Add dependencies")
			t.Chdir(repo)
			t.Setenv("PROXY_URL", "")
			stdout, stderr, err := runCmd(t, "proxy", "warm", "--dry-run")
			if err != nil || stdout != tt.want || !strings.Contains(stderr, tt.skipped) {
				t.Fatalf("stdout = %q, want %q; err = %v\nstderr: %s", stdout, tt.want, err, stderr)
			}
		})
	}
}

func TestProxyWarmValidation(t *testing.T) {
	t.Setenv("PROXY_URL", "")
	for _, args := range [][]string{
		{}, {"--url", "ftp://example.test"}, {"--url", "http://user:secret@example.test"},
		{"--url", "http://example.test?token=secret"}, {"--timeout", "0"}, {"unexpected-argument"},
	} {
		_, _, err := runCmd(t, append([]string{"proxy", "warm"}, args...)...)
		if err == nil {
			t.Errorf("args %v: expected error", args)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("credentials leaked: %v", err)
		}
	}
}
