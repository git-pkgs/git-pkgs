package cmd_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestVulnsScanFailOnThresholds(t *testing.T) {
	for _, mode := range []string{"cached", "sync", "live"} {
		for _, tt := range []struct {
			severity string
			fails    []string
		}{
			{"critical", []string{"critical", "high", "medium", "low"}},
			{"high", []string{"high", "medium", "low"}},
			{"medium", []string{"medium", "low"}},
			{"low", []string{"low"}},
			{"unknown", nil},
		} {
			t.Run(mode+"/"+tt.severity, func(t *testing.T) {
				setupVulnsScan(t, tt.severity)
				for _, threshold := range []string{"", "critical", "high", "medium", "low"} {
					args := []string{"--format", "json"}
					if threshold != "" {
						args = append(args, "--fail-on", threshold)
					}
					stdout, _, err := runVulnsScan(t, mode, args...)
					assertVulnsPolicyError(t, err, slices.Contains(tt.fails, threshold))
					assertVulnsScanReport(t, stdout, "json", []string{tt.severity})
				}
			})
		}
	}
}

func TestVulnsScanFailOnReports(t *testing.T) {
	for _, mode := range []string{"cached", "sync", "live"} {
		for _, format := range []string{"text", "json", "sarif"} {
			t.Run(mode+"/"+format, func(t *testing.T) {
				setupVulnsScan(t, "high", "low", "unknown")
				for _, tt := range []struct {
					filter string
					want   []string
				}{
					{"", []string{"high", "low", "unknown"}},
					{"high", []string{"high"}},
					{"critical", nil},
				} {
					stdout, stderr, err := runVulnsScan(t, mode, "--format", format, "--fail-on", "HIGH", "--severity", tt.filter)
					assertVulnsPolicyError(t, err, true)
					assertVulnsScanReport(t, stdout, format, tt.want)
					if !strings.Contains(stderr, "vulnerability policy failed") {
						t.Fatalf("missing policy diagnostic on stderr: %q", stderr)
					}
				}
			})
		}
	}
}

func TestVulnsScanFailOnNoFindings(t *testing.T) {
	for _, mode := range []string{"cached", "sync", "live"} {
		t.Run(mode, func(t *testing.T) {
			setupVulnsScan(t)
			for _, format := range []string{"text", "json", "sarif"} {
				stdout, _, err := runVulnsScan(t, mode, "--format", format, "--fail-on", "low")
				assertVulnsPolicyError(t, err, false)
				assertVulnsScanReport(t, stdout, format, nil)
			}
		})
	}
}

func TestVulnsScanFailOnValidation(t *testing.T) {
	cleanup := chdir(t, t.TempDir())
	defer cleanup()
	for _, threshold := range []string{"", "unknown", "urgent", " high"} {
		stdout, _, err := runCmd(t, "vulns", "scan", "--fail-on", threshold)
		if err == nil || !strings.Contains(err.Error(), "invalid --fail-on") {
			t.Fatalf("threshold %q: expected validation error, got %v", threshold, err)
		}
		if stdout != "" {
			t.Fatalf("threshold %q: unexpected report %q", threshold, stdout)
		}
	}
}

func TestVulnsScanFailOnWithoutDependencies(t *testing.T) {
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "README.md", "# Empty project\n", "Initial commit")
	t.Cleanup(chdir(t, dir))
	for _, format := range []string{"json", "sarif"} {
		stdout, _, err := runVulnsScan(t, "cached", "--format", format, "--fail-on", "low")
		assertVulnsPolicyError(t, err, false)
		assertVulnsScanReport(t, stdout, format, nil)
	}
}

func TestVulnsScanFailOnLookupErrors(t *testing.T) {
	for _, mode := range []string{"sync", "live"} {
		for _, failure := range []struct {
			path   string
			status int
		}{
			{"/v1/querybatch", http.StatusServiceUnavailable},
			{"/v1/vulns/SCAN-high", http.StatusServiceUnavailable},
			{"/v1/vulns/SCAN-high", http.StatusNotFound},
		} {
			t.Run(fmt.Sprintf("%s/%s/%d", mode, failure.path, failure.status), func(t *testing.T) {
				transport := setupVulnsScan(t, "high")
				transport.failPath, transport.status = failure.path, failure.status
				stdout, _, err := runVulnsScan(t, mode, "--format", "json", "--fail-on", "high")
				if err == nil || errors.Is(err, cmd.ErrVulnerabilityPolicy) {
					t.Fatalf("expected lookup error, got %v", err)
				}
				if stdout != "" {
					t.Fatalf("unexpected success report: %q", stdout)
				}
				stdout, _, err = runVulnsScan(t, "cached", "--format", "json")
				assertVulnsPolicyError(t, err, false)
				assertVulnsScanReport(t, stdout, "json", []string{"high"})
			})
		}
	}
}

func TestVulnsScanLiveFetchesDetailsOnce(t *testing.T) {
	transport := setupVulnsScan(t, "high")
	addFileAndCommit(t, ".", "app/package-lock.json", outdatedLockfile("4.17.20"), "Add another occurrence")
	stdout, _, err := runVulnsScan(t, "live", "--format", "json", "--fail-on", "high")
	assertVulnsPolicyError(t, err, true)
	assertVulnsScanReport(t, stdout, "json", []string{"high", "high"})
	if got := transport.gets.Load(); got != 1 {
		t.Fatalf("detail requests = %d, want 1", got)
	}
}

func runVulnsScan(t *testing.T, mode string, flags ...string) (string, string, error) {
	t.Helper()
	args := []string{"vulns", "scan"}
	switch mode {
	case "cached":
		args = append(args, "--no-sync")
	case "live":
		args = append(args, "--live")
	}
	return runCmd(t, append(args, flags...)...)
}

func assertVulnsPolicyError(t *testing.T, err error, want bool) {
	t.Helper()
	if errors.Is(err, cmd.ErrVulnerabilityPolicy) != want || (!want && err != nil) {
		t.Fatalf("error = %v, want policy failure %t", err, want)
	}
}

func assertVulnsScanReport(t *testing.T, output, format string, severities []string) {
	t.Helper()
	var ids []string
	switch format {
	case "json":
		var results []cmd.VulnResult
		if err := json.Unmarshal([]byte(output), &results); err != nil {
			t.Fatalf("invalid JSON report: %v\n%s", err, output)
		}
		for _, result := range results {
			ids = append(ids, result.ID)
		}
	case "sarif":
		var report struct {
			Runs []struct {
				Results []struct{ RuleID string }
			}
		}
		if err := json.Unmarshal([]byte(output), &report); err != nil || len(report.Runs) != 1 {
			t.Fatalf("invalid SARIF report: %v\n%s", err, output)
		}
		for _, result := range report.Runs[0].Results {
			ids = append(ids, result.RuleID)
		}
	case "text":
		for _, field := range strings.Fields(output) {
			if strings.HasPrefix(field, "SCAN-") {
				ids = append(ids, field)
			}
		}
		if len(severities) == 0 && !strings.Contains(output, "No vulnerabilities found.") {
			t.Fatalf("missing empty report: %q", output)
		}
	}
	var want []string
	for _, severity := range severities {
		want = append(want, "SCAN-"+severity)
	}
	slices.Sort(ids)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Fatalf("report IDs = %v, want %v\n%s", ids, want, output)
	}
}

func setupVulnsScan(t *testing.T, severities ...string) *vulnsScanTransport {
	t.Helper()
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "package-lock.json", outdatedLockfile("4.17.20"), "Add dependency")
	t.Cleanup(chdir(t, dir))
	if _, _, err := runCmd(t, "init", "--no-hooks"); err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(filepath.Join(dir, ".git", "pkgs.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, severity := range severities {
		v := database.Vulnerability{
			ID: "SCAN-" + severity, Severity: severity, Summary: "Synthetic scan finding",
			FetchedAt: time.Now().Format(time.RFC3339),
		}
		if err := db.InsertVulnerability(v); err != nil {
			t.Fatal(err)
		}
		if err := db.InsertVulnerabilityPackage(database.VulnerabilityPackage{
			VulnerabilityID: v.ID, Ecosystem: "npm", PackageName: "lodash",
			AffectedVersions: "vers:npm/>=0.0.0|<4.17.21", FixedVersions: "4.17.21",
		}); err != nil {
			t.Fatal(err)
		}
	}
	transport := &vulnsScanTransport{severities: severities}
	original := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original })
	return transport
}

type vulnsScanTransport struct {
	severities []string
	failPath   string
	status     int
	gets       atomic.Int64
}

func (v *vulnsScanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.osv.dev" {
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	}
	status := http.StatusOK
	var payload any
	switch {
	case req.URL.Path == v.failPath:
		status = v.status
		payload = map[string]string{"error": "advisory lookup unavailable"}
	case req.URL.Path == "/v1/querybatch":
		var query struct{ Queries []json.RawMessage }
		if err := json.NewDecoder(req.Body).Decode(&query); err != nil {
			return nil, err
		}
		var summaries []map[string]string
		for _, severity := range v.severities {
			summaries = append(summaries, map[string]string{"id": "SCAN-" + severity, "modified": "2026-01-01T00:00:00Z"})
		}
		results := make([]map[string]any, len(query.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": summaries}
		}
		payload = map[string]any{"results": results}
	case strings.HasPrefix(req.URL.Path, "/v1/vulns/SCAN-"):
		v.gets.Add(1)
		severity := strings.TrimPrefix(req.URL.Path, "/v1/vulns/SCAN-")
		payload = map[string]any{
			"id": "SCAN-" + severity, "summary": "Synthetic scan finding",
			"database_specific": map[string]string{"severity": severity},
			"affected": []any{map[string]any{
				"package": map[string]string{"ecosystem": "npm", "name": "lodash"},
				"ranges": []any{map[string]any{"type": "SEMVER", "events": []any{
					map[string]string{"introduced": "0"}, map[string]string{"fixed": "4.17.21"},
				}}},
			}},
		}
	default:
		return nil, fmt.Errorf("unexpected request: %s", req.URL)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: req}, nil
}
