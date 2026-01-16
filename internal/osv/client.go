// Package osv provides a client for the OSV (Open Source Vulnerabilities) API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/git-pkgs/vers"
)

const (
	DefaultAPIURL = "https://api.osv.dev/v1"
	DefaultTimeout = 30 * time.Second
)

// Client is an OSV API client.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new OSV API client.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultAPIURL,
	}
}

// Vulnerability represents an OSV vulnerability.
type Vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary,omitempty"`
	Details          string           `json:"details,omitempty"`
	Aliases          []string         `json:"aliases,omitempty"`
	Modified         time.Time        `json:"modified"`
	Published        time.Time        `json:"published"`
	References       []Reference      `json:"references,omitempty"`
	Affected         []Affected       `json:"affected,omitempty"`
	Severity         []Severity       `json:"severity,omitempty"`
	DatabaseSpecific map[string]any   `json:"database_specific,omitempty"`
}

// Reference is a link to more information about a vulnerability.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Affected describes which package versions are affected.
type Affected struct {
	Package           Package           `json:"package"`
	Ranges            []Range           `json:"ranges,omitempty"`
	Versions          []string          `json:"versions,omitempty"`
	EcosystemSpecific map[string]any    `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any    `json:"database_specific,omitempty"`
}

// Package identifies a package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// Range describes a version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is a version event (introduced, fixed, etc).
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Severity describes the severity of a vulnerability.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// QueryRequest is a request to query vulnerabilities.
type QueryRequest struct {
	Commit  string  `json:"commit,omitempty"`
	Version string  `json:"version,omitempty"`
	Package Package `json:"package,omitempty"`
}

// QueryResponse is the response from a query.
type QueryResponse struct {
	Vulns []Vulnerability `json:"vulns,omitempty"`
}

// BatchQueryRequest is a request to query multiple packages.
type BatchQueryRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// BatchQueryResponse is the response from a batch query.
type BatchQueryResponse struct {
	Results []QueryResponse `json:"results"`
}

// Query queries for vulnerabilities affecting a specific package version.
func (c *Client) Query(ctx context.Context, ecosystem, name, version string) ([]Vulnerability, error) {
	req := QueryRequest{
		Version: version,
		Package: Package{
			Ecosystem: normalizeEcosystem(ecosystem),
			Name:      name,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return queryResp.Vulns, nil
}

// BatchQuery queries for vulnerabilities affecting multiple packages.
func (c *Client) BatchQuery(ctx context.Context, queries []QueryRequest) ([][]Vulnerability, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	// Normalize ecosystems
	for i := range queries {
		queries[i].Package.Ecosystem = normalizeEcosystem(queries[i].Package.Ecosystem)
	}

	// OSV batch API has a limit of 1000 queries per request
	const batchSize = 1000
	var allResults [][]Vulnerability

	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[i:end]

		req := BatchQueryRequest{Queries: batch}
		body, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/querybatch", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			return nil, fmt.Errorf("executing request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("batch query failed with status %d: %s", resp.StatusCode, string(respBody))
		}

		var batchResp BatchQueryResponse
		if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("decoding response: %w", err)
		}
		_ = resp.Body.Close()

		for _, result := range batchResp.Results {
			allResults = append(allResults, result.Vulns)
		}
	}

	return allResults, nil
}

// GetVulnerability fetches a specific vulnerability by ID.
func (c *Client) GetVulnerability(ctx context.Context, id string) (*Vulnerability, error) {
	httpReq, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get vulnerability failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &vuln, nil
}

// normalizeEcosystem converts our ecosystem names to OSV ecosystem names.
func normalizeEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "gem", "rubygems":
		return "RubyGems"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "cargo":
		return "crates.io"
	case "go", "golang":
		return "Go"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "composer", "packagist":
		return "Packagist"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "cocoapods":
		return "CocoaPods"
	default:
		return ecosystem
	}
}

// GetSeverityLevel returns a normalized severity level from a vulnerability.
func GetSeverityLevel(v *Vulnerability) string {
	for _, sev := range v.Severity {
		if sev.Type == "CVSS_V3" {
			score := parseCVSSScore(sev.Score)
			if score >= 9.0 {
				return "critical"
			} else if score >= 7.0 {
				return "high"
			} else if score >= 4.0 {
				return "medium"
			}
			return "low"
		}
	}

	// Check database_specific for severity
	if v.DatabaseSpecific != nil {
		if severity, ok := v.DatabaseSpecific["severity"].(string); ok {
			return strings.ToLower(severity)
		}
	}

	return "unknown"
}

func parseCVSSScore(score string) float64 {
	// CVSS scores can be in various formats
	// Try to extract the numeric score
	var numScore float64
	_, _ = fmt.Sscanf(score, "%f", &numScore)
	return numScore
}

// GetFixedVersion returns the fixed version for an affected entry, if available.
func GetFixedVersion(affected Affected) string {
	for _, r := range affected.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				return e.Fixed
			}
		}
	}
	return ""
}

// IsVersionAffected checks if a specific version is affected by the vulnerability.
func IsVersionAffected(affected Affected, version string) bool {
	// Check explicit versions list first
	for _, v := range affected.Versions {
		if v == version {
			return true
		}
	}

	// Check version ranges
	for _, r := range affected.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}

		// Process events to determine if version is in affected range
		inRange := false
		for _, e := range r.Events {
			if e.Introduced != "" {
				// "0" means all versions from the beginning
				if e.Introduced == "0" {
					inRange = true
				} else if vers.Compare(version, e.Introduced) >= 0 {
					inRange = true
				}
			}
			if e.Fixed != "" && inRange {
				// If version is >= fixed, no longer affected
				if vers.Compare(version, e.Fixed) >= 0 {
					inRange = false
				}
			}
			if e.LastAffected != "" && inRange {
				// If version is > lastAffected, no longer affected
				if vers.Compare(version, e.LastAffected) > 0 {
					inRange = false
				}
			}
		}
		if inRange {
			return true
		}
	}

	return false
}
