package database

import (
	"database/sql"
	"strings"
	"time"
)

// Package represents a row in the packages table.
// This type is shared between git-pkgs and the proxy.
type Package struct {
	ID            int64          `db:"id" json:"id"`
	PURL          string         `db:"purl" json:"purl"`
	Ecosystem     string         `db:"ecosystem" json:"ecosystem"`
	Name          string         `db:"name" json:"name"`
	LatestVersion sql.NullString `db:"latest_version" json:"latest_version,omitzero"`
	License       sql.NullString `db:"license" json:"license,omitzero"`
	Description   sql.NullString `db:"description" json:"description,omitzero"`
	Homepage      sql.NullString `db:"homepage" json:"homepage,omitzero"`
	RepositoryURL sql.NullString `db:"repository_url" json:"repository_url,omitzero"`
	RegistryURL   sql.NullString `db:"registry_url" json:"registry_url,omitzero"`
	SupplierName  sql.NullString `db:"supplier_name" json:"supplier_name,omitzero"`
	SupplierType  sql.NullString `db:"supplier_type" json:"supplier_type,omitzero"`
	Source        sql.NullString `db:"source" json:"source,omitzero"`
	EnrichedAt    sql.NullTime   `db:"enriched_at" json:"enriched_at,omitzero"`
	VulnsSyncedAt sql.NullTime   `db:"vulns_synced_at" json:"vulns_synced_at,omitzero"`
	CreatedAt     time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time      `db:"updated_at" json:"updated_at"`
}

// Version represents a row in the versions table.
// This type is shared between git-pkgs and the proxy.
type Version struct {
	ID          int64          `db:"id" json:"id"`
	PURL        string         `db:"purl" json:"purl"`
	PackagePURL string         `db:"package_purl" json:"package_purl"`
	License     sql.NullString `db:"license" json:"license,omitzero"`
	PublishedAt sql.NullTime   `db:"published_at" json:"published_at,omitzero"`
	Integrity   sql.NullString `db:"integrity" json:"integrity,omitzero"`
	Yanked      bool           `db:"yanked" json:"yanked"`
	Source      sql.NullString `db:"source" json:"source,omitzero"`
	EnrichedAt  sql.NullTime   `db:"enriched_at" json:"enriched_at,omitzero"`
	CreatedAt   time.Time      `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at" json:"updated_at"`
}

// VersionString extracts the version string from the PURL.
// e.g., "pkg:npm/lodash@4.17.21" -> "4.17.21"
func (v *Version) VersionString() string {
	if idx := strings.LastIndex(v.PURL, "@"); idx >= 0 {
		return v.PURL[idx+1:]
	}
	return ""
}

// Extension and query result types below.

type BranchInfo struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	LastAnalyzedSHA string `json:"last_analyzed_sha"`
	LastSHA         string `json:"last_sha,omitempty"`
	CommitCount     int    `json:"commit_count"`
}

type Dependency struct {
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	PURL           string `json:"purl"`
	Requirement    string `json:"requirement"`
	DependencyType string `json:"dependency_type"`
	Integrity      string `json:"integrity,omitempty"`
	ManifestPath   string `json:"manifest_path"`
	ManifestKind   string `json:"manifest_kind"`
}

type Change struct {
	Name                string `json:"name"`
	Ecosystem           string `json:"ecosystem"`
	PURL                string `json:"purl"`
	ChangeType          string `json:"change_type"`
	Requirement         string `json:"requirement"`
	PreviousRequirement string `json:"previous_requirement,omitempty"`
	DependencyType      string `json:"dependency_type"`
	ManifestPath        string `json:"manifest_path"`
}

type CommitWithChanges struct {
	SHA         string   `json:"sha"`
	Message     string   `json:"message"`
	AuthorName  string   `json:"author_name"`
	AuthorEmail string   `json:"author_email"`
	CommittedAt string   `json:"committed_at"`
	Changes     []Change `json:"changes"`
}

type LogOptions struct {
	BranchID  int64
	Ecosystem string
	Author    string
	Since     string
	Until     string
	Limit     int
}

type HistoryEntry struct {
	SHA                 string `json:"sha"`
	Message             string `json:"message"`
	AuthorName          string `json:"author_name"`
	AuthorEmail         string `json:"author_email"`
	CommittedAt         string `json:"committed_at"`
	Name                string `json:"name"`
	Ecosystem           string `json:"ecosystem"`
	ChangeType          string `json:"change_type"`
	Requirement         string `json:"requirement"`
	PreviousRequirement string `json:"previous_requirement,omitempty"`
	ManifestPath        string `json:"manifest_path"`
	ManifestKind        string `json:"manifest_kind"`
}

type HistoryOptions struct {
	BranchID    int64
	PackageName string
	Ecosystem   string
	Author      string
	Since       string
	Until       string
}

type BlameEntry struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Requirement  string `json:"requirement"`
	ManifestPath string `json:"manifest_path"`
	SHA          string `json:"sha"`
	AuthorName   string `json:"author_name"`
	AuthorEmail  string `json:"author_email"`
	CommittedAt  string `json:"committed_at"`
}

type WhyResult struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	ManifestPath string `json:"manifest_path"`
	SHA          string `json:"sha"`
	Message      string `json:"message"`
	AuthorName   string `json:"author_name"`
	AuthorEmail  string `json:"author_email"`
	CommittedAt  string `json:"committed_at"`
}

type SearchResult struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Requirement  string `json:"requirement"`
	FirstSeen    string `json:"first_seen"`
	LastChanged  string `json:"last_changed"`
	AddedIn      string `json:"added_in"`
	ManifestKind string `json:"manifest_kind"`
}

type StaleEntry struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Requirement  string `json:"requirement"`
	ManifestPath string `json:"manifest_path"`
	LastChanged  string `json:"last_changed"`
	DaysSince    int    `json:"days_since"`
}

type Stats struct {
	Branch             string         `json:"branch"`
	CommitsAnalyzed    int            `json:"commits_analyzed"`
	CommitsWithChanges int            `json:"commits_with_changes"`
	CurrentDeps        int            `json:"current_deps"`
	DepsByEcosystem    map[string]int `json:"deps_by_ecosystem"`
	TotalChanges       int            `json:"total_changes"`
	ChangesByType      map[string]int `json:"changes_by_type"`
	TopChanged         []NameCount    `json:"top_changed"`
	TopAuthors         []NameCount    `json:"top_authors"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type AuthorStats struct {
	Name    string         `json:"name"`
	Email   string         `json:"email"`
	Commits int            `json:"commits"`
	Changes int            `json:"changes"`
	ByType  map[string]int `json:"by_type"`
}

type StatsOptions struct {
	BranchID  int64
	Ecosystem string
	Since     string
	Until     string
	Limit     int
}

type EcosystemCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type DatabaseInfo struct {
	Path            string           `json:"path"`
	SizeBytes       int64            `json:"size_bytes"`
	SchemaVersion   int              `json:"schema_version"`
	BranchName      string           `json:"branch_name"`
	LastAnalyzedSHA string           `json:"last_analyzed_sha"`
	RowCounts       map[string]int   `json:"row_counts"`
	Ecosystems      []EcosystemCount `json:"ecosystems"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	Severity    string   `json:"severity"`
	CVSSScore   float64  `json:"cvss_score"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	References  []string `json:"references,omitempty"`
	Summary     string   `json:"summary"`
	Details     string   `json:"details,omitempty"`
	PublishedAt string   `json:"published_at"`
	WithdrawnAt string   `json:"withdrawn_at,omitempty"`
	ModifiedAt  string   `json:"modified_at"`
	FetchedAt   string   `json:"fetched_at"`
}

type VulnerabilityPackage struct {
	VulnerabilityID  string `json:"vulnerability_id"`
	Ecosystem        string `json:"ecosystem"`
	PackageName      string `json:"package_name"`
	AffectedVersions string `json:"affected_versions"`
	FixedVersions    string `json:"fixed_versions"`
}

type VulnSyncStatus struct {
	Ecosystem   string `json:"ecosystem"`
	PackageName string `json:"package_name"`
	SyncedAt    string `json:"synced_at"`
	VulnCount   int    `json:"vuln_count"`
}

type CachedPackage struct {
	PURL          string    `json:"purl"`
	Ecosystem     string    `json:"ecosystem"`
	Name          string    `json:"name"`
	LatestVersion string    `json:"latest_version"`
	License       string    `json:"license"`
	EnrichedAt    time.Time `json:"enriched_at"`
}

type CachedVersion struct {
	PURL        string    `json:"purl"`
	PackagePURL string    `json:"package_purl"`
	License     string    `json:"license"`
	PublishedAt time.Time `json:"published_at"`
}

type PackageEnrichmentData struct {
	PURL          string
	Ecosystem     string
	Name          string
	LatestVersion string
	License       string
	RegistryURL   string
	Source        string
}

type Note struct {
	ID        int64             `json:"id"`
	PURL      string            `json:"purl"`
	Namespace string            `json:"namespace"`
	Origin    string            `json:"origin"`
	Message   string            `json:"message,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

type NamespaceCount struct {
	Namespace string `json:"namespace"`
	Count     int    `json:"count"`
}

type BisectCandidate struct {
	SHA      string `json:"sha"`
	Message  string `json:"message"`
	Position int    `json:"position"`
}

type BisectOptions struct {
	BranchID     int64
	StartSHA     string
	EndSHA       string
	Ecosystem    string
	PackageName  string
	ManifestPath string
}
