// Package enrichment provides a unified interface for fetching package metadata
// from external sources (ecosyste.ms API or direct registry queries).
package enrichment

import (
	"context"
	"time"
)

// Client fetches package metadata from external sources.
type Client interface {
	// BulkLookup fetches metadata for multiple packages by PURL.
	// Returns a map of PURL to PackageInfo. Missing packages are omitted.
	BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error)

	// GetVersions fetches all versions for a package.
	// The purl should be a package PURL without version (pkg:npm/lodash).
	GetVersions(ctx context.Context, purl string) ([]VersionInfo, error)

	// GetVersion fetches metadata for a specific version.
	// The purl must include a version (pkg:npm/lodash@4.17.21).
	GetVersion(ctx context.Context, purl string) (*VersionInfo, error)
}

// PackageInfo contains metadata about a package.
type PackageInfo struct {
	Ecosystem     string
	Name          string
	LatestVersion string
	License       string
	RegistryURL   string // Base URL of the registry this came from
	Source        string // "ecosystems" or "registries"
}

// VersionInfo contains metadata about a specific version.
type VersionInfo struct {
	Number      string
	PublishedAt time.Time
	Integrity   string
	License     string
}
