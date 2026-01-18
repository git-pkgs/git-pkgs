package enrichment

import (
	"context"
	"strings"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
)

// EcosystemsClient wraps the ecosyste.ms API client.
type EcosystemsClient struct {
	client *ecosystems.Client
}

// NewEcosystemsClient creates a client that uses the ecosyste.ms API.
func NewEcosystemsClient() (*EcosystemsClient, error) {
	client, err := ecosystems.NewClient("git-pkgs/1.0")
	if err != nil {
		return nil, err
	}
	return &EcosystemsClient{client: client}, nil
}

func (c *EcosystemsClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	packages, err := c.client.BulkLookup(ctx, purls)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*PackageInfo, len(packages))
	for purl, pkg := range packages {
		if pkg == nil {
			continue
		}

		info := &PackageInfo{
			Ecosystem:   pkg.Ecosystem,
			Name:        pkg.Name,
			RegistryURL: ecosystemToDefaultRegistry(pkg.Ecosystem),
			Source:      "ecosystems",
		}
		if pkg.LatestReleaseNumber != nil {
			info.LatestVersion = *pkg.LatestReleaseNumber
		}
		if len(pkg.NormalizedLicenses) > 0 {
			info.License = pkg.NormalizedLicenses[0]
		} else if pkg.Licenses != nil && *pkg.Licenses != "" {
			info.License = *pkg.Licenses
		}
		result[purl] = info
	}
	return result, nil
}

func (c *EcosystemsClient) GetVersions(ctx context.Context, purl string) ([]VersionInfo, error) {
	ecosystem, name := parsePURLForEcosystems(purl)
	registry := ecosystemToRegistry(ecosystem)
	if registry == "" {
		return nil, nil
	}

	versions, err := c.client.GetAllVersions(ctx, registry, name)
	if err != nil {
		return nil, err
	}

	result := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info := VersionInfo{Number: v.Number}
		if v.PublishedAt != nil {
			info.PublishedAt, _ = time.Parse(time.RFC3339, *v.PublishedAt)
		}
		result = append(result, info)
	}
	return result, nil
}

func (c *EcosystemsClient) GetVersion(ctx context.Context, purl string) (*VersionInfo, error) {
	ecosystem, name, version := parsePURLWithVersion(purl)
	registry := ecosystemToRegistry(ecosystem)
	if registry == "" {
		return nil, nil
	}

	v, err := c.client.GetVersion(ctx, registry, name, version)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}

	info := &VersionInfo{Number: v.Number}
	if v.PublishedAt != nil {
		info.PublishedAt, _ = time.Parse(time.RFC3339, *v.PublishedAt)
	}
	if v.Integrity != nil {
		info.Integrity = *v.Integrity
	}
	return info, nil
}

// parsePURLForEcosystems extracts ecosystem and name from a PURL.
// Returns ecosystem type (npm, gem, etc) and package name.
func parsePURLForEcosystems(purl string) (ecosystem, name string) {
	// pkg:npm/lodash -> npm, lodash
	// pkg:npm/%40babel/core -> npm, @babel/core
	purl = strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(purl, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	ecosystem = parts[0]
	name = parts[1]
	// Handle URL-encoded scopes
	name = strings.ReplaceAll(name, "%40", "@")
	// Remove version if present
	if idx := strings.LastIndex(name, "@"); idx > 0 {
		// Don't split on @ if it's the first char (scoped package)
		if !strings.HasPrefix(name, "@") || strings.Count(name, "@") > 1 {
			name = name[:idx]
		}
	}
	return ecosystem, name
}

// parsePURLWithVersion extracts ecosystem, name, and version from a versioned PURL.
func parsePURLWithVersion(purl string) (ecosystem, name, version string) {
	purl = strings.TrimPrefix(purl, "pkg:")
	parts := strings.SplitN(purl, "/", 2)
	if len(parts) != 2 {
		return "", "", ""
	}
	ecosystem = parts[0]
	rest := strings.ReplaceAll(parts[1], "%40", "@")

	// Find version - last @ that's not a scope prefix
	if strings.HasPrefix(rest, "@") {
		// Scoped package like @babel/core@7.0.0
		afterScope := rest[1:]
		if idx := strings.LastIndex(afterScope, "@"); idx > 0 {
			name = rest[:idx+1]
			version = afterScope[idx+1:]
		} else {
			name = rest
		}
	} else {
		if idx := strings.LastIndex(rest, "@"); idx > 0 {
			name = rest[:idx]
			version = rest[idx+1:]
		} else {
			name = rest
		}
	}
	return ecosystem, name, version
}

// ecosystemToRegistry maps PURL ecosystem types to ecosyste.ms registry names.
func ecosystemToRegistry(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npmjs.org"
	case "gem":
		return "rubygems.org"
	case "pypi":
		return "pypi.org"
	case "cargo":
		return "crates.io"
	case "golang":
		return "proxy.golang.org"
	case "maven":
		return "repo1.maven.org"
	case "nuget":
		return "nuget.org"
	case "composer":
		return "packagist.org"
	case "hex":
		return "hex.pm"
	case "pub":
		return "pub.dev"
	case "cocoapods":
		return "cocoapods.org"
	default:
		return ""
	}
}

// ecosystemToDefaultRegistry returns the default registry URL for an ecosystem.
func ecosystemToDefaultRegistry(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "https://registry.npmjs.org"
	case "gem":
		return "https://rubygems.org"
	case "pypi":
		return "https://pypi.org"
	case "cargo":
		return "https://crates.io"
	case "golang":
		return "https://proxy.golang.org"
	case "maven":
		return "https://repo1.maven.org/maven2"
	case "nuget":
		return "https://api.nuget.org/v3"
	case "composer":
		return "https://packagist.org"
	case "hex":
		return "https://hex.pm"
	case "pub":
		return "https://pub.dev"
	case "cocoapods":
		return "https://trunk.cocoapods.org"
	default:
		return ""
	}
}
