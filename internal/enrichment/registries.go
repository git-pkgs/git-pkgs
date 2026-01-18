package enrichment

import (
	"context"
	"strings"

	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
)

// RegistriesClient queries package registries directly.
type RegistriesClient struct {
	client *registries.Client
}

// NewRegistriesClient creates a client that queries registries directly.
func NewRegistriesClient() *RegistriesClient {
	return &RegistriesClient{
		client: registries.DefaultClient(),
	}
}

func (c *RegistriesClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	// Use bulk fetch for packages
	packages := registries.BulkFetchPackages(ctx, purls, c.client)

	// For packages without LatestVersion populated, fetch it
	var needLatest []string
	for purl, pkg := range packages {
		if pkg != nil && pkg.LatestVersion == "" {
			needLatest = append(needLatest, purl)
		}
	}

	var latestVersions map[string]*registries.Version
	if len(needLatest) > 0 {
		latestVersions = registries.BulkFetchLatestVersions(ctx, needLatest, c.client)
	}

	result := make(map[string]*PackageInfo, len(packages))
	for purl, pkg := range packages {
		if pkg == nil {
			continue
		}

		ecosystem := extractEcosystem(purl)
		info := &PackageInfo{
			Ecosystem:     ecosystem,
			Name:          pkg.Name,
			LatestVersion: pkg.LatestVersion,
			License:       pkg.Licenses,
			RegistryURL:   extractRegistryURL(purl, ecosystem),
			Source:        "registries",
		}

		// Fill in latest version from separate fetch if needed
		if info.LatestVersion == "" {
			if v, ok := latestVersions[purl]; ok && v != nil {
				info.LatestVersion = v.Number
			}
		}

		result[purl] = info
	}
	return result, nil
}

func (c *RegistriesClient) GetVersions(ctx context.Context, purl string) ([]VersionInfo, error) {
	reg, name, _, err := registries.NewFromPURL(purl, c.client)
	if err != nil {
		return nil, err
	}

	versions, err := reg.FetchVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	result := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info := VersionInfo{
			Number:      v.Number,
			PublishedAt: v.PublishedAt,
			Integrity:   v.Integrity,
			License:     v.Licenses,
		}
		result = append(result, info)
	}
	return result, nil
}

func (c *RegistriesClient) GetVersion(ctx context.Context, purl string) (*VersionInfo, error) {
	v, err := registries.FetchVersionFromPURL(ctx, purl, c.client)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}

	return &VersionInfo{
		Number:      v.Number,
		PublishedAt: v.PublishedAt,
		Integrity:   v.Integrity,
		License:     v.Licenses,
	}, nil
}

// extractEcosystem extracts the ecosystem type from a PURL.
func extractEcosystem(purl string) string {
	// pkg:npm/lodash -> npm
	purl = strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(purl, "/"); idx > 0 {
		return purl[:idx]
	}
	return ""
}

// extractRegistryURL extracts the registry URL from a PURL qualifier or returns the default.
func extractRegistryURL(purl, ecosystem string) string {
	// Check for repository_url qualifier
	if idx := strings.Index(purl, "repository_url="); idx > 0 {
		url := purl[idx+len("repository_url="):]
		// Trim any trailing qualifiers
		if end := strings.Index(url, "&"); end > 0 {
			url = url[:end]
		}
		return url
	}

	// Return default registry URL
	return registries.DefaultURL(ecosystem)
}
