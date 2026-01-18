package enrichment

import (
	"context"

	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/package-url/packageurl-go"
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
	p, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	return p.Type
}

// extractRegistryURL extracts the registry URL from a PURL qualifier or returns the default.
func extractRegistryURL(purl, ecosystem string) string {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return registries.DefaultURL(ecosystem)
	}
	if url := p.Qualifiers.Map()["repository_url"]; url != "" {
		return url
	}
	return registries.DefaultURL(ecosystem)
}
