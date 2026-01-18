package enrichment

import (
	"context"
	"sync"

	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/git-pkgs/vers"
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

	// For packages without LatestVersion populated, fetch versions and compute it
	var needLatest []string
	for purl, pkg := range packages {
		if pkg != nil && pkg.LatestVersion == "" {
			needLatest = append(needLatest, purl)
		}
	}

	latestVersions := make(map[string]string)
	if len(needLatest) > 0 {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10) // limit concurrency

		for _, purl := range needLatest {
			wg.Add(1)
			go func(purl string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				versions, err := c.GetVersions(ctx, purl)
				if err != nil || len(versions) == 0 {
					return
				}
				latest := findLatestVersion(versions)
				mu.Lock()
				latestVersions[purl] = latest
				mu.Unlock()
			}(purl)
		}
		wg.Wait()
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

		// Fill in latest version from computed value if needed
		if info.LatestVersion == "" {
			info.LatestVersion = latestVersions[purl]
		}

		result[purl] = info
	}
	return result, nil
}

// findLatestVersion returns the highest version from a list using semver comparison.
func findLatestVersion(versions []VersionInfo) string {
	if len(versions) == 0 {
		return ""
	}
	latest := versions[0].Number
	for _, v := range versions[1:] {
		if vers.Compare(v.Number, latest) > 0 {
			latest = v.Number
		}
	}
	return latest
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
