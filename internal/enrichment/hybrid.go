package enrichment

import (
	"context"

	"github.com/package-url/packageurl-go"
)

// HybridClient routes requests based on PURL qualifiers.
// PURLs with repository_url go to registries, others go to ecosyste.ms.
type HybridClient struct {
	ecosystems *EcosystemsClient
	registries *RegistriesClient
}

// NewHybridClient creates a client that routes based on PURL qualifiers.
func NewHybridClient() (*HybridClient, error) {
	eco, err := NewEcosystemsClient()
	if err != nil {
		return nil, err
	}
	return &HybridClient{
		ecosystems: eco,
		registries: NewRegistriesClient(),
	}, nil
}

func (c *HybridClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	var ecoPurls, regPurls []string

	for _, purl := range purls {
		if hasRepositoryURL(purl) {
			regPurls = append(regPurls, purl)
		} else {
			ecoPurls = append(ecoPurls, purl)
		}
	}

	result := make(map[string]*PackageInfo)

	// Fetch from ecosyste.ms
	if len(ecoPurls) > 0 {
		ecoResults, err := c.ecosystems.BulkLookup(ctx, ecoPurls)
		if err != nil {
			return nil, err
		}
		for purl, info := range ecoResults {
			result[purl] = info
		}
	}

	// Fetch from registries (for private/custom registry URLs)
	if len(regPurls) > 0 {
		regResults, err := c.registries.BulkLookup(ctx, regPurls)
		if err != nil {
			// Don't fail entirely if registries fail, just skip those
			for purl, info := range regResults {
				result[purl] = info
			}
		} else {
			for purl, info := range regResults {
				result[purl] = info
			}
		}
	}

	return result, nil
}

func (c *HybridClient) GetVersions(ctx context.Context, purl string) ([]VersionInfo, error) {
	if hasRepositoryURL(purl) {
		return c.registries.GetVersions(ctx, purl)
	}
	return c.ecosystems.GetVersions(ctx, purl)
}

func (c *HybridClient) GetVersion(ctx context.Context, purl string) (*VersionInfo, error) {
	if hasRepositoryURL(purl) {
		return c.registries.GetVersion(ctx, purl)
	}
	return c.ecosystems.GetVersion(ctx, purl)
}

// hasRepositoryURL checks if a PURL has a repository_url qualifier.
func hasRepositoryURL(purl string) bool {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return false
	}
	return p.Qualifiers.Map()["repository_url"] != ""
}
