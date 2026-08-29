// Package artifactregistry adapts registry resolution and downloading to the
// shared artifact acquisition service.
package artifactregistry

import (
	"context"
	"fmt"
	"strings"

	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/integrity"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	registryfetch "github.com/git-pkgs/registries/fetch"
)

const (
	sha256HexLength = 64
	sha384HexLength = 96
	sha512HexLength = 128
)

// Client resolves and fetches package files from package registries.
type Client struct {
	registryClient *registries.Client
	fetcher        *registryfetch.Fetcher
}

// New creates a registry artifact client.
func New(userAgent string) *Client {
	registryClient := registries.NewClient()
	registryClient.UserAgent = userAgent
	return &Client{
		registryClient: registryClient,
		fetcher:        registryfetch.NewFetcher(registryfetch.WithUserAgent(userAgent)),
	}
}

// Resolve selects a download source for a versioned package URL.
func (client *Client) Resolve(ctx context.Context, request acquire.Request) (acquire.Source, error) {
	registry, name, version, err := registries.NewFromPURL(request.PURL, client.registryClient)
	if err != nil {
		return acquire.Source{}, err
	}
	resolver := registryfetch.NewResolver()
	resolver.RegisterRegistry(registry)
	info, err := resolver.ResolveWithOptions(
		ctx,
		registry.Ecosystem(),
		name,
		version,
		registryfetch.ResolveOptions{
			Filename:  request.Filename,
			Integrity: nativeIntegrity(request.Integrity),
		},
	)
	if err != nil {
		return acquire.Source{}, err
	}
	metadata, err := ParseIntegrity(info.Integrity)
	if err != nil {
		return acquire.Source{}, fmt.Errorf("parse registry integrity: %w", err)
	}
	return acquire.Source{
		URL:       info.URL,
		Filename:  info.Filename,
		Integrity: metadata,
	}, nil
}

// Fetch opens an artifact URL through the registry fetcher.
func (client *Client) Fetch(ctx context.Context, url string) (*acquire.Download, error) {
	artifact, err := client.fetcher.Fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	return &acquire.Download{
		Body:      artifact.Body,
		Size:      artifact.Size,
		MediaType: artifact.ContentType,
	}, nil
}

// Close releases resources held by the registry fetcher.
func (client *Client) Close() error {
	return client.fetcher.Close()
}

// ParseIntegrity converts an artifact digest into supported SRI metadata.
// Go module h1 values are not raw archive digests. SHA-1 is outside the
// supported algorithm set. Both return an empty result.
func ParseIntegrity(value string) (integrity.SRI, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if metadata, err := integrity.ParseSRI(value); err == nil {
		return metadata, nil
	}

	fields := strings.Fields(value)
	metadata := make(integrity.SRI, 0, len(fields))
	for _, field := range fields {
		digest, supported, err := parseIntegrityField(field)
		if err != nil {
			return nil, err
		}
		if supported {
			metadata = append(metadata, digest)
		}
	}
	return metadata, nil
}

func parseIntegrityField(value string) (integrity.Digest, bool, error) {
	if metadata, err := integrity.ParseSRI(value); err == nil {
		return metadata[0], true, nil
	}
	algorithmName, encoded, found := strings.Cut(value, "-")
	if !found {
		algorithmName, encoded, found = strings.Cut(value, ":")
	}
	if found {
		algorithm, supported := integrityAlgorithm(algorithmName)
		if !supported {
			return integrity.Digest{}, false, nil
		}
		digest, err := integrity.ParseHex(algorithm, encoded)
		if err != nil {
			return integrity.Digest{}, false, fmt.Errorf("parse %s integrity: %w", algorithm, err)
		}
		return digest, true, nil
	}

	algorithm, supported := integrityAlgorithmForHex(value)
	if !supported {
		return integrity.Digest{}, false, nil
	}
	digest, err := integrity.ParseHex(algorithm, value)
	if err != nil {
		return integrity.Digest{}, false, err
	}
	return digest, true, nil
}

func integrityAlgorithm(value string) (integrity.Algorithm, bool) {
	switch strings.ToLower(value) {
	case "sha256":
		return integrity.SHA256, true
	case "sha384":
		return integrity.SHA384, true
	case "sha512":
		return integrity.SHA512, true
	default:
		return 0, false
	}
}

func integrityAlgorithmForHex(value string) (integrity.Algorithm, bool) {
	switch len(value) {
	case sha256HexLength:
		return integrity.SHA256, true
	case sha384HexLength:
		return integrity.SHA384, true
	case sha512HexLength:
		return integrity.SHA512, true
	default:
		return 0, false
	}
}

func nativeIntegrity(metadata integrity.SRI) string {
	values := make([]string, 0, len(metadata))
	for _, item := range metadata {
		values = append(values, item.Algorithm().String()+"-"+item.Hex())
	}
	return strings.Join(values, " ")
}
