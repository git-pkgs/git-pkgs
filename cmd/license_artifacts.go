package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/git-pkgs/archives"
	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/git-pkgs/internal/artifactcache"
	"github.com/git-pkgs/git-pkgs/internal/artifactregistry"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/integrity"
	licensespkg "github.com/git-pkgs/licenses"
	"github.com/git-pkgs/purl"
)

const (
	maxLicenseArtifactBytes      = 512 << 20
	maxLicenseArtifactCacheBytes = 4 << 30
	licenseArtifactConcurrency   = 4
)

type licenseArtifactLoader interface {
	Load(context.Context, acquire.Request, bool) (*acquire.Result, error)
	Close() error
}

type acquiringLicenseArtifactLoader struct {
	service  acquire.Service
	registry *artifactregistry.Client
}

func newLicenseArtifactLoader() (licenseArtifactLoader, error) { //nolint:ireturn
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	store, err := artifactcache.New(
		filepath.Join(userCacheDir, "git-pkgs", "artifacts"),
		maxLicenseArtifactBytes,
	)
	if err != nil {
		return nil, err
	}
	if err := store.Trim(maxLicenseArtifactCacheBytes); err != nil {
		return nil, fmt.Errorf("trimming package artifact cache: %w", err)
	}
	registry := artifactregistry.New(userAgent)
	return &acquiringLicenseArtifactLoader{
		service: acquire.Service{
			Resolver: registry,
			Fetcher:  registry,
			Store:    store,
		},
		registry: registry,
	}, nil
}

func (loader *acquiringLicenseArtifactLoader) Load(
	ctx context.Context,
	request acquire.Request,
	offline bool,
) (*acquire.Result, error) {
	return loader.service.Acquire(ctx, request, acquire.Options{
		Offline:  offline,
		MaxBytes: maxLicenseArtifactBytes,
	})
}

func (loader *acquiringLicenseArtifactLoader) Close() error {
	return loader.registry.Close()
}

func scanDependencyArtifacts(
	ctx context.Context,
	dependencies []database.Dependency,
	loader licenseArtifactLoader,
	offline bool,
) (map[string]licenseScanResult, error) {
	matcher, err := licensespkg.New()
	if err != nil {
		return nil, fmt.Errorf("creating license matcher: %w", err)
	}

	requests, err := uniqueLicenseArtifactRequests(dependencies)
	if err != nil {
		return nil, err
	}

	workers := min(licenseArtifactConcurrency, len(requests))
	jobs := make(chan int)
	scans := make([]licenseScanResult, len(requests))

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		firstErr error
		errOnce  sync.Once
	)
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				scan, err := loadAndScanLicenseArtifact(scanCtx, matcher, loader, requests[i], offline)
				if err != nil {
					if !errors.Is(err, context.Canceled) || ctx.Err() != nil {
						errOnce.Do(func() { firstErr = err })
					}
					cancel()
					continue
				}
				scans[i] = scan
			}
		}()
	}
feed:
	for i := range requests {
		select {
		case jobs <- i:
		case <-scanCtx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := make(map[string]licenseScanResult, len(requests))
	for i, request := range requests {
		merged := results[request.PURL]
		mergeLicenseScanResult(&merged, scans[i])
		results[request.PURL] = merged
	}
	return results, nil
}

func loadAndScanLicenseArtifact(
	ctx context.Context,
	matcher *licensespkg.Matcher,
	loader licenseArtifactLoader,
	request acquire.Request,
	offline bool,
) (licenseScanResult, error) {
	artifact, err := loader.Load(ctx, request, offline)
	if err != nil {
		return licenseScanResult{}, fmt.Errorf("loading package artifact: %w", err)
	}
	scan, scanErr := scanLicenseArtifact(ctx, matcher, artifact)
	closeErr := artifact.Body.Close()
	if scanErr != nil {
		return licenseScanResult{}, fmt.Errorf("scanning package artifact %s: %w", request.PURL, scanErr)
	}
	if closeErr != nil {
		return licenseScanResult{}, fmt.Errorf("closing package artifact %s: %w", request.PURL, closeErr)
	}
	return scan, nil
}

func uniqueLicenseArtifactRequests(dependencies []database.Dependency) ([]acquire.Request, error) {
	unique := make(map[string]acquire.Request)
	keys := make([]string, 0, len(dependencies))
	for _, dependency := range dependencies {
		versionedPURL := versionedPURLForDependency(dependency)
		if versionedPURL == "" {
			return nil, fmt.Errorf(
				"dependency %s from %s has no resolved package version",
				dependency.Name,
				dependency.ManifestPath,
			)
		}
		if isLocalSourcePURL(versionedPURL) {
			continue
		}
		metadata, err := artifactregistry.ParseIntegrity(dependency.Integrity)
		if err != nil {
			return nil, fmt.Errorf("parsing integrity for %s: %w", versionedPURL, err)
		}
		key := versionedPURL + "\x00" + integrity.FormatSRI(metadata)
		if _, ok := unique[key]; ok {
			continue
		}
		unique[key] = acquire.Request{PURL: versionedPURL, Integrity: metadata}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	requests := make([]acquire.Request, 0, len(keys))
	for _, key := range keys {
		requests = append(requests, unique[key])
	}
	return requests, nil
}

// isLocalSourcePURL reports whether a PURL's repository_url qualifier points
// at a local filesystem path rather than a remote registry. Bundler PATH
// sources and npm file: dependencies produce such PURLs; there is no artifact
// to download for them.
func isLocalSourcePURL(versionedPURL string) bool {
	parsed, err := purl.Parse(versionedPURL)
	if err != nil {
		return false
	}
	repo := parsed.RepositoryURL()
	if repo == "" {
		return false
	}
	return !strings.HasPrefix(repo, "http://") && !strings.HasPrefix(repo, "https://")
}

func scanLicenseArtifact(
	ctx context.Context,
	matcher *licensespkg.Matcher,
	artifact *acquire.Result,
) (licenseScanResult, error) {
	reader, err := archives.Open(artifact.Artifact.Filename, io.Reader(artifact.Body))
	if err != nil {
		return licenseScanResult{}, err
	}
	defer func() { _ = reader.Close() }()
	if err := validateLicenseArchive(reader); err != nil {
		return licenseScanResult{}, err
	}

	dir, err := os.MkdirTemp("", "git-pkgs-license-artifact-")
	if err != nil {
		return licenseScanResult{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := archives.ExtractAll(reader, dir, archives.WithMaxBytes(maxLicenseArtifactBytes)); err != nil {
		return licenseScanResult{}, err
	}
	return scanDependencyLicense(ctx, matcher, singleLicenseArchiveRoot(dir))
}

func validateLicenseArchive(reader archives.Reader) error {
	files, err := reader.List()
	if err != nil {
		return err
	}
	var total int64
	for _, file := range files {
		if file.Size < 0 {
			return fmt.Errorf("archive entry %q has negative size %d", file.Path, file.Size)
		}
		if file.Size > maxLicenseArtifactBytes-total {
			return fmt.Errorf("archive contents exceed %d bytes", maxLicenseArtifactBytes)
		}
		total += file.Size
	}
	return nil
}

func singleLicenseArchiveRoot(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || !entries[0].IsDir() {
		return root
	}
	return filepath.Join(root, entries[0].Name())
}
