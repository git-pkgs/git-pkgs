package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/git-pkgs/archives"
	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/git-pkgs/internal/artifactcache"
	"github.com/git-pkgs/git-pkgs/internal/artifactregistry"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/integrity"
	licensespkg "github.com/git-pkgs/licenses"
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
	errs := make([]error, len(requests))

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				scans[i], errs[i] = loadAndScanLicenseArtifact(scanCtx, matcher, loader, requests[i], offline)
				if errs[i] != nil {
					cancel()
				}
			}
		}()
	}
	for i := range requests {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	results := make(map[string]licenseScanResult, len(requests))
	for i, request := range requests {
		if errs[i] != nil {
			return nil, errs[i]
		}
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
		return licenseScanResult{}, fmt.Errorf("loading package artifact %s: %w", request.PURL, err)
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
