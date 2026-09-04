// Package artifactcache stores completed package files in a local filesystem
// cache.
package artifactcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/artifacts"
	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/integrity"
	"github.com/opencontainers/go-digest"
)

const (
	dirPermissions  = 0o700
	filePermissions = 0o600
	artifactName    = "artifact"
	metadataName    = "metadata.json"
)

// Store is a filesystem-backed artifact acquisition store.
type Store struct {
	root     string
	maxBytes int64
}

type metadata struct {
	Artifact artifacts.Artifact `json:"artifact"`
}

// New creates a filesystem store rooted at path. A zero maxBytes disables the
// size check when cached content is opened.
func New(path string, maxBytes int64) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("artifact cache path is empty")
	}
	if maxBytes < 0 {
		return nil, fmt.Errorf("artifact cache max bytes must be zero or greater")
	}
	return &Store{root: filepath.Clean(path), maxBytes: maxBytes}, nil
}

// Open returns a completed entry matching every populated request field.
func (store *Store) Open(ctx context.Context, request acquire.Request) (*acquire.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(store.packageDir(request.PURL))
	if errors.Is(err, os.ErrNotExist) {
		return nil, acquire.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read artifact cache: %w", err)
	}

	candidates := make([]metadata, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".stage-") {
			continue
		}
		candidate, err := store.readMetadata(request.PURL, entry.Name())
		if err != nil {
			return nil, err
		}
		if candidate.Artifact.PURL != request.PURL {
			return nil, fmt.Errorf("cached artifact has PURL %q, want %q", candidate.Artifact.PURL, request.PURL)
		}
		if request.Filename != "" && candidate.Artifact.Filename != request.Filename {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return nil, acquire.ErrNotFound
	}
	if len(candidates) > 1 && request.Filename == "" && len(request.Integrity) == 0 {
		return nil, fmt.Errorf("%w: several files are cached for %s", acquire.ErrNotFound, request.PURL)
	}

	var match *acquire.Entry
	for _, candidate := range candidates {
		entry, matches, err := store.openCandidate(request, candidate)
		if err != nil {
			return nil, err
		}
		if !matches {
			continue
		}
		if match != nil {
			_ = match.Body.Close()
			_ = entry.Body.Close()
			return nil, fmt.Errorf("several cached artifacts match %s", request.PURL)
		}
		match = entry
	}
	if match == nil {
		return nil, acquire.ErrNotFound
	}
	return match, nil
}

// Stage creates a private write for unverified package bytes.
//
//nolint:ireturn // acquire.Store requires its staging interface.
func (store *Store) Stage(
	ctx context.Context,
	request acquire.Request,
	_ acquire.Source,
) (acquire.Stage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	packageDir := store.packageDir(request.PURL)
	if err := os.MkdirAll(packageDir, dirPermissions); err != nil {
		return nil, fmt.Errorf("create artifact cache directory: %w", err)
	}
	stageDir, err := os.MkdirTemp(packageDir, ".stage-")
	if err != nil {
		return nil, fmt.Errorf("create artifact cache stage: %w", err)
	}
	if err := os.Chmod(stageDir, dirPermissions); err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, fmt.Errorf("set artifact cache stage permissions: %w", err)
	}
	file, err := os.OpenFile(
		filepath.Join(stageDir, artifactName),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		filePermissions,
	)
	if err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, fmt.Errorf("create staged artifact: %w", err)
	}
	return &stage{
		store:   store,
		request: request,
		dir:     stageDir,
		file:    file,
	}, nil
}

func (store *Store) openCandidate(
	request acquire.Request,
	candidate metadata,
) (*acquire.Entry, bool, error) {
	if err := candidate.Artifact.Validate(); err != nil {
		return nil, false, fmt.Errorf("validate cached artifact metadata: %w", err)
	}
	path := filepath.Join(
		store.packageDir(request.PURL),
		store.entryKey(candidate.Artifact),
		artifactName,
	)
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("cached artifact bytes for %s are missing at %s", request.PURL, path)
	}
	if err != nil {
		return nil, false, fmt.Errorf("open cached artifact for %s: %w", request.PURL, err)
	}
	matches, err := store.verifyFile(file, candidate.Artifact, request.Integrity)
	if err != nil {
		_ = file.Close()
		return nil, false, err
	}
	if !matches {
		_ = file.Close()
		return nil, false, nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, false, fmt.Errorf("rewind cached artifact: %w", err)
	}
	return &acquire.Entry{Artifact: candidate.Artifact, Body: file}, true, nil
}

func (store *Store) verifyFile(
	file *os.File,
	artifact artifacts.Artifact,
	expected integrity.SRI,
) (bool, error) {
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("read cached artifact size: %w", err)
	}
	if info.Size() != artifact.Size {
		return false, fmt.Errorf("cached artifact size is %d, want %d", info.Size(), artifact.Size)
	}
	if store.maxBytes > 0 && info.Size() > store.maxBytes {
		return false, fmt.Errorf("cached artifact is %d bytes; limit is %d", info.Size(), store.maxBytes)
	}
	if artifact.Digest.Algorithm() != digest.SHA256 {
		return false, fmt.Errorf("cached artifact digest uses %s, want sha256", artifact.Digest.Algorithm())
	}
	contentDigest, err := integrity.ParseHex(integrity.SHA256, artifact.Digest.Encoded())
	if err != nil {
		return false, fmt.Errorf("parse cached artifact digest: %w", err)
	}
	algorithms := []integrity.Algorithm{integrity.SHA256}
	for _, item := range expected {
		algorithms = append(algorithms, item.Algorithm())
	}
	reader, err := integrity.NewReader(file, algorithms...)
	if err != nil {
		return false, fmt.Errorf("verify cached artifact: %w", err)
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return false, fmt.Errorf("read cached artifact: %w", err)
	}
	result := reader.Result()
	if err := result.Verify(integrity.SRI{contentDigest}); err != nil {
		return false, fmt.Errorf("cached artifact does not match its content digest: %w", err)
	}
	if len(expected) > 0 {
		if err := result.Verify(expected); err != nil {
			return false, nil
		}
	}
	return true, nil
}

func (store *Store) readMetadata(packageURL, entry string) (metadata, error) {
	path := filepath.Join(store.packageDir(packageURL), entry, metadataName)
	content, err := os.ReadFile(path)
	if err != nil {
		return metadata{}, fmt.Errorf("read artifact cache metadata: %w", err)
	}
	var result metadata
	if err := json.Unmarshal(content, &result); err != nil {
		return metadata{}, fmt.Errorf("parse artifact cache metadata: %w", err)
	}
	return result, nil
}

func (store *Store) packageDir(packageURL string) string {
	key := sha256.Sum256([]byte(packageURL))
	return filepath.Join(store.root, hex.EncodeToString(key[:]))
}

func (store *Store) entryKey(artifact artifacts.Artifact) string {
	key := sha256.Sum256([]byte(artifact.Digest.String() + "\x00" + artifact.Filename))
	return hex.EncodeToString(key[:])
}

type trimEntry struct {
	dir     string
	size    int64
	modTime time.Time
}

// Trim removes the oldest cache entries until the total stored artifact bytes
// are at or below maxTotal. A maxTotal of zero or less is a no-op. In-progress
// stages are never removed.
func (store *Store) Trim(maxTotal int64) error {
	if maxTotal <= 0 {
		return nil
	}
	packageDirs, err := os.ReadDir(store.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read artifact cache: %w", err)
	}

	var entries []trimEntry
	var total int64
	for _, packageDir := range packageDirs {
		if !packageDir.IsDir() {
			continue
		}
		entryDirs, err := os.ReadDir(filepath.Join(store.root, packageDir.Name()))
		if err != nil {
			return fmt.Errorf("read artifact cache package: %w", err)
		}
		for _, entryDir := range entryDirs {
			if !entryDir.IsDir() || strings.HasPrefix(entryDir.Name(), ".stage-") {
				continue
			}
			path := filepath.Join(store.root, packageDir.Name(), entryDir.Name())
			info, err := os.Stat(filepath.Join(path, artifactName))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return fmt.Errorf("stat cached artifact: %w", err)
			}
			entries = append(entries, trimEntry{dir: path, size: info.Size(), modTime: info.ModTime()})
			total += info.Size()
		}
	}
	if total <= maxTotal {
		return nil
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].modTime.Before(entries[j].modTime) })
	for _, entry := range entries {
		if total <= maxTotal {
			break
		}
		if err := os.RemoveAll(entry.dir); err != nil {
			return fmt.Errorf("remove cached artifact: %w", err)
		}
		total -= entry.size
		parent := filepath.Dir(entry.dir)
		if remaining, err := os.ReadDir(parent); err == nil && len(remaining) == 0 {
			_ = os.Remove(parent)
		}
	}
	return nil
}

type stage struct {
	store     *Store
	request   acquire.Request
	dir       string
	file      *os.File
	committed bool
	discarded bool
}

func (item *stage) Write(content []byte) (int, error) {
	if item.committed || item.discarded {
		return 0, fmt.Errorf("artifact cache stage is closed")
	}
	return item.file.Write(content)
}

func (item *stage) Commit(ctx context.Context, artifact artifacts.Artifact) (io.ReadCloser, error) {
	if item.committed || item.discarded {
		return nil, fmt.Errorf("artifact cache stage is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := artifact.Validate(); err != nil {
		return nil, err
	}
	if artifact.PURL != item.request.PURL || artifact.Filename != item.request.Filename {
		return nil, fmt.Errorf("artifact metadata does not match its cache request")
	}
	if err := item.file.Sync(); err != nil {
		return nil, fmt.Errorf("sync staged artifact: %w", err)
	}
	if err := item.file.Close(); err != nil {
		return nil, fmt.Errorf("close staged artifact: %w", err)
	}
	item.file = nil

	staged, err := os.Open(filepath.Join(item.dir, artifactName))
	if err != nil {
		return nil, fmt.Errorf("reopen staged artifact: %w", err)
	}
	verified, err := item.store.verifyFile(staged, artifact, item.request.Integrity)
	_ = staged.Close()
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, fmt.Errorf("staged artifact does not match request integrity")
	}

	content, err := json.Marshal(metadata{Artifact: artifact})
	if err != nil {
		return nil, fmt.Errorf("encode artifact cache metadata: %w", err)
	}
	if err := writeFile(filepath.Join(item.dir, metadataName), content); err != nil {
		return nil, fmt.Errorf("write artifact cache metadata: %w", err)
	}

	destination := filepath.Join(item.store.packageDir(item.request.PURL), item.store.entryKey(artifact))
	if _, err := os.Stat(destination); err == nil {
		if err := os.RemoveAll(item.dir); err != nil {
			return nil, fmt.Errorf("remove duplicate artifact cache stage: %w", err)
		}
		item.discarded = true
		return item.openCommitted(artifact)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("check artifact cache destination: %w", err)
	}
	if err := os.Rename(item.dir, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr == nil {
			if removeErr := os.RemoveAll(item.dir); removeErr != nil {
				return nil, fmt.Errorf("remove duplicate artifact cache stage: %w", removeErr)
			}
			item.discarded = true
			return item.openCommitted(artifact)
		}
		return nil, fmt.Errorf("publish artifact cache entry: %w", err)
	}
	item.committed = true
	return item.openCommitted(artifact)
}

func (item *stage) Discard(context.Context) error {
	if item.committed || item.discarded {
		return nil
	}
	if item.file != nil {
		_ = item.file.Close()
		item.file = nil
	}
	item.discarded = true
	if err := os.RemoveAll(item.dir); err != nil {
		return err
	}
	parent := item.store.packageDir(item.request.PURL)
	if remaining, err := os.ReadDir(parent); err == nil && len(remaining) == 0 {
		_ = os.Remove(parent)
	}
	return nil
}

func (item *stage) openCommitted(artifact artifacts.Artifact) (io.ReadCloser, error) {
	path := filepath.Join(
		item.store.packageDir(item.request.PURL),
		item.store.entryKey(artifact),
		artifactName,
	)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open committed artifact: %w", err)
	}
	return file, nil
}

func writeFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
