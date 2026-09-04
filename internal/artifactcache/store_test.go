package artifactcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/artifacts"
	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/integrity"
	"github.com/opencontainers/go-digest"
)

const cacheTestPURL = "pkg:pypi/example@1.0.0"

func TestStagePublishesOnlyOnCommit(t *testing.T) {
	store := testStore(t)
	content := []byte("package bytes")
	request := acquire.Request{PURL: cacheTestPURL, Filename: "example.whl", Integrity: testIntegrity(t, content)}
	staged, err := store.Stage(context.Background(), request, acquire.Source{URL: "https://files.example/example.whl"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Write(content); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(context.Background(), request); err != acquire.ErrNotFound {
		t.Fatalf("Open before Commit error = %v, want ErrNotFound", err)
	}

	artifact := testArtifact(t, request.PURL, request.Filename, content)
	body, err := staged.Commit(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, body); got != string(content) {
		t.Errorf("committed body = %q, want %q", got, content)
	}
	_ = body.Close()

	entry, err := store.Open(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = entry.Body.Close() }()
	if entry.Artifact != artifact {
		t.Errorf("Artifact = %+v, want %+v", entry.Artifact, artifact)
	}
	if got := readAll(t, entry.Body); got != string(content) {
		t.Errorf("cached body = %q, want %q", got, content)
	}
}

func TestDiscardRemovesStage(t *testing.T) {
	store := testStore(t)
	request := acquire.Request{PURL: cacheTestPURL, Filename: "example.whl"}
	staged, err := store.Stage(context.Background(), request, acquire.Source{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staged.Write([]byte("discarded")); err != nil {
		t.Fatal(err)
	}
	if err := staged.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(context.Background(), request); err != acquire.ErrNotFound {
		t.Fatalf("Open error = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(store.packageDir(request.PURL)); !os.IsNotExist(err) {
		t.Errorf("package dir left behind after discard: %v", err)
	}
}

func TestDiscardKeepsPackageDirWithCommittedEntry(t *testing.T) {
	store := testStore(t)
	commitTestArtifact(t, store, "kept.whl", []byte("committed"))
	request := acquire.Request{PURL: cacheTestPURL, Filename: "abandoned.whl"}
	staged, err := store.Stage(context.Background(), request, acquire.Source{})
	if err != nil {
		t.Fatal(err)
	}
	if err := staged.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry, err := store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: "kept.whl"})
	if err != nil {
		t.Fatalf("committed entry lost after discard: %v", err)
	}
	_ = entry.Body.Close()
}

func TestOpenSelectsByFilenameAndIntegrity(t *testing.T) {
	store := testStore(t)
	first := []byte("first wheel")
	second := []byte("second wheel")
	commitTestArtifact(t, store, "first.whl", first)
	commitTestArtifact(t, store, "second.whl", second)

	if _, err := store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL}); err == nil {
		t.Fatal("unqualified Open error = nil")
	}
	entry, err := store.Open(context.Background(), acquire.Request{
		PURL:      cacheTestPURL,
		Integrity: testIntegrity(t, second),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = entry.Body.Close() }()
	if entry.Artifact.Filename != "second.whl" {
		t.Errorf("Filename = %q, want second.whl", entry.Artifact.Filename)
	}
	if got := readAll(t, entry.Body); got != string(second) {
		t.Errorf("Body = %q, want %q", got, second)
	}
}

func TestOpenDetectsCorruptContent(t *testing.T) {
	store := testStore(t)
	content := []byte("original")
	artifact := commitTestArtifact(t, store, "example.whl", content)
	path := filepath.Join(store.packageDir(cacheTestPURL), store.entryKey(artifact), artifactName)
	if err := os.WriteFile(path, []byte("changed!"), filePermissions); err != nil {
		t.Fatal(err)
	}

	_, err := store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: artifact.Filename})
	if err == nil || !strings.Contains(err.Error(), "content digest") {
		t.Fatalf("Open error = %v, want content digest failure", err)
	}
}

func TestTrimRemovesOldestUntilUnderCap(t *testing.T) {
	store := testStore(t)
	old := commitTestArtifact(t, store, "old.whl", bytes.Repeat([]byte("a"), 100))
	oldPath := filepath.Join(store.packageDir(cacheTestPURL), store.entryKey(old), artifactName)
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatal(err)
	}
	fresh := commitTestArtifact(t, store, "new.whl", bytes.Repeat([]byte("b"), 100))

	if err := store.Trim(300); err != nil {
		t.Fatal(err)
	}
	entry, err := store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: old.Filename})
	if err != nil {
		t.Fatalf("Trim above total removed an entry: %v", err)
	}
	_ = entry.Body.Close()

	if err := store.Trim(150); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: old.Filename}); err != acquire.ErrNotFound {
		t.Fatalf("old entry error = %v, want ErrNotFound", err)
	}
	entry, err = store.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: fresh.Filename})
	if err != nil {
		t.Fatalf("fresh entry removed: %v", err)
	}
	_ = entry.Body.Close()
}

func TestOpenEnforcesSizeLimit(t *testing.T) {
	store := testStore(t)
	artifact := commitTestArtifact(t, store, "example.whl", []byte("five!"))
	limited, err := New(store.root, 4)
	if err != nil {
		t.Fatal(err)
	}
	_, err = limited.Open(context.Background(), acquire.Request{PURL: cacheTestPURL, Filename: artifact.Filename})
	if err == nil || !strings.Contains(err.Error(), "limit is 4") {
		t.Fatalf("Open error = %v, want size limit", err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func commitTestArtifact(t *testing.T, store *Store, filename string, content []byte) artifacts.Artifact {
	t.Helper()
	request := acquire.Request{PURL: cacheTestPURL, Filename: filename, Integrity: testIntegrity(t, content)}
	staged, err := store.Stage(context.Background(), request, acquire.Source{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(staged, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	artifact := testArtifact(t, request.PURL, filename, content)
	body, err := staged.Commit(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	_ = body.Close()
	return artifact
}

func testArtifact(t *testing.T, packageURL, filename string, content []byte) artifacts.Artifact {
	t.Helper()
	sum := sha256.Sum256(content)
	artifact, err := artifacts.New(
		packageURL,
		digest.Digest(fmt.Sprintf("sha256:%x", sum)),
		int64(len(content)),
		filename,
		"application/octet-stream",
	)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func testIntegrity(t *testing.T, content []byte) integrity.SRI {
	t.Helper()
	sum := sha256.Sum256(content)
	item, err := integrity.ParseHex(integrity.SHA256, fmt.Sprintf("%x", sum))
	if err != nil {
		t.Fatal(err)
	}
	return integrity.SRI{item}
}

func readAll(t *testing.T, reader io.Reader) string {
	t.Helper()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
