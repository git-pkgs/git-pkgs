package artifactregistry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/git-pkgs/artifacts/acquire"
	"github.com/git-pkgs/integrity"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
)

func TestParseIntegrity(t *testing.T) {
	sum := sha256.Sum256([]byte("package"))
	hexDigest := fmt.Sprintf("%x", sum)
	sriDigest := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty"},
		{name: "SRI", value: sriDigest, want: sriDigest},
		{name: "prefixed hex", value: "sha256-" + hexDigest, want: sriDigest},
		{name: "colon hex", value: "sha256:" + hexDigest, want: sriDigest},
		{name: "bare hex", value: hexDigest, want: sriDigest},
		{name: "Go module sum", value: "h1:opaque-module-sum"},
		{name: "SHA-1", value: "sha1-0123456789012345678901234567890123456789"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata, err := ParseIntegrity(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got := integrity.FormatSRI(metadata); got != test.want {
				t.Errorf("ParseIntegrity() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseIntegrityRejectsMalformedSupportedDigest(t *testing.T) {
	if _, err := ParseIntegrity("sha512-not-a-digest"); err == nil {
		t.Fatal("ParseIntegrity() error = nil")
	}
}

func TestParseIntegrityAcceptsMixedEncodings(t *testing.T) {
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	value := "sha256-" + base64.StdEncoding.EncodeToString(first[:]) +
		" sha256-" + fmt.Sprintf("%x", second)
	metadata, err := ParseIntegrity(value)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 2 {
		t.Fatalf("digests = %d, want 2", len(metadata))
	}
}

func TestParseIntegrityIgnoresGoSumAlongsideSupportedDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("package"))
	want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	metadata, err := ParseIntegrity("h1:opaque-module-sum " + want)
	if err != nil {
		t.Fatal(err)
	}
	if got := integrity.FormatSRI(metadata); got != want {
		t.Errorf("ParseIntegrity() = %q, want %q", got, want)
	}
}

func TestNativeIntegrity(t *testing.T) {
	sum := sha256.Sum256([]byte("package"))
	item, err := integrity.ParseHex(integrity.SHA256, fmt.Sprintf("%x", sum))
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256-" + fmt.Sprintf("%x", sum)
	if got := nativeIntegrity(integrity.SRI{item}); got != want {
		t.Errorf("nativeIntegrity() = %q, want %q", got, want)
	}
}

func TestResolveSelectsArtifactByIntegrity(t *testing.T) {
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/pypi/example/json" {
			t.Errorf("path = %q", request.URL.Path)
		}
		_, _ = fmt.Fprintf(response, `{
			"info":{"name":"example"},
			"releases":{"1.0.0":[
				{"digests":{"sha256":"%s"},"url":"https://files.example.invalid/example-1.0.0.tar.gz"},
				{"digests":{"sha256":"%s"},"url":"https://files.example.invalid/example-1.0.0-py3-none-any.whl"}
			]}
		}`, first, second)
	}))
	defer server.Close()

	client := New("test")
	defer func() { _ = client.Close() }()
	client.registryClient = registries.NewClient(registries.WithHTTPClient(server.Client()))
	metadata, err := ParseIntegrity("sha256-" + second)
	if err != nil {
		t.Fatal(err)
	}
	packageURL := purl.New("pypi", "", "example", "1.0.0", map[string]string{
		"repository_url": server.URL,
	}).String()

	source, err := client.Resolve(context.Background(), acquire.Request{
		PURL:      packageURL,
		Integrity: metadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.Filename != "example-1.0.0-py3-none-any.whl" {
		t.Errorf("Filename = %q", source.Filename)
	}
	if got := integrity.FormatSRI(source.Integrity); got != integrity.FormatSRI(metadata) {
		t.Errorf("Integrity = %q, want %q", got, integrity.FormatSRI(metadata))
	}
}
