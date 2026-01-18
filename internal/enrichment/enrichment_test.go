package enrichment

import (
	"testing"
)

func TestExtractEcosystem(t *testing.T) {
	tests := []struct {
		purl      string
		ecosystem string
	}{
		{"pkg:npm/lodash", "npm"},
		{"pkg:gem/rails", "gem"},
		{"pkg:cargo/serde@1.0.0", "cargo"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			ecosystem := extractEcosystem(tt.purl)
			if ecosystem != tt.ecosystem {
				t.Errorf("got %q, want %q", ecosystem, tt.ecosystem)
			}
		})
	}
}

func TestNewClientDefault(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	// Default should be HybridClient
	if _, ok := client.(*HybridClient); !ok {
		t.Errorf("expected *HybridClient, got %T", client)
	}
}

func TestNewClientDirect(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "1")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if _, ok := client.(*RegistriesClient); !ok {
		t.Errorf("expected *RegistriesClient, got %T", client)
	}
}

func TestDirectMode(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "")

	// Test env var takes effect
	if directMode() {
		t.Error("directMode() should be false with no env var set")
	}

	t.Setenv("GIT_PKGS_DIRECT", "1")
	if !directMode() {
		t.Error("directMode() should be true with GIT_PKGS_DIRECT=1")
	}

	t.Setenv("GIT_PKGS_DIRECT", "yes")
	if !directMode() {
		t.Error("directMode() should be true with GIT_PKGS_DIRECT=yes")
	}
}

func TestHasRepositoryURL(t *testing.T) {
	tests := []struct {
		purl string
		want bool
	}{
		{"pkg:npm/lodash", false},
		{"pkg:npm/lodash@4.17.21", false},
		{"pkg:npm/%40mycompany/utils?repository_url=https://npm.mycompany.com", true},
		{"pkg:npm/%40mycompany/utils@1.0.0?repository_url=https://npm.mycompany.com", true},
		{"pkg:pypi/requests?repository_url=https://pypi.internal.com/simple", true},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got := hasRepositoryURL(tt.purl)
			if got != tt.want {
				t.Errorf("hasRepositoryURL(%q) = %v, want %v", tt.purl, got, tt.want)
			}
		})
	}
}

