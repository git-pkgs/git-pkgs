package enrichment

import (
	"os"
	"testing"
)

func TestParsePURLForEcosystems(t *testing.T) {
	tests := []struct {
		purl      string
		ecosystem string
		name      string
	}{
		{"pkg:npm/lodash", "npm", "lodash"},
		{"pkg:npm/lodash@4.17.21", "npm", "lodash"},
		{"pkg:npm/%40babel/core", "npm", "@babel/core"},
		{"pkg:npm/%40babel/core@7.24.0", "npm", "@babel/core"},
		{"pkg:gem/rails", "gem", "rails"},
		{"pkg:gem/rails@7.1.0", "gem", "rails"},
		{"pkg:pypi/requests", "pypi", "requests"},
		{"pkg:cargo/serde", "cargo", "serde"},
		{"pkg:golang/github.com/gorilla/mux", "golang", "github.com/gorilla/mux"},
		{"pkg:maven/org.apache.commons/commons-lang3", "maven", "org.apache.commons/commons-lang3"},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			ecosystem, name := parsePURLForEcosystems(tt.purl)
			if ecosystem != tt.ecosystem {
				t.Errorf("ecosystem: got %q, want %q", ecosystem, tt.ecosystem)
			}
			if name != tt.name {
				t.Errorf("name: got %q, want %q", name, tt.name)
			}
		})
	}
}

func TestParsePURLWithVersion(t *testing.T) {
	tests := []struct {
		purl      string
		ecosystem string
		name      string
		version   string
	}{
		{"pkg:npm/lodash@4.17.21", "npm", "lodash", "4.17.21"},
		{"pkg:npm/%40babel/core@7.24.0", "npm", "@babel/core", "7.24.0"},
		{"pkg:gem/rails@7.1.0", "gem", "rails", "7.1.0"},
		{"pkg:cargo/serde@1.0.0", "cargo", "serde", "1.0.0"},
		{"pkg:npm/lodash", "npm", "lodash", ""},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			ecosystem, name, version := parsePURLWithVersion(tt.purl)
			if ecosystem != tt.ecosystem {
				t.Errorf("ecosystem: got %q, want %q", ecosystem, tt.ecosystem)
			}
			if name != tt.name {
				t.Errorf("name: got %q, want %q", name, tt.name)
			}
			if version != tt.version {
				t.Errorf("version: got %q, want %q", version, tt.version)
			}
		})
	}
}

func TestEcosystemToRegistry(t *testing.T) {
	tests := []struct {
		ecosystem string
		registry  string
	}{
		{"npm", "npmjs.org"},
		{"gem", "rubygems.org"},
		{"pypi", "pypi.org"},
		{"cargo", "crates.io"},
		{"golang", "proxy.golang.org"},
		{"maven", "repo1.maven.org"},
		{"nuget", "nuget.org"},
		{"composer", "packagist.org"},
		{"hex", "hex.pm"},
		{"pub", "pub.dev"},
		{"cocoapods", "cocoapods.org"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			registry := ecosystemToRegistry(tt.ecosystem)
			if registry != tt.registry {
				t.Errorf("got %q, want %q", registry, tt.registry)
			}
		})
	}
}

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
	os.Unsetenv("GIT_PKGS_DIRECT")

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
	os.Setenv("GIT_PKGS_DIRECT", "1")
	defer os.Unsetenv("GIT_PKGS_DIRECT")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if _, ok := client.(*RegistriesClient); !ok {
		t.Errorf("expected *RegistriesClient, got %T", client)
	}
}

func TestDirectMode(t *testing.T) {
	// Save and clear env
	orig := os.Getenv("GIT_PKGS_DIRECT")
	os.Unsetenv("GIT_PKGS_DIRECT")
	defer func() {
		if orig != "" {
			os.Setenv("GIT_PKGS_DIRECT", orig)
		} else {
			os.Unsetenv("GIT_PKGS_DIRECT")
		}
	}()

	// Test env var takes effect
	if directMode() {
		t.Error("directMode() should be false with no env var set")
	}

	os.Setenv("GIT_PKGS_DIRECT", "1")
	if !directMode() {
		t.Error("directMode() should be true with GIT_PKGS_DIRECT=1")
	}

	os.Setenv("GIT_PKGS_DIRECT", "yes")
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

