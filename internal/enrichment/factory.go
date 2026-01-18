package enrichment

import (
	"os"
	"os/exec"
	"strings"
)

// NewClient creates an enrichment client based on configuration.
//
// By default, uses a hybrid approach:
//   - PURLs with repository_url qualifier → direct registry query
//   - Other PURLs → ecosyste.ms API
//
// To skip ecosyste.ms and query all registries directly:
//   - Set GIT_PKGS_DIRECT=1 environment variable, or
//   - Set git config: git config --global pkgs.direct true
func NewClient() (Client, error) {
	if directMode() {
		return NewRegistriesClient(), nil
	}
	return NewHybridClient()
}

// directMode checks if direct registry mode is enabled.
// Environment variable takes precedence over git config.
func directMode() bool {
	// Check environment variable first
	if os.Getenv("GIT_PKGS_DIRECT") != "" {
		return true
	}

	// Check git config
	out, err := exec.Command("git", "config", "--get", "pkgs.direct").Output()
	if err != nil {
		return false
	}

	val := strings.TrimSpace(string(out))
	return val == "true" || val == "1" || val == "yes"
}
