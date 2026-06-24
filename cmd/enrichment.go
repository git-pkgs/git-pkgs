package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/git-pkgs/enrichment"
)

const (
	envEcosystemsFrom      = "GIT_PKGS_ECOSYSTEMS_FROM"
	envEcosystemsAPIKey    = "GIT_PKGS_ECOSYSTEMS_API_KEY"
	envEcosystemsBatchSize = "GIT_PKGS_ECOSYSTEMS_BATCH_SIZE"
)

// NewEnrichmentClient is the constructor for the enrichment client.
// Tests can replace this to avoid external API calls.
var NewEnrichmentClient = enrichment.NewClient

// newEnrichmentClient builds an enrichment client with the standard
// git-pkgs user agent and any identity options supplied via environment
// variables. All commands that talk to ecosyste.ms should use this so
// that GIT_PKGS_ECOSYSTEMS_FROM and GIT_PKGS_ECOSYSTEMS_API_KEY are
// applied consistently.
func newEnrichmentClient() (enrichment.Client, error) {
	return NewEnrichmentClient(enrichmentOptions()...)
}

func enrichmentOptions() []enrichment.Option {
	opts := []enrichment.Option{
		enrichment.WithUserAgent(userAgent),
	}
	if from := os.Getenv(envEcosystemsFrom); from != "" {
		opts = append(opts, enrichment.WithFrom(from))
	}
	if key := os.Getenv(envEcosystemsAPIKey); key != "" {
		opts = append(opts, enrichment.WithAPIKey(key))
	}
	if raw := os.Getenv(envEcosystemsBatchSize); raw != "" {
		if size, err := strconv.Atoi(raw); err == nil && size > 0 {
			opts = append(opts, enrichment.WithBatchSize(size))
		}
	}
	return opts
}

// wrapEcosystemsError annotates ecosyste.ms request failures with a hint
// about the polite-pool environment variables so users hitting shared-pool
// rate limits or stream errors have a path forward. If an identity is
// already configured the error is returned unchanged.
func wrapEcosystemsError(err error) error {
	if os.Getenv(envEcosystemsFrom) != "" || os.Getenv(envEcosystemsAPIKey) != "" {
		return err
	}
	return fmt.Errorf(
		"%w\n"+
			"requests to ecosyste.ms without an identity share a common rate-limit pool; "+
			"set %s to your email address (or %s to an API key) to use the polite pool",
		err, envEcosystemsFrom, envEcosystemsAPIKey,
	)
}
