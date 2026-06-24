package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestEnrichmentOptions(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want int
	}{
		{"user agent only", nil, 1},
		{"from", map[string]string{envEcosystemsFrom: "user@example.com"}, 2},
		{"api key", map[string]string{envEcosystemsAPIKey: "secret"}, 2},
		{"from and api key", map[string]string{
			envEcosystemsFrom:   "user@example.com",
			envEcosystemsAPIKey: "secret",
		}, 3},
		{"batch size", map[string]string{envEcosystemsBatchSize: "50"}, 2},
		{"invalid batch size ignored", map[string]string{envEcosystemsBatchSize: "abc"}, 1},
		{"zero batch size ignored", map[string]string{envEcosystemsBatchSize: "0"}, 1},
		{"all", map[string]string{
			envEcosystemsFrom:      "user@example.com",
			envEcosystemsAPIKey:    "secret",
			envEcosystemsBatchSize: "50",
		}, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, k := range []string{envEcosystemsFrom, envEcosystemsAPIKey, envEcosystemsBatchSize} {
				t.Setenv(k, tt.env[k])
			}
			got := enrichmentOptions()
			if len(got) != tt.want {
				t.Errorf("enrichmentOptions() returned %d options, want %d", len(got), tt.want)
			}
		})
	}
}

func TestWrapEcosystemsError(t *testing.T) {
	base := errors.New("bulk lookup: stream error: stream ID 1; INTERNAL_ERROR")

	t.Run("adds hint when no identity configured", func(t *testing.T) {
		t.Setenv(envEcosystemsFrom, "")
		t.Setenv(envEcosystemsAPIKey, "")

		got := wrapEcosystemsError(base)
		if !errors.Is(got, base) {
			t.Errorf("wrapped error does not unwrap to base error")
		}
		msg := got.Error()
		if !strings.Contains(msg, "INTERNAL_ERROR") {
			t.Errorf("wrapped error lost original message: %q", msg)
		}
		if !strings.Contains(msg, envEcosystemsFrom) {
			t.Errorf("wrapped error missing %s hint: %q", envEcosystemsFrom, msg)
		}
		if !strings.Contains(msg, envEcosystemsAPIKey) {
			t.Errorf("wrapped error missing %s hint: %q", envEcosystemsAPIKey, msg)
		}
		if !strings.Contains(msg, "polite pool") {
			t.Errorf("wrapped error missing polite pool hint: %q", msg)
		}
	})

	t.Run("passes through when from is set", func(t *testing.T) {
		t.Setenv(envEcosystemsFrom, "user@example.com")
		t.Setenv(envEcosystemsAPIKey, "")

		if got := wrapEcosystemsError(base); got != base {
			t.Errorf("wrapEcosystemsError() = %v, want unchanged %v", got, base)
		}
	})

	t.Run("passes through when api key is set", func(t *testing.T) {
		t.Setenv(envEcosystemsFrom, "")
		t.Setenv(envEcosystemsAPIKey, "secret")

		if got := wrapEcosystemsError(base); got != base {
			t.Errorf("wrapEcosystemsError() = %v, want unchanged %v", got, base)
		}
	})
}
