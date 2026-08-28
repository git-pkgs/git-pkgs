package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	"github.com/spf13/cobra"
)

const (
	sourceStatusOK          = "ok"
	sourceStatusError       = "error"
	sourceStatusUnsupported = "unsupported"
)

// SourceStatus describes the outcome of consulting one upstream for an ecosystem.
type SourceStatus struct {
	Ecosystem       string    `json:"ecosystem"`
	Upstream        string    `json:"upstream"`
	Status          string    `json:"status"`
	FetchedAt       time.Time `json:"fetched_at,omitzero"`
	CacheAgeSeconds *int64    `json:"cache_age_seconds,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// ResultEnvelope adds source health to command result rows.
type ResultEnvelope[T any] struct {
	Results  []T            `json:"results"`
	Sources  []SourceStatus `json:"sources"`
	Warnings []string       `json:"warnings,omitempty"`
}

type sourceKey struct {
	ecosystem string
	upstream  string
}

type sourceObservation struct {
	unsupported bool
	fetchedAt   time.Time
	errors      []error
}

type sourceTracker struct {
	observations map[sourceKey]*sourceObservation
}

func newSourceTracker() *sourceTracker {
	return &sourceTracker{observations: make(map[sourceKey]*sourceObservation)}
}

func sourceTrackerOrNew(trackers []*sourceTracker) *sourceTracker {
	if len(trackers) > 0 && trackers[0] != nil {
		return trackers[0]
	}
	return newSourceTracker()
}

func (t *sourceTracker) consider(ecosystem, upstream string, supported bool) {
	key := newSourceKey(ecosystem, upstream)
	observation := t.observation(key)
	if !supported {
		observation.unsupported = true
	}
}

func (t *sourceTracker) markOK(ecosystem, upstream string, fetchedAt time.Time) {
	observation := t.observation(newSourceKey(ecosystem, upstream))
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	fetchedAt = fetchedAt.UTC()
	if observation.fetchedAt.IsZero() || fetchedAt.After(observation.fetchedAt) {
		observation.fetchedAt = fetchedAt
	}
}

func (t *sourceTracker) markError(ecosystem, upstream string, err error) {
	if err == nil {
		return
	}
	observation := t.observation(newSourceKey(ecosystem, upstream))
	observation.errors = append(observation.errors, err)
}

func newSourceKey(ecosystem, upstream string) sourceKey {
	return sourceKey{ecosystem: canonicalSourceEcosystem(ecosystem), upstream: upstream}
}

func canonicalSourceEcosystem(ecosystem string) string {
	purlType := purl.EcosystemToPURLType(ecosystem)
	canonical := purl.PURLTypeToEcosystem(purlType)
	if canonical != "" {
		return canonical
	}
	return ecosystem
}

func (t *sourceTracker) observation(key sourceKey) *sourceObservation {
	observation := t.observations[key]
	if observation == nil {
		observation = &sourceObservation{}
		t.observations[key] = observation
	}
	return observation
}

func resultEnvelope[T any](t *sourceTracker, results []T, now time.Time) ResultEnvelope[T] {
	sources, warnings := t.statuses(now)
	return ResultEnvelope[T]{
		Results:  nonNilSlice(results),
		Sources:  nonNilSlice(sources),
		Warnings: warnings,
	}
}

func (t *sourceTracker) statuses(now time.Time) ([]SourceStatus, []string) {
	keys := make([]sourceKey, 0, len(t.observations))
	for key := range t.observations {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ecosystem != keys[j].ecosystem {
			return keys[i].ecosystem < keys[j].ecosystem
		}
		return keys[i].upstream < keys[j].upstream
	})

	if now.IsZero() {
		now = time.Now().UTC()
	}
	var warnings []string
	sources := make([]SourceStatus, 0, len(keys))
	for _, key := range keys {
		observation := t.observations[key]
		errorMessages := observationErrorMessages(observation)
		status := SourceStatus{Ecosystem: key.ecosystem, Upstream: key.upstream}
		switch {
		case observation.unsupported:
			status.Status = sourceStatusUnsupported
		case !observation.fetchedAt.IsZero():
			status.Status = sourceStatusOK
			status.FetchedAt = observation.fetchedAt.UTC()
			ageSeconds := int64(0)
			if age := now.Sub(status.FetchedAt); age > 0 {
				ageSeconds = int64(age / time.Second)
			}
			status.CacheAgeSeconds = &ageSeconds
			for _, message := range errorMessages {
				warnings = append(warnings, sourceWarning(key, errors.New(message)))
			}
		case len(errorMessages) > 0:
			status.Status = sourceStatusError
			status.Error = errorMessages[0]
		default:
			status.Status = sourceStatusError
			status.Error = "no source data was returned"
		}
		sources = append(sources, status)
	}
	return sources, warnings
}

func observationErrorMessages(observation *sourceObservation) []string {
	seen := make(map[string]bool)
	messages := make([]string, 0, len(observation.errors))
	for _, err := range observation.errors {
		if err == nil || seen[err.Error()] {
			continue
		}
		seen[err.Error()] = true
		messages = append(messages, err.Error())
	}
	sort.Strings(messages)
	return messages
}

func (t *sourceTracker) allUnavailable() bool {
	if len(t.observations) == 0 {
		return false
	}
	for _, observation := range t.observations {
		if !observation.fetchedAt.IsZero() && !observation.unsupported {
			return false
		}
	}
	return true
}

func (t *sourceTracker) unavailableError() error {
	if !t.allUnavailable() {
		return nil
	}
	sources, _ := t.statuses(time.Now().UTC())
	var errs []error
	for _, source := range sources {
		if source.Status != sourceStatusError {
			continue
		}
		errs = append(errs, fmt.Errorf("%s (%s): %s", source.Ecosystem, source.Upstream, source.Error))
	}
	if len(errs) == 0 {
		return fmt.Errorf("no supported sources available")
	}
	return fmt.Errorf("all sources failed: %w", errors.Join(errs...))
}

func (t *sourceTracker) observedError() error {
	keys := make([]sourceKey, 0, len(t.observations))
	for key := range t.observations {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ecosystem != keys[j].ecosystem {
			return keys[i].ecosystem < keys[j].ecosystem
		}
		return keys[i].upstream < keys[j].upstream
	})

	var errs []error
	for _, key := range keys {
		for _, err := range t.observations[key].errors {
			if err != nil {
				errs = append(errs, errors.New(sourceWarning(key, err)))
			}
		}
	}
	return errors.Join(errs...)
}

func sourceWarning(key sourceKey, err error) string {
	if key.upstream == "" {
		return fmt.Sprintf("%s: %v", key.ecosystem, err)
	}
	return fmt.Sprintf("%s (%s): %v", key.ecosystem, key.upstream, err)
}

func outputResultEnvelope[T any](cmd *cobra.Command, envelope ResultEnvelope[T]) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func registrySource(ecosystem string) (string, bool) {
	purlType := purl.EcosystemToPURLType(ecosystem)
	for _, supported := range registries.SupportedEcosystems() {
		if purl.EcosystemToPURLType(supported) == purlType {
			return sourceHostname(registries.DefaultURL(purlType)), true
		}
	}
	return "", false
}

func sourceHostname(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	return strings.TrimSuffix(strings.TrimPrefix(rawURL, "https://"), "/")
}

func ecosystemsFromDependencies(deps []database.Dependency) []string {
	seen := make(map[string]bool)
	for _, dep := range deps {
		if dep.Ecosystem != "" {
			seen[dep.Ecosystem] = true
		}
	}
	ecosystems := make([]string, 0, len(seen))
	for ecosystem := range seen {
		ecosystems = append(ecosystems, ecosystem)
	}
	sort.Strings(ecosystems)
	return ecosystems
}
