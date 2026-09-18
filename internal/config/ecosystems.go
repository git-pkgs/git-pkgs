package config

import (
	"sort"
	"strings"

	"github.com/git-pkgs/purl"
	gitconfig "github.com/go-git/go-git/v6/config"
)

const (
	EcosystemsKey        = "pkgs.ecosystems"
	IgnoredEcosystemsKey = "pkgs.ignoredEcosystems"
)

type EcosystemFilter struct {
	allowed map[string]bool
	ignored map[string]bool
}

func LoadEcosystemFilter(cfg *gitconfig.Config) EcosystemFilter {
	section := cfg.Raw.Section("pkgs")
	allowed := configValues(section.Options.GetAll("ecosystems"))
	ignored := configValues(section.Options.GetAll("ignoredEcosystems"))
	return NewEcosystemFilter(allowed, ignored)
}

func NewEcosystemFilter(allowed, ignored []string) EcosystemFilter {
	return EcosystemFilter{
		allowed: ecosystemSet(allowed),
		ignored: ecosystemSet(ignored),
	}
}

func (f EcosystemFilter) Empty() bool {
	return len(f.allowed) == 0 && len(f.ignored) == 0
}

func (f EcosystemFilter) Allows(ecosystem string) bool {
	normalized := normalizeEcosystem(ecosystem)
	if normalized == "" {
		return true
	}
	if f.ignored[normalized] {
		return false
	}
	return len(f.allowed) == 0 || f.allowed[normalized]
}

// Values returns the canonical ecosystem values configured for the allow and
// ignore lists. The returned slices are sorted for deterministic query inputs.
func (f EcosystemFilter) Values() (allowed, ignored []string) {
	allowed = filterValues(f.allowed)
	ignored = filterValues(f.ignored)
	return allowed, ignored
}

// StoredValues returns filter values expanded to include the PURL type aliases
// that manifest parsers may persist in the database.
func (f EcosystemFilter) StoredValues() (allowed, ignored []string) {
	allowed = storedEcosystemValues(f.allowed)
	ignored = storedEcosystemValues(f.ignored)
	return allowed, ignored
}

func storedEcosystemValues(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	stored := make(map[string]bool, len(values)*2)
	for ecosystem := range values {
		stored[ecosystem] = true
		purlType := purl.EcosystemToPURLType(ecosystem)
		if purlType == "" {
			continue
		}
		stored[purlType] = true
		if mapped := purl.PURLTypeToEcosystem(purlType); mapped != "" {
			stored[mapped] = true
		}
	}
	return filterValues(stored)
}

func filterValues(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func configValues(raw []string) []string {
	var values []string
	for _, value := range raw {
		values = append(values, splitConfigValues(value)...)
	}
	return values
}

func splitConfigValues(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == ',' || r == ' ' || r == '\t'
	})
	values := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func ecosystemSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if normalized := normalizeEcosystem(value); normalized != "" {
			set[normalized] = true
		}
	}
	return set
}

func normalizeEcosystem(ecosystem string) string {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	if ecosystem == "" {
		return ""
	}
	if ecosystem == "go" {
		return "golang"
	}
	if mapped := purl.PURLTypeToEcosystem(ecosystem); mapped != "" {
		return strings.ToLower(mapped)
	}
	return ecosystem
}
