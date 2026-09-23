package config

import (
	"strings"
	"testing"

	gitconfig "github.com/go-git/go-git/v6/config"
)

func TestEcosystemFilterAllowsAllWhenUnset(t *testing.T) {
	filter := NewEcosystemFilter(nil, nil)

	for _, ecosystem := range []string{"npm", "rubygems", "golang"} {
		if !filter.Allows(ecosystem) {
			t.Fatalf("expected unset filter to allow %s", ecosystem)
		}
	}
}

func TestEcosystemFilterAllowList(t *testing.T) {
	filter := NewEcosystemFilter([]string{"npm", "gem"}, nil)

	if !filter.Allows("npm") {
		t.Fatal("expected npm to be allowed")
	}
	if !filter.Allows("rubygems") {
		t.Fatal("expected gem alias to allow rubygems")
	}
	if filter.Allows("pypi") {
		t.Fatal("expected pypi to be filtered")
	}
}

func TestEcosystemFilterIgnoreListWins(t *testing.T) {
	filter := NewEcosystemFilter([]string{"npm", "rubygems"}, []string{"npm"})

	if filter.Allows("npm") {
		t.Fatal("expected ignored npm to be filtered")
	}
	if !filter.Allows("rubygems") {
		t.Fatal("expected rubygems to remain allowed")
	}
}

func TestEcosystemFilterNormalizesGoAlias(t *testing.T) {
	filter := NewEcosystemFilter(nil, []string{"go"})

	if filter.Allows("golang") {
		t.Fatal("expected go alias to exclude golang")
	}
}

func TestEcosystemFilterValues(t *testing.T) {
	filter := NewEcosystemFilter([]string{"rubygems", "npm"}, []string{"pypi", "go"})
	allowed, ignored := filter.Values()

	if got, want := strings.Join(allowed, ","), "npm,rubygems"; got != want {
		t.Fatalf("allowed = %q, want %q", got, want)
	}
	if got, want := strings.Join(ignored, ","), "golang,pypi"; got != want {
		t.Fatalf("ignored = %q, want %q", got, want)
	}
}

func TestEcosystemFilterStoredValuesIncludesPURLAliases(t *testing.T) {
	filter := NewEcosystemFilter(
		[]string{"rubygems", "packagist", "github-actions", "alpine", "arch"},
		nil,
	)
	allowed, ignored := filter.StoredValues()

	if len(ignored) != 0 {
		t.Fatalf("ignored = %#v, want none", ignored)
	}
	want := "alpine,alpm,apk,arch,composer,gem,github-actions,githubactions,packagist,rubygems"
	if got := strings.Join(allowed, ","); got != want {
		t.Fatalf("allowed = %q, want %q", got, want)
	}
}

func TestSplitConfigValues(t *testing.T) {
	values := splitConfigValues("npm, rubygems\npypi\tgolang")

	want := []string{"npm", "rubygems", "pypi", "golang"}
	if len(values) != len(want) {
		t.Fatalf("got %d values, want %d: %#v", len(values), len(want), values)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("value %d = %q, want %q", i, values[i], want[i])
		}
	}
}

func TestLoadEcosystemFilter(t *testing.T) {
	cfg, err := gitconfig.ReadConfig(strings.NewReader(`[pkgs]
	ecosystems = npm, rubygems
	ecosystems = golang
	ignoredEcosystems = pypi
`))
	if err != nil {
		t.Fatal(err)
	}
	filter := LoadEcosystemFilter(cfg)
	allowed, ignored := filter.Values()
	if got, want := strings.Join(allowed, ","), "golang,npm,rubygems"; got != want {
		t.Fatalf("allowed=%q, want %q", got, want)
	}
	if got, want := strings.Join(ignored, ","), "pypi"; got != want {
		t.Fatalf("ignored=%q, want %q", got, want)
	}
}
