package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addIntegrityCmd(rootCmd)
}

func addIntegrityCmd(parent *cobra.Command) {
	integrityCmd := &cobra.Command{
		Use:   "integrity",
		Short: "Show lockfile integrity hashes",
		Long: `Display integrity hashes for lockfile dependencies and detect
drift where the same version has different hashes across manifests.`,
		RunE: runIntegrity,
	}

	integrityCmd.Flags().StringP("commit", "c", "", "Check integrity at specific commit (default: HEAD)")
	integrityCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	integrityCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	integrityCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	integrityCmd.Flags().Bool("drift", false, "Only show packages with integrity drift")
	integrityCmd.Flags().Bool("registry", false, "Check integrity against package registry")
	integrityCmd.Flags().Bool("stateless", false, "Parse manifests directly without database")
	parent.AddCommand(integrityCmd)
}

type IntegrityEntry struct {
	Name             string   `json:"name"`
	Ecosystem        string   `json:"ecosystem"`
	Version          string   `json:"version"`
	Integrity        string   `json:"integrity"`
	ManifestPath     string   `json:"manifest_path"`
	HasDrift         bool     `json:"has_drift,omitempty"`
	OtherHashes      []string `json:"other_hashes,omitempty"`
	RegistryMismatch bool     `json:"registry_mismatch,omitempty"`
	RegistryHash     string   `json:"registry_hash,omitempty"`
}

type IntegrityDrift struct {
	Name      string            `json:"name"`
	Ecosystem string            `json:"ecosystem"`
	Version   string            `json:"version"`
	Hashes    map[string]string `json:"hashes"` // manifest_path -> integrity
}

type RegistryMismatch struct {
	Name         string `json:"name"`
	Ecosystem    string `json:"ecosystem"`
	Version      string `json:"version"`
	LocalHash    string `json:"local_hash"`
	RegistryHash string `json:"registry_hash"`
	ManifestPath string `json:"manifest_path"`
}

func runIntegrity(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")
	driftOnly, _ := cmd.Flags().GetBool("drift")
	checkRegistry, _ := cmd.Flags().GetBool("registry")
	stateless, _ := cmd.Flags().GetBool("stateless")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	var deps []database.Dependency

	if stateless {
		deps, err = listStateless(repo, commit)
		if err != nil {
			return err
		}
	} else {
		dbPath := repo.DatabasePath()
		if !database.Exists(dbPath) {
			return fmt.Errorf("database not found. Run 'git pkgs init' first")
		}

		db, err := database.Open(dbPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer func() { _ = db.Close() }()

		var branch *database.BranchInfo
		if branchName != "" {
			branch, err = db.GetBranch(branchName)
			if err != nil {
				return fmt.Errorf("branch %q not found: %w", branchName, err)
			}
		} else {
			branch, err = db.GetDefaultBranch()
			if err != nil {
				return fmt.Errorf("getting branch: %w", err)
			}
		}

		if commit != "" {
			deps, err = db.GetDependenciesAtRef(commit, branch.ID)
		} else {
			deps, err = db.GetLatestDependencies(branch.ID)
		}
		if err != nil {
			return fmt.Errorf("getting dependencies: %w", err)
		}
	}

	// Filter by ecosystem
	if ecosystem != "" {
		var filtered []database.Dependency
		for _, d := range deps {
			if d.Ecosystem == ecosystem {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	// Handle registry mismatch check mode
	if checkRegistry {
		return runRegistryCheck(cmd, deps, format)
	}

	// Filter to lockfile deps with integrity hashes
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "lockfile" && d.Integrity != "" {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies with integrity hashes found.")
		return nil
	}

	// Group by name+version to detect drift
	type key struct {
		name, version string
	}
	groups := make(map[key][]database.Dependency)
	for _, d := range lockfileDeps {
		k := key{d.Name, d.Requirement}
		groups[k] = append(groups[k], d)
	}

	// Find drift
	var entries []IntegrityEntry
	var drifts []IntegrityDrift

	for k, deps := range groups {
		// Check if all hashes are the same
		hashSet := make(map[string]string) // hash -> manifest
		for _, d := range deps {
			hashSet[d.Integrity] = d.ManifestPath
		}

		hasDrift := len(hashSet) > 1

		if driftOnly && !hasDrift {
			continue
		}

		if hasDrift {
			drift := IntegrityDrift{
				Name:      k.name,
				Ecosystem: deps[0].Ecosystem,
				Version:   k.version,
				Hashes:    make(map[string]string),
			}
			for _, d := range deps {
				drift.Hashes[d.ManifestPath] = d.Integrity
			}
			drifts = append(drifts, drift)
		}

		for _, d := range deps {
			var otherHashes []string
			if hasDrift {
				for h := range hashSet {
					if h != d.Integrity {
						otherHashes = append(otherHashes, h)
					}
				}
			}

			entries = append(entries, IntegrityEntry{
				Name:         d.Name,
				Ecosystem:    d.Ecosystem,
				Version:      d.Requirement,
				Integrity:    d.Integrity,
				ManifestPath: d.ManifestPath,
				HasDrift:     hasDrift,
				OtherHashes:  otherHashes,
			})
		}
	}

	// Sort by name
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].ManifestPath < entries[j].ManifestPath
	})

	if format == "json" {
		if driftOnly {
			return outputDriftJSON(cmd, drifts)
		}
		return outputIntegrityJSON(cmd, entries)
	}

	if driftOnly {
		return outputDriftText(cmd, drifts)
	}
	return outputIntegrityText(cmd, entries)
}

func outputIntegrityJSON(cmd *cobra.Command, entries []IntegrityEntry) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

func outputDriftJSON(cmd *cobra.Command, drifts []IntegrityDrift) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(drifts)
}

func outputIntegrityText(cmd *cobra.Command, entries []IntegrityEntry) error {
	// Group by manifest path
	byManifest := make(map[string][]IntegrityEntry)
	for _, e := range entries {
		byManifest[e.ManifestPath] = append(byManifest[e.ManifestPath], e)
	}

	var paths []string
	for p := range byManifest {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", path)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", len(path)))

		for _, e := range byManifest[path] {
			hash := e.Integrity
			if len(hash) > 40 {
				hash = hash[:40] + "..."
			}
			line := fmt.Sprintf("  %s@%s  %s", e.Name, e.Version, hash)
			if e.HasDrift {
				line += "  [DRIFT]"
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

func outputDriftText(cmd *cobra.Command, drifts []IntegrityDrift) error {
	if len(drifts) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No integrity drift detected.")
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d packages with integrity drift:\n\n", len(drifts))

	for _, d := range drifts {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s@%s (%s)\n", d.Name, d.Version, d.Ecosystem)
		for manifest, hash := range d.Hashes {
			if len(hash) > 40 {
				hash = hash[:40] + "..."
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", manifest, hash)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}

func runRegistryCheck(cmd *cobra.Command, deps []database.Dependency, format string) error {
	// Filter to lockfile deps with integrity hashes
	var lockfileDeps []database.Dependency
	for _, d := range deps {
		if d.ManifestKind == "lockfile" && d.Integrity != "" && d.Requirement != "" {
			lockfileDeps = append(lockfileDeps, d)
		}
	}

	if len(lockfileDeps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies with integrity hashes found.")
		return nil
	}

	// Create ecosystems client
	client, err := ecosystems.NewClient("git-pkgs/1.0")
	if err != nil {
		return fmt.Errorf("creating ecosystems client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Check each dependency against registry
	var mismatches []RegistryMismatch
	checked := 0
	skipped := 0

	// Deduplicate by name+version to avoid redundant API calls
	type key struct{ name, version, ecosystem string }
	seen := make(map[key]string) // key -> registry integrity

	for _, d := range lockfileDeps {
		k := key{d.Name, d.Requirement, d.Ecosystem}

		var registryHash string
		if cached, ok := seen[k]; ok {
			registryHash = cached
		} else {
			registry := ecosystemToRegistry(d.Ecosystem)
			if registry == "" {
				skipped++
				continue
			}

			version, err := client.GetVersion(ctx, registry, d.Name, d.Requirement)
			if err != nil || version == nil {
				skipped++
				continue
			}

			if version.Integrity != nil {
				registryHash = *version.Integrity
			}
			seen[k] = registryHash
			checked++
		}

		if registryHash == "" {
			continue
		}

		// Compare hashes (normalize by comparing just the hash part)
		if !hashesMatch(d.Integrity, registryHash) {
			mismatches = append(mismatches, RegistryMismatch{
				Name:         d.Name,
				Ecosystem:    d.Ecosystem,
				Version:      d.Requirement,
				LocalHash:    d.Integrity,
				RegistryHash: registryHash,
				ManifestPath: d.ManifestPath,
			})
		}
	}

	if format == "json" {
		return outputRegistryMismatchJSON(cmd, mismatches, checked, skipped)
	}
	return outputRegistryMismatchText(cmd, mismatches, checked, skipped)
}

func hashesMatch(local, registry string) bool {
	// Normalize hashes for comparison
	// Lockfiles may use different formats:
	// - npm: sha512-xxx or sha1-xxx
	// - ecosyste.ms may return similar format

	// If they're exactly equal, match
	if local == registry {
		return true
	}

	// Extract just the hash portion after the algorithm prefix
	localHash := extractHashValue(local)
	registryHash := extractHashValue(registry)

	if localHash != "" && registryHash != "" {
		return localHash == registryHash
	}

	return false
}

func extractHashValue(hash string) string {
	// Handle formats like "sha512-abcdef..." or "sha256:abcdef..."
	for _, sep := range []string{"-", ":"} {
		if idx := strings.Index(hash, sep); idx > 0 {
			return hash[idx+1:]
		}
	}
	return hash
}

type RegistryCheckResult struct {
	Mismatches []RegistryMismatch `json:"mismatches"`
	Checked    int                `json:"checked"`
	Skipped    int                `json:"skipped"`
}

func outputRegistryMismatchJSON(cmd *cobra.Command, mismatches []RegistryMismatch, checked, skipped int) error {
	result := RegistryCheckResult{
		Mismatches: mismatches,
		Checked:    checked,
		Skipped:    skipped,
	}
	if result.Mismatches == nil {
		result.Mismatches = []RegistryMismatch{}
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputRegistryMismatchText(cmd *cobra.Command, mismatches []RegistryMismatch, checked, skipped int) error {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Registry integrity check: %d packages checked", checked)
	if skipped > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), " (%d skipped)", skipped)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	if len(mismatches) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), Green("No registry mismatches detected."))
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s Found %d packages with registry mismatches:\n\n", Red("WARNING:"), len(mismatches))

	for _, m := range mismatches {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s@%s (%s)\n", m.Name, m.Version, m.Ecosystem)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Manifest: %s\n", m.ManifestPath)

		localHash := m.LocalHash
		if len(localHash) > 50 {
			localHash = localHash[:50] + "..."
		}
		registryHash := m.RegistryHash
		if len(registryHash) > 50 {
			registryHash = registryHash[:50] + "..."
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Local:    %s\n", Red(localHash))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Registry: %s\n", Green(registryHash))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return fmt.Errorf("registry integrity mismatches found")
}
