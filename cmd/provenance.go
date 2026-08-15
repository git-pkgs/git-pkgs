package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/provenance"
	"github.com/git-pkgs/purl"
	"github.com/spf13/cobra"
)

const provenanceLookupTimeout = 5 * time.Minute
const provenanceLookupConcurrency = 8

const (
	provenanceStatusTrustedPublishing = provenance.StatusTrustedPublishing
	provenanceStatusAttested          = provenance.StatusAttested
	provenanceStatusSigned            = provenance.StatusSigned
	provenanceStatusMissing           = provenance.StatusMissing
	provenanceStatusUnsupported       = provenance.StatusUnsupported
	provenanceStatusError             = provenance.StatusError
)

func addProvenanceCmd(parent *cobra.Command) {
	provenanceCmd := &cobra.Command{
		Use:   "provenance",
		Short: "Check dependency provenance metadata",
		Long: `Check resolved dependencies for registry provenance and attestation metadata.

The command reports verified trusted-publishing signals where registry APIs
expose them, registry attestations and signatures as weaker integrity signals,
and unsupported ecosystems explicitly instead of treating missing metadata as
verified.`,
		RunE: runProvenance,
	}

	provenanceCmd.Flags().StringP("commit", "c", "", "Check dependencies at specific commit (default: HEAD)")
	provenanceCmd.Flags().StringP("branch", "b", "", "Branch to query (default: current branch)")
	provenanceCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	provenanceCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	provenanceCmd.Flags().Bool("missing", false, "Only show dependencies without trusted-publishing provenance")
	parent.AddCommand(provenanceCmd)
}

type ProvenanceSummary struct {
	TotalDependencies      int `json:"total_dependencies"`
	CheckedDependencies    int `json:"checked_dependencies"`
	TrustedPublishing      int `json:"trusted_publishing"`
	AttestedDependencies   int `json:"attested_dependencies"`
	RegistrySignatures     int `json:"registry_signatures"`
	WithoutProvenance      int `json:"without_provenance"`
	UnsupportedEcosystems  int `json:"unsupported_ecosystems"`
	LookupErrors           int `json:"lookup_errors"`
	UnresolvedDependencies int `json:"unresolved_dependencies"`
}

type ProvenanceEntry struct {
	Name               string   `json:"name"`
	Ecosystem          string   `json:"ecosystem"`
	Version            string   `json:"version"`
	ManifestPath       string   `json:"manifest_path"`
	PURL               string   `json:"purl,omitempty"`
	Status             string   `json:"status"`
	TrustedPublishing  bool     `json:"trusted_publishing"`
	RegistrySignatures int      `json:"registry_signatures,omitempty"`
	Evidence           []string `json:"evidence,omitempty"`
	Error              string   `json:"error,omitempty"`
}

type ProvenanceResult struct {
	Summary      ProvenanceSummary `json:"summary"`
	Dependencies []ProvenanceEntry `json:"dependencies"`
}

type provenanceLookupData = provenance.Result

func runProvenance(cmd *cobra.Command, args []string) error {
	commit, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	showMissing, _ := cmd.Flags().GetBool("missing")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	deps, err := getDependencies(repo, commit, branchName)
	if err != nil {
		return fmt.Errorf("loading dependencies: %w", err)
	}

	deps = filterByEcosystem(deps, ecosystem)
	resolved, unresolved := selectProvenanceDependencies(deps)
	if len(resolved) == 0 {
		result := emptyProvenanceResult()
		result.Summary.UnresolvedDependencies = unresolved
		if format == formatJSON {
			return outputProvenanceJSON(cmd, result)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No resolved dependencies found.")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), provenanceLookupTimeout)
	defer cancel()

	lookupData := fetchProvenanceData(ctx, resolved)
	result := buildProvenanceResult(resolved, unresolved, lookupData, showMissing)

	switch format {
	case formatJSON:
		return outputProvenanceJSON(cmd, result)
	default:
		outputProvenanceText(cmd, result, showMissing)
		return nil
	}
}

func selectProvenanceDependencies(deps []database.Dependency) ([]database.Dependency, int) {
	var resolved []database.Dependency
	unresolved := 0
	for _, dep := range deps {
		if isResolvedDependency(dep) {
			resolved = append(resolved, dep)
			continue
		}
		unresolved++
	}
	return resolved, unresolved
}

func fetchProvenanceData(ctx context.Context, deps []database.Dependency) map[string]provenanceLookupData {
	purls, purlToDep := uniqueProvenancePURLs(deps)
	results := make(map[string]provenanceLookupData, len(purls))
	if len(purls) == 0 {
		return results
	}

	type lookupResult struct {
		purl string
		data provenanceLookupData
	}

	jobs := make(chan string)
	out := make(chan lookupResult, len(purls))
	workers := provenanceLookupConcurrency
	if len(purls) < workers {
		workers = len(purls)
	}

	var wg sync.WaitGroup
	client := provenance.NewClient(userAgent)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for purlStr := range jobs {
				dep := purlToDep[purlStr]
				out <- lookupResult{
					purl: purlStr,
					data: client.Lookup(ctx, provenance.Dependency{
						Ecosystem: dep.Ecosystem,
						Name:      dep.Name,
						Version:   dep.Requirement,
					}),
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, purlStr := range purls {
			select {
			case <-ctx.Done():
				return
			case jobs <- purlStr:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	for result := range out {
		results[result.purl] = result.data
	}
	for _, purlStr := range purls {
		if _, ok := results[purlStr]; !ok {
			results[purlStr] = provenanceLookupData{
				Status: provenanceStatusError,
				Error:  ctx.Err().Error(),
			}
		}
	}

	return results
}

func uniqueProvenancePURLs(deps []database.Dependency) ([]string, map[string]database.Dependency) {
	var purls []string
	purlToDep := make(map[string]database.Dependency)
	seen := make(map[string]bool)
	for _, dep := range deps {
		purlStr := provenancePURLForDependency(dep)
		if purlStr == "" || seen[purlStr] {
			continue
		}
		seen[purlStr] = true
		purls = append(purls, purlStr)
		purlToDep[purlStr] = dep
	}
	return purls, purlToDep
}

func provenancePURLForDependency(dep database.Dependency) string {
	if dep.PURL != "" {
		parsed, err := purl.Parse(dep.PURL)
		if err == nil && parsed.Version != "" {
			return parsed.String()
		}
	}
	return purl.MakePURLString(dep.Ecosystem, dep.Name, dep.Requirement)
}

func buildProvenanceResult(
	deps []database.Dependency,
	unresolved int,
	lookupData map[string]provenanceLookupData,
	showMissing bool,
) *ProvenanceResult {
	result := emptyProvenanceResult()
	result.Summary.TotalDependencies = len(deps)
	result.Summary.UnresolvedDependencies = unresolved

	seen := make(map[string]bool)
	for _, dep := range deps {
		purlStr := provenancePURLForDependency(dep)
		key := purlStr + "\x00" + dep.ManifestPath
		if seen[key] {
			continue
		}
		seen[key] = true

		data, ok := lookupData[purlStr]
		if !ok {
			data = provenanceLookupData{Status: provenanceStatusError, Error: "provenance lookup missing"}
		}
		result.Summary.CheckedDependencies++

		if data.RegistrySignatures > 0 {
			result.Summary.RegistrySignatures++
		}
		switch data.Status {
		case provenanceStatusTrustedPublishing:
			result.Summary.TrustedPublishing++
		case provenanceStatusAttested:
			result.Summary.AttestedDependencies++
		case provenanceStatusSigned:
			result.Summary.WithoutProvenance++
		case provenanceStatusMissing:
			result.Summary.WithoutProvenance++
		case provenanceStatusUnsupported:
			result.Summary.UnsupportedEcosystems++
		case provenanceStatusError:
			result.Summary.LookupErrors++
		}

		if showMissing && (data.Status == provenanceStatusTrustedPublishing || data.Status == provenanceStatusAttested) {
			continue
		}

		result.Dependencies = append(result.Dependencies, ProvenanceEntry{
			Name:               dep.Name,
			Ecosystem:          dep.Ecosystem,
			Version:            dep.Requirement,
			ManifestPath:       dep.ManifestPath,
			PURL:               purlStr,
			Status:             string(data.Status),
			TrustedPublishing:  data.TrustedPublishing,
			RegistrySignatures: data.RegistrySignatures,
			Evidence:           uniqueStrings(data.Evidence),
			Error:              data.Error,
		})
	}

	sort.Slice(result.Dependencies, func(i, j int) bool {
		if result.Dependencies[i].Status != result.Dependencies[j].Status {
			return result.Dependencies[i].Status < result.Dependencies[j].Status
		}
		if result.Dependencies[i].Ecosystem != result.Dependencies[j].Ecosystem {
			return result.Dependencies[i].Ecosystem < result.Dependencies[j].Ecosystem
		}
		if result.Dependencies[i].Name != result.Dependencies[j].Name {
			return result.Dependencies[i].Name < result.Dependencies[j].Name
		}
		return result.Dependencies[i].Version < result.Dependencies[j].Version
	})

	return result
}

func emptyProvenanceResult() *ProvenanceResult {
	return &ProvenanceResult{Dependencies: []ProvenanceEntry{}}
}

func outputProvenanceJSON(cmd *cobra.Command, result *ProvenanceResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputProvenanceText(cmd *cobra.Command, result *ProvenanceResult, showMissing bool) {
	if len(result.Dependencies) == 0 {
		if showMissing {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "All checked dependencies have trusted-publishing provenance.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No provenance metadata found.")
		}
		return
	}

	if showMissing {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Found %d dependencies without trusted-publishing provenance:\n\n", len(result.Dependencies))
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Provenance results for %d dependencies:\n\n", len(result.Dependencies))
	}

	maxNameLen := 0
	for _, dep := range result.Dependencies {
		if len(dep.Name) > maxNameLen {
			maxNameLen = len(dep.Name)
		}
	}

	for _, dep := range result.Dependencies {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %s  %s  %s\n",
			maxNameLen,
			dep.Name,
			dep.Version,
			dep.Status,
			Dim("("+dep.ManifestPath+")"))
		for _, evidence := range dep.Evidence {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  evidence: %s\n", evidence)
		}
		if dep.Error != "" {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  error: %s\n", dep.Error)
		}
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"Checked: %d, trusted publishing: %d, attested: %d, registry signatures: %d, without provenance: %d, unsupported: %d, errors: %d\n",
		result.Summary.CheckedDependencies,
		result.Summary.TrustedPublishing,
		result.Summary.AttestedDependencies,
		result.Summary.RegistrySignatures,
		result.Summary.WithoutProvenance,
		result.Summary.UnsupportedEcosystems,
		result.Summary.LookupErrors)
}
