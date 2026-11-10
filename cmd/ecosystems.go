package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/git-pkgs/managers"
	"github.com/git-pkgs/manifests"
	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	"github.com/spf13/cobra"
)

type EcosystemDetail struct {
	Name      string   `json:"name"`
	Manifest  string   `json:"manifest,omitempty"`
	Lockfiles []string `json:"lockfiles,omitempty"`
	Managers  []string `json:"managers,omitempty"`
	Registry  bool     `json:"registry"`
}

func addEcosystemsCmd(parent *cobra.Command) {
	ecosystemsCmd := &cobra.Command{
		Use:   "ecosystems",
		Short: "List supported ecosystems",
		Long:  `Display all supported package ecosystems with their manifest files, lockfiles, managers, and registry support.`,
		RunE:  runEcosystems,
	}

	ecosystemsCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(ecosystemsCmd)
}

func buildEcosystemDetails() []EcosystemDetail {
	configs := managers.GitPkgsFileDetectionPolicy().Ecosystems
	configMap := make(map[string]*managers.EcosystemDetectionPolicy)
	for i := range configs {
		pt := purl.EcosystemToPURLType(configs[i].Ecosystem)
		configMap[pt] = &configs[i]
	}

	// Build a set of registry-supported ecosystems, keyed by PURL type
	registrySet := make(map[string]bool)
	for _, eco := range registries.SupportedEcosystems() {
		registrySet[purl.EcosystemToPURLType(eco)] = true
	}

	seen := make(map[string]bool)
	var details []EcosystemDetail

	for _, eco := range manifests.Ecosystems() {
		pt := purl.EcosystemToPURLType(eco)
		if seen[pt] {
			continue
		}
		seen[pt] = true
		details = append(details, buildDetail(pt, configMap[pt], registrySet[pt]))
	}

	for _, cfg := range configs {
		pt := purl.EcosystemToPURLType(cfg.Ecosystem)
		if !seen[pt] {
			seen[pt] = true
			details = append(details, buildDetail(pt, &cfg, registrySet[pt]))
		}
	}

	return details
}

func buildDetail(name string, cfg *managers.EcosystemDetectionPolicy, hasRegistry bool) EcosystemDetail {
	d := EcosystemDetail{
		Name:     name,
		Registry: hasRegistry,
	}
	if cfg != nil {
		d.Manifest = strings.Join(cfg.Manifests, ", ")
		for _, lf := range cfg.Lockfiles {
			d.Lockfiles = append(d.Lockfiles, lf.File)
		}
		// Collect unique managers
		managerSet := make(map[string]bool)
		var mgrs []string
		if cfg.DefaultManager != "" {
			managerSet[cfg.DefaultManager] = true
			mgrs = append(mgrs, cfg.DefaultManager)
		}
		for _, lf := range cfg.Lockfiles {
			if !managerSet[lf.Manager] {
				managerSet[lf.Manager] = true
				mgrs = append(mgrs, lf.Manager)
			}
		}
		d.Managers = mgrs
	}
	return d
}

func runEcosystems(cmd *cobra.Command, args []string) error {
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}
	details := buildEcosystemDetails()

	switch format {
	case formatJSON:
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(details)
	default:
		return outputEcosystemsText(cmd, details)
	}
}

func outputEcosystemsText(cmd *cobra.Command, details []EcosystemDetail) error {
	const tabPadding = 2
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, tabPadding, tabPadding, ' ', 0)
	_, _ = fmt.Fprintln(w, "Ecosystem\tManifest\tLockfiles\tManagers\tRegistry")
	for _, d := range details {
		registry := "no"
		if d.Registry {
			registry = displayYes
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			d.Name,
			d.Manifest,
			strings.Join(d.Lockfiles, ", "),
			strings.Join(d.Managers, ", "),
			registry,
		)
	}
	return w.Flush()
}
