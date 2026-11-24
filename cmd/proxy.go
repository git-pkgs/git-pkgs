package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/purl"
	"github.com/spf13/cobra"
)

const defaultProxyWarmTimeout = 30 * time.Minute

func addProxyCmd(parent *cobra.Command) {
	proxyCmd := &cobra.Command{Use: "proxy", Short: "Work with a git-pkgs proxy"}
	warmCmd := &cobra.Command{
		Use: "warm", Short: "Cache resolved dependencies in a git-pkgs proxy",
		Long: `Cache the repository's resolved package versions in a running git-pkgs proxy.
Reads committed HEAD by default, including transitive dependencies in lockfiles.
The proxy must enable mirror_api. Waits for completion and fails if any package fails.
Unresolved dependencies and local sources are skipped with a reason.`,
		Args: cobra.NoArgs,
		RunE: runProxyWarm,
	}
	flags := warmCmd.Flags()
	flags.String("url", "", "Proxy base URL (defaults to PROXY_URL)")
	flags.String("commit", "", "Commit or revision to read (default: HEAD)")
	flags.StringP("ecosystem", "e", "", "Filter by ecosystem")
	flags.StringP("manifest", "m", "", "Filter by manifest path")
	flags.StringP("type", "t", "", "Filter by dependency type (runtime, development, etc.)")
	flags.Bool("dry-run", false, "List PURLs without contacting the proxy")
	flags.Duration("timeout", defaultProxyWarmTimeout, "Maximum time to submit and wait for the mirror job")
	proxyCmd.AddCommand(warmCmd)
	parent.AddCommand(proxyCmd)
}

func runProxyWarm(cmd *cobra.Command, _ []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	baseURL, _ := cmd.Flags().GetString("url")
	if baseURL == "" {
		baseURL = os.Getenv("PROXY_URL")
	}
	timeout, _ := cmd.Flags().GetDuration("timeout")
	if timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	var client *proxyMirrorClient
	if !dryRun {
		var err error
		client, err = newProxyMirrorClient(baseURL)
		if err != nil {
			return err
		}
	}

	purls, err := proxyWarmPURLs(cmd)
	if err != nil {
		return err
	}
	if len(purls) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No resolved package versions to warm.")
		return nil
	}
	if dryRun {
		for _, value := range purls {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), value)
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id, err := client.start(ctx, purls)
	if err != nil {
		return err
	}
	quiet, _ := cmd.Flags().GetBool("quiet")
	if !quiet {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Mirror job %s: %d package versions submitted\n", Sanitize(id), len(purls))
	}
	job, err := client.wait(ctx, id, func(status string) {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), status)
		}
	})
	if err != nil {
		return fmt.Errorf("waiting for mirror job %s (it may still be running): %w", Sanitize(id), err)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), job.summary())
	for _, failure := range job.Progress.Errors {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s/%s@%s: %s\n",
			Sanitize(failure.Ecosystem), Sanitize(failure.Name), Sanitize(failure.Version), Sanitize(failure.Error))
	}
	if job.State != "complete" || job.Progress.Failed > 0 {
		return fmt.Errorf("mirror job %s %s: %d package versions failed%s",
			Sanitize(id), job.State, job.Progress.Failed, proxyJobError(job.Error))
	}
	return nil
}

func proxyWarmPURLs(cmd *cobra.Command) ([]string, error) {
	commitRef, _ := cmd.Flags().GetString("commit")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	manifest, _ := cmd.Flags().GetString("manifest")
	depType, _ := cmd.Flags().GetString("type")
	repo, err := git.OpenRepository(".")
	if err != nil {
		return nil, fmt.Errorf("not in a git repository: %w", err)
	}
	deps, err := repo.GetDependencies(commitRef, "")
	if err != nil {
		return nil, fmt.Errorf("loading dependencies: %w", err)
	}
	deps = filterDependencies(deps, ecosystem, manifest, depType)
	seen := make(map[string]bool)
	var purls []string
	for _, component := range selectSBOMDependencies(deps) {
		dep := component.primary
		value, reason := proxyWarmPURL(dep)
		if reason != "" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Skipping %s (%s): %s\n", Sanitize(dep.Name), Sanitize(dep.ManifestPath), reason)
			continue
		}
		if !seen[value] {
			seen[value] = true
			purls = append(purls, value)
		}
	}
	sort.Strings(purls)
	return purls, nil
}

func proxyWarmPURL(dep database.Dependency) (value, reason string) {
	if !isResolvedDependency(dep) {
		return "", "no resolved version"
	}
	// Maven manifests can contain ranges and property references as well as pins.
	if dep.Ecosystem == ecosystemMaven {
		if strings.ContainsAny(dep.Requirement, "$[](),") || dep.Requirement == "LATEST" || dep.Requirement == "RELEASE" {
			return "", "no resolved version"
		}
	}
	value = versionedPURLForDependency(dep)
	parsed, err := purl.Parse(value)
	if err != nil || parsed.Version == "" {
		return "", "no versioned package URL"
	}
	if isLocalSourcePURL(value) {
		return "", "local source has no registry artifact"
	}
	return value, ""
}

func proxyJobError(message string) string {
	if message == "" {
		return ""
	}
	return ": " + Sanitize(message)
}
