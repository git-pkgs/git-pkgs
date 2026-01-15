package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addWhyCmd(rootCmd)
}

func addWhyCmd(parent *cobra.Command) {
	whyCmd := &cobra.Command{
		Use:   "why <package>",
		Short: "Show why a dependency was added",
		Long:  `Show the commit that first added a dependency, including the author and commit message.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runWhy,
	}

	whyCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	whyCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(whyCmd)
}

func runWhy(cmd *cobra.Command, args []string) error {
	packageName := args[0]
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return fmt.Errorf("getting branch: %w", err)
	}

	result, err := db.GetWhy(branchInfo.ID, packageName, ecosystem)
	if err != nil {
		return fmt.Errorf("getting why: %w", err)
	}

	if result == nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in dependency history.\n", packageName)
		return nil
	}

	switch format {
	case "json":
		return outputWhyJSON(cmd, result)
	default:
		return outputWhyText(cmd, result)
	}
}

func outputWhyJSON(cmd *cobra.Command, result *database.WhyResult) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func outputWhyText(cmd *cobra.Command, result *database.WhyResult) error {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s was added in commit %s\n\n", result.Name, result.SHA[:7])
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Date:     %s\n", result.CommittedAt[:10])
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Author:   %s <%s>\n", result.AuthorName, result.AuthorEmail)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Manifest: %s\n", result.ManifestPath)
	if result.Ecosystem != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Ecosystem: %s\n", result.Ecosystem)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	// Show commit message
	message := strings.TrimSpace(result.Message)
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Commit message:")
	for _, line := range strings.Split(message, "\n") {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", line)
	}

	return nil
}
