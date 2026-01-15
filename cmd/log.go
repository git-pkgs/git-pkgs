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
	addLogCmd(rootCmd)
}

func addLogCmd(parent *cobra.Command) {
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "List commits with dependency changes",
		Long:  `Show commits that modified dependencies, most recent first.`,
		RunE:  runLog,
	}

	logCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	logCmd.Flags().String("author", "", "Filter by author name or email")
	logCmd.Flags().String("since", "", "Only commits after this date (YYYY-MM-DD)")
	logCmd.Flags().String("until", "", "Only commits before this date (YYYY-MM-DD)")
	logCmd.Flags().IntP("limit", "n", 20, "Maximum number of commits to show")
	logCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(logCmd)
}

func runLog(cmd *cobra.Command, args []string) error {
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	author, _ := cmd.Flags().GetString("author")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	limit, _ := cmd.Flags().GetInt("limit")
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

	commits, err := db.GetCommitsWithChanges(database.LogOptions{
		BranchID:  branchInfo.ID,
		Ecosystem: ecosystem,
		Author:    author,
		Since:     since,
		Until:     until,
		Limit:     limit,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	if len(commits) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No commits with dependency changes found.")
		return nil
	}

	switch format {
	case "json":
		return outputLogJSON(cmd, commits)
	default:
		return outputLogText(cmd, commits)
	}
}

func outputLogJSON(cmd *cobra.Command, commits []database.CommitWithChanges) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(commits)
}

func outputLogText(cmd *cobra.Command, commits []database.CommitWithChanges) error {
	for _, c := range commits {
		// First line of message only
		message := c.Message
		if idx := strings.Index(message, "\n"); idx > 0 {
			message = message[:idx]
		}
		message = strings.TrimSpace(message)
		if len(message) > 60 {
			message = message[:57] + "..."
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", c.SHA[:7], message)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Author: %s <%s>\n", c.AuthorName, c.AuthorEmail)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Date:   %s\n", c.CommittedAt[:10])

		// Summarize changes
		var added, modified, removed int
		for _, ch := range c.Changes {
			switch ch.ChangeType {
			case "added":
				added++
			case "modified":
				modified++
			case "removed":
				removed++
			}
		}

		var parts []string
		if added > 0 {
			parts = append(parts, fmt.Sprintf("+%d", added))
		}
		if modified > 0 {
			parts = append(parts, fmt.Sprintf("~%d", modified))
		}
		if removed > 0 {
			parts = append(parts, fmt.Sprintf("-%d", removed))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Changes: %s\n", strings.Join(parts, " "))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
