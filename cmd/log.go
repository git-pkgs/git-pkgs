package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

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
	const defaultLogLimit = 20
	logCmd.Flags().IntP("limit", "n", defaultLogLimit, "Maximum number of commits to show")
	logCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	logCmd.Flags().Bool("exclude-bots", false, "Exclude commits by bot authors")
	parent.AddCommand(logCmd)
}

func runLog(cmd *cobra.Command, args []string) error {
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	author, _ := cmd.Flags().GetString("author")
	since, _ := cmd.Flags().GetString("since")
	until, _ := cmd.Flags().GetString("until")
	limit, _ := cmd.Flags().GetInt("limit")
	format, _ := cmd.Flags().GetString("format")
	excludeBots, _ := cmd.Flags().GetBool("exclude-bots")

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
		BranchID:    branchInfo.ID,
		Ecosystem:   ecosystem,
		Author:      author,
		Since:       since,
		Until:       until,
		Limit:       limit,
		ExcludeBots: excludeBots,
	})
	if err != nil {
		return fmt.Errorf("getting commits: %w", err)
	}

	switch format {
	case formatJSON:
		return outputLogJSON(cmd, commits)
	default:
		if len(commits) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No commits with dependency changes found.")
			return nil
		}
		outputLogText(cmd, commits)
		return nil
	}
}

func outputLogJSON(cmd *cobra.Command, commits []database.CommitWithChanges) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(commits))
}

func outputLogText(cmd *cobra.Command, commits []database.CommitWithChanges) {
	for _, c := range commits {
		// First line of message only
		message := c.Message
		if idx := strings.Index(message, "\n"); idx > 0 {
			message = message[:idx]
		}
		message = strings.TrimSpace(message)
		if len(message) > subjectTruncLen {
			message = message[:subjectTruncLen-3] + "..."
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", Yellow(shortSHA(c.SHA)), message)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Author: %s %s\n", c.AuthorName, Dim("<"+c.AuthorEmail+">"))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Date:   %s\n", c.CommittedAt[:10])

		// Summarize changes
		var added, modified, removed int
		for _, ch := range c.Changes {
			switch ch.ChangeType {
			case changeTypeAdded:
				added++
			case changeTypeModified:
				modified++
			case changeTypeRemoved:
				removed++
			}
		}

		var parts []string
		if added > 0 {
			parts = append(parts, Green(fmt.Sprintf("+%d", added)))
		}
		if modified > 0 {
			parts = append(parts, Yellow(fmt.Sprintf("~%d", modified)))
		}
		if removed > 0 {
			parts = append(parts, Red(fmt.Sprintf("-%d", removed)))
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  Changes: %s\n", strings.Join(parts, " "))
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}
}
