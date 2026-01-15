package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/manifests"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addWhereCmd(rootCmd)
}

func addWhereCmd(parent *cobra.Command) {
	whereCmd := &cobra.Command{
		Use:   "where <package>",
		Short: "Find where a package is declared",
		Long: `Search manifest files for a package declaration.
Shows the file path, line number, and content.`,
		Args: cobra.ExactArgs(1),
		RunE: runWhere,
	}

	whereCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	whereCmd.Flags().IntP("context", "C", 0, "Show N lines of surrounding context")
	whereCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(whereCmd)
}

type WhereMatch struct {
	FilePath   string   `json:"file_path"`
	LineNumber int      `json:"line_number"`
	Content    string   `json:"content"`
	Context    []string `json:"context,omitempty"`
	Ecosystem  string   `json:"ecosystem"`
}

func runWhere(cmd *cobra.Command, args []string) error {
	packageName := args[0]
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	context, _ := cmd.Flags().GetInt("context")
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	workDir := repo.WorkDir()

	var matches []WhereMatch

	// Walk the working directory looking for manifest files
	err = filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't read
		}

		if info.IsDir() {
			// Skip common non-project directories
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if this is a manifest file
		eco, _, ok := manifests.Identify(info.Name())
		if !ok {
			return nil
		}

		// Filter by ecosystem if specified
		if ecosystem != "" && !strings.EqualFold(eco, ecosystem) {
			return nil
		}

		// Read and search the file
		relPath, _ := filepath.Rel(workDir, path)
		fileMatches, err := searchFileForPackage(path, relPath, packageName, eco, context)
		if err != nil {
			return nil // Skip files we can't read
		}

		matches = append(matches, fileMatches...)
		return nil
	})
	if err != nil {
		return fmt.Errorf("searching files: %w", err)
	}

	if len(matches) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in manifest files.\n", packageName)
		return nil
	}

	switch format {
	case "json":
		return outputWhereJSON(cmd, matches)
	default:
		return outputWhereText(cmd, matches, context > 0)
	}
}

func searchFileForPackage(path, relPath, packageName, ecosystem string, contextLines int) ([]WhereMatch, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var matches []WhereMatch
	var lines []string

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lines = append(lines, line)

		// Case-insensitive search for the package name
		if strings.Contains(strings.ToLower(line), strings.ToLower(packageName)) {
			match := WhereMatch{
				FilePath:   relPath,
				LineNumber: lineNum,
				Content:    line,
				Ecosystem:  ecosystem,
			}
			matches = append(matches, match)
		}
	}

	// Add context if requested
	if contextLines > 0 && len(matches) > 0 {
		for i := range matches {
			matches[i].Context = getContext(lines, matches[i].LineNumber-1, contextLines)
		}
	}

	return matches, scanner.Err()
}

func getContext(lines []string, lineIndex, contextLines int) []string {
	start := lineIndex - contextLines
	if start < 0 {
		start = 0
	}

	end := lineIndex + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	return lines[start:end]
}

func outputWhereJSON(cmd *cobra.Command, matches []WhereMatch) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(matches)
}

func outputWhereText(cmd *cobra.Command, matches []WhereMatch, showContext bool) error {
	for _, m := range matches {
		if showContext && len(m.Context) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:\n", m.FilePath)
			startLine := m.LineNumber - len(m.Context)/2
			if startLine < 1 {
				startLine = 1
			}
			for i, line := range m.Context {
				lineNum := startLine + i
				marker := " "
				if lineNum == m.LineNumber {
					marker = ">"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %4d: %s\n", marker, lineNum, line)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:%d:%s\n", m.FilePath, m.LineNumber, m.Content)
		}
	}

	return nil
}
