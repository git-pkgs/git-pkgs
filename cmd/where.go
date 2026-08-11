package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/config"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/gitignore"
	"github.com/git-pkgs/manifests"
	"github.com/spf13/cobra"
)

func addWhereCmd(parent *cobra.Command) {
	whereCmd := &cobra.Command{
		Use:     "where <package>",
		Aliases: []string{"find"},
		Short:   "Find where a package is declared",
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
	FilePath         string   `json:"file_path"`
	LineNumber       int      `json:"line_number"`
	Content          string   `json:"content"`
	Context          []string `json:"context,omitempty"`
	ContextStartLine int      `json:"-"`
	Ecosystem        string   `json:"ecosystem"`
}

type whereOptions struct {
	ecosystem         string
	packageName       string
	contextLines      int
	format            string
	includeSubmodules bool
}

func runWhere(cmd *cobra.Command, args []string) error {
	opts, err := whereOptionsFromCommand(cmd, args[0])
	if err != nil {
		return err
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	matches, err := findWhereMatches(repo, opts)
	if err != nil {
		return err
	}
	return outputWhereMatches(cmd, matches, opts)
}

func whereOptionsFromCommand(cmd *cobra.Command, packageArg string) (whereOptions, error) {
	ecosystemFlag, _ := cmd.Flags().GetString("ecosystem")

	ecosystem, packageName, _, err := ParsePackageArg(packageArg, ecosystemFlag)
	if err != nil {
		return whereOptions{}, err
	}
	contextLines, _ := cmd.Flags().GetInt("context")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return whereOptions{}, err
	}
	includeSubmodules, _ := cmd.Flags().GetBool("include-submodules")
	return whereOptions{
		ecosystem:         ecosystem,
		packageName:       packageName,
		contextLines:      contextLines,
		format:            format,
		includeSubmodules: includeSubmodules,
	}, nil
}

func findWhereMatches(repo *git.Repository, opts whereOptions) ([]WhereMatch, error) {
	workDir := repo.WorkDir()
	ecosystemFilter, err := repo.EcosystemFilter()
	if err != nil {
		return nil, fmt.Errorf("loading ecosystem config: %w", err)
	}

	// Scope all file reads to the repo directory so that symlinks
	// pointing outside the repository are rejected by the kernel.
	osRoot, err := os.OpenRoot(workDir)
	if err != nil {
		return nil, fmt.Errorf("opening root %q: %w", workDir, err)
	}
	defer func() { _ = osRoot.Close() }()

	search := whereSearch{
		workDir:         workDir,
		root:            osRoot,
		matcher:         gitignore.New(workDir),
		submodules:      whereSubmoduleMap(repo, opts.includeSubmodules),
		ecosystemFilter: ecosystemFilter,
		ecosystem:       opts.ecosystem,
		packageName:     opts.packageName,
		contextLines:    opts.contextLines,
	}
	if err := filepath.WalkDir(workDir, search.visit); err != nil {
		return nil, fmt.Errorf("searching files: %w", err)
	}
	return search.matches, nil
}

func whereSubmoduleMap(repo *git.Repository, includeSubmodules bool) map[string]bool {
	if includeSubmodules {
		return nil
	}
	paths, err := repo.GetSubmodulePaths()
	if err != nil {
		return nil
	}
	result := make(map[string]bool, len(paths))
	for _, path := range paths {
		result[path] = true
	}
	return result
}

type whereSearch struct {
	workDir         string
	root            *os.Root
	matcher         *gitignore.Matcher
	submodules      map[string]bool
	ecosystemFilter config.EcosystemFilter
	ecosystem       string
	packageName     string
	contextLines    int
	matches         []WhereMatch
}

func (search *whereSearch) visit(path string, entry os.DirEntry, walkErr error) error {
	if walkErr != nil {
		return nil
	}
	osRel, _ := filepath.Rel(search.workDir, path)
	relPath := filepath.ToSlash(osRel)
	if entry.IsDir() {
		return search.visitDirectory(path, entry, relPath)
	}
	search.visitFile(osRel, relPath)
	return nil
}

func (search *whereSearch) visitDirectory(path string, entry os.DirEntry, relPath string) error {
	if entry.Name() == ".git" {
		return filepath.SkipDir
	}
	if relPath != "." && search.matcher.Match(relPath+"/") {
		return filepath.SkipDir
	}
	if search.submodules[relPath] {
		return filepath.SkipDir
	}
	if relPath == "." {
		return nil
	}
	nestedIgnore := filepath.Join(path, ".gitignore")
	if _, err := os.Stat(nestedIgnore); err == nil {
		search.matcher.AddFromFile(nestedIgnore, relPath)
	}
	return nil
}

func (search *whereSearch) visitFile(osRel, relPath string) {
	if search.matcher.Match(relPath) {
		return
	}
	ecosystem, _, ok := manifests.Identify(relPath)
	if !ok {
		return
	}
	if search.ecosystem != "" && !strings.EqualFold(ecosystem, search.ecosystem) {
		return
	}
	if !search.ecosystemFilter.Allows(ecosystem) {
		return
	}
	matches, err := searchFileForPackage(
		search.root,
		osRel,
		relPath,
		search.packageName,
		ecosystem,
		search.contextLines,
	)
	if err == nil {
		search.matches = append(search.matches, matches...)
	}
}

func outputWhereMatches(cmd *cobra.Command, matches []WhereMatch, opts whereOptions) error {
	if opts.format == formatJSON {
		return outputWhereJSON(cmd, matches)
	}
	if len(matches) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in manifest files.\n", opts.packageName)
		return nil
	}
	outputWhereText(cmd, matches, opts.contextLines > 0)
	return nil
}

func searchFileForPackage(root *os.Root, osRel, relPath, packageName, ecosystem string, contextLines int) ([]WhereMatch, error) {
	file, err := root.Open(osRel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var matches []WhereMatch
	var lines []string

	// Case-insensitive search with package-token boundaries to avoid matching inside
	// hashes or similarly named packages. We can't use \b because package names may
	// start/end with non-word chars (e.g. @scope/pkg), and punctuation like hyphens
	// can be part of package names. Allow @ as a boundary so GitHub Actions like
	// actions/checkout@v4 still match actions/checkout.
	quoted := regexp.QuoteMeta(packageName)
	re := regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9._-])` + quoted + `(?:$|[^A-Za-z0-9._-])`)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lines = append(lines, line)

		if re.MatchString(line) {
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
			matches[i].Context, matches[i].ContextStartLine = getContext(lines, matches[i].LineNumber-1, contextLines)
		}
	}

	return matches, scanner.Err()
}

func getContext(lines []string, lineIndex, contextLines int) ([]string, int) {
	start := lineIndex - contextLines
	if start < 0 {
		start = 0
	}

	end := lineIndex + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	return lines[start:end], start + 1
}

func outputWhereJSON(cmd *cobra.Command, matches []WhereMatch) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(nonNilSlice(matches))
}

func outputWhereText(cmd *cobra.Command, matches []WhereMatch, showContext bool) {
	for _, m := range matches {
		if showContext && len(m.Context) > 0 {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:\n", m.FilePath)
			startLine := m.ContextStartLine
			if startLine < 1 {
				startLine = 1
			}
			for i, line := range m.Context {
				lineNum := startLine + i
				marker := " "
				if lineNum == m.LineNumber {
					marker = ">"
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %4d: %s\n", marker, lineNum, Sanitize(line))
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s:%d:%s\n", m.FilePath, m.LineNumber, Sanitize(m.Content))
		}
	}
}
