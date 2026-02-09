package gitignore

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type pattern struct {
	regex  *regexp.Regexp
	negate bool
}

// Matcher checks paths against gitignore rules collected from .gitignore files,
// .git/info/exclude, and any additional patterns. Patterns from subdirectory
// .gitignore files are scoped to paths within that directory.
//
// Paths passed to Match should use forward slashes. Directory paths must
// have a trailing slash (e.g. "vendor/") so that directory-only patterns
// (those written with a trailing slash in .gitignore) match correctly.
type Matcher struct {
	patterns []pattern
}

// New creates a Matcher that reads patterns from the repository's
// .git/info/exclude and root .gitignore. The root parameter should be
// the repository working directory (containing .git/).
func New(root string) *Matcher {
	m := &Matcher{}

	// Read .git/info/exclude
	excludePath := filepath.Join(root, ".git", "info", "exclude")
	if data, err := os.ReadFile(excludePath); err == nil {
		m.addPatterns(data, "")
	}

	// Read root .gitignore
	ignorePath := filepath.Join(root, ".gitignore")
	if data, err := os.ReadFile(ignorePath); err == nil {
		m.addPatterns(data, "")
	}

	return m
}

// AddFromFile reads a .gitignore file at the given absolute path and scopes
// its patterns to the given relative directory.
func (m *Matcher) AddFromFile(absPath, relDir string) {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return
	}
	m.addPatterns(data, relDir)
}

// Match returns true if the given path should be ignored.
// The path should be slash-separated and relative to the repository root.
// For directories, append a trailing slash (e.g. "vendor/").
// Uses last-match-wins semantics: iterates patterns in reverse and returns
// on the first match.
func (m *Matcher) Match(relPath string) bool {
	for i := len(m.patterns) - 1; i >= 0; i-- {
		if m.patterns[i].regex.MatchString(relPath) {
			return !m.patterns[i].negate
		}
	}
	return false
}

func (m *Matcher) addPatterns(data []byte, dir string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := trimTrailingSpaces(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if p, ok := compilePattern(line, dir); ok {
			m.patterns = append(m.patterns, p)
		}
	}
}

// trimTrailingSpaces removes unescaped trailing spaces per gitignore spec.
func trimTrailingSpaces(s string) string {
	if strings.HasSuffix(s, `\ `) {
		return strings.TrimLeft(s, " ")
	}
	return strings.TrimRight(s, " \t")
}

func compilePattern(line, dir string) (pattern, bool) {
	p := pattern{}

	// Handle negation
	if strings.HasPrefix(line, "!") {
		p.negate = true
		line = line[1:]
	}

	// Handle escaped leading characters (after negation is stripped)
	if len(line) >= 2 && line[0] == '\\' && (line[1] == '#' || line[1] == '!') {
		line = line[1:]
	}

	if line == "" || line == "/" {
		return pattern{}, false
	}

	expr := patternToRegex(line, dir)
	re, err := regexp.Compile(expr)
	if err != nil {
		return pattern{}, false
	}
	p.regex = re
	return p, true
}

// patternToRegex converts a gitignore pattern to a regular expression.
// The dir parameter scopes patterns from subdirectory .gitignore files.
//
// Git's rules (from git-scm.com/docs/gitignore):
//
//  1. If the pattern does not contain a slash /, it can match at any directory
//     level. Equivalent to prepending **/.
//
//  2. If there is a separator at the beginning or middle of the pattern, it is
//     relative to the directory level of the .gitignore file (anchored).
//     A leading slash is stripped after noting the anchoring.
//
//  3. A trailing slash means the pattern matches only directories.
//
//  4. A pattern without a trailing slash can match both files and directories.
//     When it matches a directory, all contents underneath are also matched.
//
//  5. ** has special meaning in leading (**/ prefix), trailing (/** suffix),
//     and middle (/**/) positions.
func patternToRegex(pat, dir string) string {
	// Determine if the pattern has a leading slash.
	hasLeadingSlash := strings.HasPrefix(pat, "/")

	// Determine if the pattern has a trailing slash (directory-only).
	hasTrailingSlash := strings.HasSuffix(pat, "/") && len(pat) > 1

	// Strip trailing slash for processing; we handle dir-only via the regex.
	if hasTrailingSlash {
		pat = strings.TrimSuffix(pat, "/")
	}

	// Strip leading slash; it's only meaningful for anchoring.
	if hasLeadingSlash {
		pat = strings.TrimPrefix(pat, "/")
	}

	segs := strings.Split(pat, "/")

	// Edge case: the `**/` pattern means "match any directory."
	// After stripping the trailing slash, pat is "**" and segs is ["**"].
	// Handle this specially: match any path ending with / (a directory).
	if hasTrailingSlash && len(segs) == 1 && segs[0] == "**" {
		prefix := ""
		if dir != "" {
			prefix = regexp.QuoteMeta(dir) + "/"
		}
		return "^" + prefix + ".*/$"
	}

	// Determine if the pattern contains a slash (after stripping leading/trailing).
	// A pattern with an internal slash is always anchored.
	hasMiddleSlash := len(segs) > 1

	// Rule 1: If the pattern has no slash at all (no leading, no trailing, no middle),
	// it matches at any level. Prepend ** to allow matching in any subdirectory.
	anchored := hasLeadingSlash || hasMiddleSlash
	if !anchored {
		segs = append([]string{"**"}, segs...)
	}

	// Collapse duplicate ** sequences.
	for i := len(segs) - 1; i > 0; i-- {
		if segs[i-1] == "**" && segs[i] == "**" {
			segs = append(segs[:i], segs[i+1:]...)
		}
	}

	var expr bytes.Buffer
	expr.WriteString("^")

	// Prefix with directory scope for patterns from subdirectory .gitignore files
	if dir != "" {
		expr.WriteString(regexp.QuoteMeta(dir))
		expr.WriteString("/")
	}

	needSlash := false
	end := len(segs) - 1

	for i, seg := range segs {
		switch seg {
		case "**":
			switch {
			case i == 0 && i == end:
				// Pattern is just **: match everything
				expr.WriteString(".+")
			case i == 0:
				// Leading **: match any leading path segments (including none)
				expr.WriteString("(?:.+/)?")
				needSlash = false
			case i == end:
				// Trailing **: match any trailing path segments
				expr.WriteString("(?:/.+)?")
			default:
				// Inner **: match zero or more path segments
				expr.WriteString("(?:/.+)?")
				needSlash = true
			}
		default:
			if needSlash {
				expr.WriteString("/")
			}
			expr.WriteString(globToRegex(seg))
			needSlash = true
		}
	}

	// Handle what this pattern matches beyond its literal path:
	if hasTrailingSlash {
		// Directory-only pattern: requires a trailing slash (indicating a
		// directory) and optionally matches all contents underneath.
		// Does NOT match the same name as a file (no trailing slash).
		expr.WriteString("/.*")
	} else if segs[end] != "**" {
		// Non-dir-only, non-** ending: matches the path itself as either
		// a file or directory, plus all directory contents.
		// Trailing slash in the match string indicates a directory.
		expr.WriteString("(?:/.*)?")
	}

	expr.WriteString("$")
	return expr.String()
}

func globToRegex(glob string) string {
	var buf bytes.Buffer
	escaped := false
	for i := 0; i < len(glob); i++ {
		ch := glob[i]
		switch {
		case escaped:
			escaped = false
			buf.WriteString(regexp.QuoteMeta(string(ch)))
		case ch == '\\':
			escaped = true
		case ch == '*':
			buf.WriteString("[^/]*")
		case ch == '?':
			buf.WriteString("[^/]")
		case ch == '[':
			buf.WriteString(parseBracket(&i, glob))
		default:
			buf.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	return buf.String()
}

func parseBracket(i *int, glob string) string {
	*i++
	j := *i

	// Handle negation (! or ^)
	if j < len(glob) && (glob[j] == '!' || glob[j] == '^') {
		j++
	}
	// Handle ] at start of bracket expression
	if j < len(glob) && glob[j] == ']' {
		j++
	}
	// Find closing bracket, skipping POSIX character classes like [:space:]
	for j < len(glob) && glob[j] != ']' {
		if glob[j] == '[' && j+1 < len(glob) && glob[j+1] == ':' {
			// Skip past the POSIX class to its closing :]
			end := strings.Index(glob[j+2:], ":]")
			if end != -1 {
				j += end + 4 // skip [: + class name + :]
				continue
			}
		}
		j++
	}
	if j >= len(glob) {
		// No closing bracket, treat [ as literal
		*i--
		return regexp.QuoteMeta("[")
	}

	// j points at closing bracket
	inner := glob[*i:j]
	*i = j // for loop will increment past ]

	// Convert ! to ^ for regex negation
	if len(inner) > 0 && inner[0] == '!' {
		inner = "^" + inner[1:]
	}

	// Escape backslashes inside bracket expressions for regex
	inner = strings.ReplaceAll(inner, `\`, `\\`)

	return "[" + inner + "]"
}
