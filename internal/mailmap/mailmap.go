// Package mailmap provides parsing and resolution of git .mailmap files.
// See https://git-scm.com/docs/gitmailmap for the specification.
package mailmap

import (
	"bufio"
	"io"
	"strings"
)

// entry represents a single mapping in a .mailmap file.
type entry struct {
	// Canonical identity (the replacement)
	properName  string
	properEmail string

	// Match criteria
	commitEmail string // Always required for matching
	commitName  string // Optional; if set, both name and email must match
}

// Mailmap holds parsed .mailmap entries and resolves author identities.
type Mailmap struct {
	// Entries that require both name and email to match (full match)
	fullMatches []entry
	// Entries that only require email to match
	emailMatches []entry
}

// New creates an empty Mailmap.
func New() *Mailmap {
	return &Mailmap{}
}

// Parse reads a .mailmap file and returns a Mailmap for resolving identities.
func Parse(r io.Reader) (*Mailmap, error) {
	mm := New()
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if e, ok := parseLine(line); ok {
			if e.commitName != "" {
				mm.fullMatches = append(mm.fullMatches, e)
			} else {
				mm.emailMatches = append(mm.emailMatches, e)
			}
		}
	}

	return mm, scanner.Err()
}

// parseLine parses a single mailmap line into an entry.
// Returns false if the line is invalid or cannot be parsed.
func parseLine(line string) (entry, bool) {
	// Extract all email addresses (enclosed in < >)
	var emails []string
	var names []string
	remaining := line

	for {
		start := strings.Index(remaining, "<")
		if start == -1 {
			// No more emails; anything left is trailing name
			if name := strings.TrimSpace(remaining); name != "" {
				names = append(names, name)
			}
			break
		}

		end := strings.Index(remaining[start:], ">")
		if end == -1 {
			// Malformed email, skip line
			return entry{}, false
		}
		end += start

		// Text before the email is a name
		if name := strings.TrimSpace(remaining[:start]); name != "" {
			names = append(names, name)
		}

		// Extract email (without angle brackets)
		email := strings.TrimSpace(remaining[start+1 : end])
		emails = append(emails, email)

		remaining = remaining[end+1:]
	}

	if len(emails) == 0 {
		return entry{}, false
	}

	var e entry

	switch len(emails) {
	case 1:
		// Format 1: Proper Name <commit@email.xx>
		// Maps canonical name to commit email
		e.commitEmail = emails[0]
		if len(names) > 0 {
			e.properName = names[0]
		}
		e.properEmail = emails[0] // Email stays the same

	case 2:
		if len(names) == 0 {
			// Format 2: <proper@email.xx> <commit@email.xx>
			// Email-only replacement
			e.properEmail = emails[0]
			e.commitEmail = emails[1]
		} else if len(names) == 1 {
			// Format 3: Proper Name <proper@email.xx> <commit@email.xx>
			// Replace both name and email when commit email matches
			e.properName = names[0]
			e.properEmail = emails[0]
			e.commitEmail = emails[1]
		} else {
			// Format 4: Proper Name <proper@email.xx> Commit Name <commit@email.xx>
			// Replace when both commit name and email match
			e.properName = names[0]
			e.properEmail = emails[0]
			e.commitName = names[1]
			e.commitEmail = emails[1]
		}

	default:
		// More than 2 emails is invalid
		return entry{}, false
	}

	return e, true
}

// Resolve maps an author's name and email to their canonical identity.
// If no mapping exists, the original values are returned unchanged.
func (m *Mailmap) Resolve(name, email string) (string, string) {
	if m == nil {
		return name, email
	}

	emailLower := strings.ToLower(email)
	nameLower := strings.ToLower(name)

	// First try full matches (name + email) - these are more specific
	for _, e := range m.fullMatches {
		if strings.ToLower(e.commitEmail) == emailLower &&
			strings.ToLower(e.commitName) == nameLower {
			resultName := name
			if e.properName != "" {
				resultName = e.properName
			}
			return resultName, e.properEmail
		}
	}

	// Then try email-only matches
	for _, e := range m.emailMatches {
		if strings.ToLower(e.commitEmail) == emailLower {
			resultName := name
			if e.properName != "" {
				resultName = e.properName
			}
			resultEmail := email
			if e.properEmail != "" {
				resultEmail = e.properEmail
			}
			return resultName, resultEmail
		}
	}

	// No match found
	return name, email
}
