package mailmap_test

import (
	"strings"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/mailmap"
)

func TestParseEmpty(t *testing.T) {
	mm, err := mailmap.Parse(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mm == nil {
		t.Fatal("expected non-nil mailmap")
	}
}

func TestParseComments(t *testing.T) {
	input := `# This is a comment
# Another comment
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mm == nil {
		t.Fatal("expected non-nil mailmap")
	}
}

func TestParseSimpleForm(t *testing.T) {
	// Format: Proper Name <commit@email.xx>
	// Maps a canonical name to a commit email address
	input := `Joe Developer <joe@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When we see email "joe@example.com", replace name with "Joe Developer"
	name, email := mm.Resolve("Wrong Name", "joe@example.com")
	if name != "Joe Developer" {
		t.Errorf("expected name 'Joe Developer', got %q", name)
	}
	if email != "joe@example.com" {
		t.Errorf("expected email 'joe@example.com', got %q", email)
	}
}

func TestParseEmailOnlyReplacement(t *testing.T) {
	// Format: <proper@email.xx> <commit@email.xx>
	// Replaces only the email part
	input := `<proper@example.com> <old@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	name, email := mm.Resolve("Jane Doe", "old@example.com")
	if name != "Jane Doe" {
		t.Errorf("expected name 'Jane Doe' (unchanged), got %q", name)
	}
	if email != "proper@example.com" {
		t.Errorf("expected email 'proper@example.com', got %q", email)
	}
}

func TestParseNameAndEmailReplacement(t *testing.T) {
	// Format: Proper Name <proper@email.xx> <commit@email.xx>
	// Replaces both name and email when commit email matches
	input := `Jane Doe <jane@example.com> <jane@laptop.(none)>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	name, email := mm.Resolve("jane", "jane@laptop.(none)")
	if name != "Jane Doe" {
		t.Errorf("expected name 'Jane Doe', got %q", name)
	}
	if email != "jane@example.com" {
		t.Errorf("expected email 'jane@example.com', got %q", email)
	}
}

func TestParseFullReplacement(t *testing.T) {
	// Format: Proper Name <proper@email.xx> Commit Name <commit@email.xx>
	// Replaces both when BOTH commit name AND email match
	input := `Joe R. Developer <joe@example.com> Joe <bugs@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should match when both name and email match
	name, email := mm.Resolve("Joe", "bugs@example.com")
	if name != "Joe R. Developer" {
		t.Errorf("expected name 'Joe R. Developer', got %q", name)
	}
	if email != "joe@example.com" {
		t.Errorf("expected email 'joe@example.com', got %q", email)
	}

	// Should NOT match when only email matches but name differs
	name, email = mm.Resolve("Different Name", "bugs@example.com")
	if name != "Different Name" {
		t.Errorf("expected name 'Different Name' (unchanged), got %q", name)
	}
	if email != "bugs@example.com" {
		t.Errorf("expected email 'bugs@example.com' (unchanged), got %q", email)
	}
}

func TestCaseInsensitiveMatching(t *testing.T) {
	input := `Jane Doe <jane@example.com> <JANE@EXAMPLE.COM>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Email matching should be case-insensitive
	name, email := mm.Resolve("jane", "Jane@Example.COM")
	if name != "Jane Doe" {
		t.Errorf("expected name 'Jane Doe', got %q", name)
	}
	if email != "jane@example.com" {
		t.Errorf("expected email 'jane@example.com', got %q", email)
	}
}

func TestNameCaseInsensitiveMatching(t *testing.T) {
	input := `Joe R. Developer <joe@example.com> JOE <bugs@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Name matching should also be case-insensitive
	name, email := mm.Resolve("joe", "bugs@example.com")
	if name != "Joe R. Developer" {
		t.Errorf("expected name 'Joe R. Developer', got %q", name)
	}
	if email != "joe@example.com" {
		t.Errorf("expected email 'joe@example.com', got %q", email)
	}
}

func TestNoMatch(t *testing.T) {
	input := `Joe Developer <joe@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unknown email should pass through unchanged
	name, email := mm.Resolve("Other Person", "other@example.com")
	if name != "Other Person" {
		t.Errorf("expected name 'Other Person' (unchanged), got %q", name)
	}
	if email != "other@example.com" {
		t.Errorf("expected email 'other@example.com' (unchanged), got %q", email)
	}
}

func TestMultipleMappings(t *testing.T) {
	input := `# Map multiple emails to one identity
Jane Doe <jane@example.com>
Jane Doe <jane@example.com> <jane@laptop.(none)>
Jane Doe <jane@example.com> <jane@desktop.(none)>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	testCases := []struct {
		inputName  string
		inputEmail string
		wantName   string
		wantEmail  string
	}{
		{"jane", "jane@example.com", "Jane Doe", "jane@example.com"},
		{"jane", "jane@laptop.(none)", "Jane Doe", "jane@example.com"},
		{"jane", "jane@desktop.(none)", "Jane Doe", "jane@example.com"},
	}

	for _, tc := range testCases {
		name, email := mm.Resolve(tc.inputName, tc.inputEmail)
		if name != tc.wantName {
			t.Errorf("Resolve(%q, %q): expected name %q, got %q", tc.inputName, tc.inputEmail, tc.wantName, name)
		}
		if email != tc.wantEmail {
			t.Errorf("Resolve(%q, %q): expected email %q, got %q", tc.inputName, tc.inputEmail, tc.wantEmail, email)
		}
	}
}

func TestBlankLines(t *testing.T) {
	input := `Joe Developer <joe@example.com>

Jane Doe <jane@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	name, _ := mm.Resolve("wrong", "joe@example.com")
	if name != "Joe Developer" {
		t.Errorf("expected 'Joe Developer', got %q", name)
	}

	name, _ = mm.Resolve("wrong", "jane@example.com")
	if name != "Jane Doe" {
		t.Errorf("expected 'Jane Doe', got %q", name)
	}
}

func TestSpecificMatchTakesPriority(t *testing.T) {
	// When both full match (name+email) and email-only match could apply,
	// the full match should take priority
	input := `Joe Generic <joe-generic@example.com> <bugs@example.com>
Joe Specific <joe-specific@example.com> Joe <bugs@example.com>
`
	mm, err := mailmap.Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Full match (name+email) should win
	name, email := mm.Resolve("Joe", "bugs@example.com")
	if name != "Joe Specific" {
		t.Errorf("expected name 'Joe Specific' (full match), got %q", name)
	}
	if email != "joe-specific@example.com" {
		t.Errorf("expected email 'joe-specific@example.com', got %q", email)
	}

	// Different name should fall back to email-only match
	name, email = mm.Resolve("Other", "bugs@example.com")
	if name != "Joe Generic" {
		t.Errorf("expected name 'Joe Generic' (email-only match), got %q", name)
	}
	if email != "joe-generic@example.com" {
		t.Errorf("expected email 'joe-generic@example.com', got %q", email)
	}
}

func TestEmptyMailmap(t *testing.T) {
	mm := mailmap.New()

	name, email := mm.Resolve("Test User", "test@example.com")
	if name != "Test User" {
		t.Errorf("expected name 'Test User', got %q", name)
	}
	if email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got %q", email)
	}
}
