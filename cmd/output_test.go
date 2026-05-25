package cmd

import "testing"

func TestSanitize(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain text", "plain text"},
		{"keep\ttab\nnewline", "keep\ttab\nnewline"},
		{"\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"\x1b]0;title\x07", "]0;title"},
		{"ab\x00cd", "abcd"},
		{"carriage\rreturn", "carriagereturn"},
		{"", ""},
	}
	for _, tt := range tests {
		got := Sanitize(tt.in)
		if got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
