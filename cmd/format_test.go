package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestUnsupportedFormatValuesAreRejected(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		formats string
	}{
		{name: "list", args: []string{"list", "--format", "yaml"}, formats: "text, json"},
		{name: "search", args: []string{"search", "lodash", "--format", "yaml"}, formats: "text, json"},
		{name: "sbom", args: []string{"sbom", "--format", "yaml"}, formats: "json, xml"},
		{name: "licenses", args: []string{"licenses", "--format", "xml"}, formats: "text, json, csv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := NewRootCmd()
			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs(tt.args)

			err := root.Execute()
			if err == nil {
				t.Fatal("expected unsupported format error")
			}
			want := fmt.Sprintf("unsupported format %q; supported formats: %s", tt.args[len(tt.args)-1], tt.formats)
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), want)
			}
		})
	}
}
