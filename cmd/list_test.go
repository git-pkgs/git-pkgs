package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/git-pkgs/git-pkgs/internal/database"
)

func TestOutputListJSON(t *testing.T) {
	t.Run("nil slice produces []", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewRootCmd()
		cmd.SetOut(&buf)

		var deps []database.Dependency // nil
		err := outputListJSON(cmd, deps)
		if err != nil {
			t.Fatalf("outputListJSON returned error: %v", err)
		}

		var result []database.Dependency
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("output is not valid JSON: %v\nRaw: %q", err, buf.String())
		}
		if result == nil {
			t.Error("decoded result is nil, expected empty slice []")
		}
		if len(result) != 0 {
			t.Errorf("expected empty array, got %d elements", len(result))
		}
	})

	t.Run("empty slice produces []", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewRootCmd()
		cmd.SetOut(&buf)

		err := outputListJSON(cmd, []database.Dependency{})
		if err != nil {
			t.Fatalf("outputListJSON returned error: %v", err)
		}

		var result []database.Dependency
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("output is not valid JSON: %v\nRaw: %q", err, buf.String())
		}
		if result == nil {
			t.Error("decoded result is nil, expected empty slice []")
		}
	})

	t.Run("non-empty slice serializes correctly", func(t *testing.T) {
		var buf bytes.Buffer
		cmd := NewRootCmd()
		cmd.SetOut(&buf)

		deps := []database.Dependency{
			{Name: "lodash", Ecosystem: "npm"},
			{Name: "express", Ecosystem: "npm"},
		}

		err := outputListJSON(cmd, deps)
		if err != nil {
			t.Fatalf("outputListJSON returned error: %v", err)
		}

		var result []database.Dependency
		if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
			t.Fatalf("output is not valid JSON: %v\nRaw: %q", err, buf.String())
		}
		if len(result) != 2 {
			t.Errorf("expected 2 elements, got %d", len(result))
		}
		if result[0].Name != "lodash" {
			t.Errorf("first element name = %q, want %q", result[0].Name, "lodash")
		}
	})
}
