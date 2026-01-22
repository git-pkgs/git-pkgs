package bisect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManager_InProgress(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	if mgr.InProgress() {
		t.Error("expected InProgress to be false with no state file")
	}

	// Create state file
	state := &State{OriginalHead: "abc123"}
	if err := mgr.Save(state); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	if !mgr.InProgress() {
		t.Error("expected InProgress to be true after saving state")
	}
}

func TestManager_SaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	state := &State{
		OriginalHead: "abc123def456",
		OriginalRef:  "main",
		BadRev:       "bad123",
		GoodRevs:     []string{"good123", "good456"},
		SkippedRevs:  []string{"skip123"},
		Ecosystem:    "npm",
		Package:      "lodash",
		Manifest:     "package.json",
		CurrentSHA:   "current123",
	}

	if err := mgr.Save(state); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}

	loaded, err := mgr.Load()
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}

	if loaded.OriginalHead != state.OriginalHead {
		t.Errorf("OriginalHead: expected %q, got %q", state.OriginalHead, loaded.OriginalHead)
	}
	if loaded.OriginalRef != state.OriginalRef {
		t.Errorf("OriginalRef: expected %q, got %q", state.OriginalRef, loaded.OriginalRef)
	}
	if loaded.BadRev != state.BadRev {
		t.Errorf("BadRev: expected %q, got %q", state.BadRev, loaded.BadRev)
	}
	if len(loaded.GoodRevs) != len(state.GoodRevs) {
		t.Errorf("GoodRevs: expected %d items, got %d", len(state.GoodRevs), len(loaded.GoodRevs))
	}
	if loaded.Ecosystem != state.Ecosystem {
		t.Errorf("Ecosystem: expected %q, got %q", state.Ecosystem, loaded.Ecosystem)
	}
	if loaded.Package != state.Package {
		t.Errorf("Package: expected %q, got %q", state.Package, loaded.Package)
	}
}

func TestManager_LoadNoState(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	_, err := mgr.Load()
	if err == nil {
		t.Error("expected error when loading non-existent state")
	}
}

func TestManager_Clean(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	// Create all state files
	state := &State{OriginalHead: "abc123"}
	if err := mgr.Save(state); err != nil {
		t.Fatalf("failed to save state: %v", err)
	}
	if err := mgr.AppendLog("test log entry"); err != nil {
		t.Fatalf("failed to append log: %v", err)
	}
	candidates := []Candidate{{SHA: "abc123", Message: "test"}}
	if err := mgr.SaveCandidates(candidates); err != nil {
		t.Fatalf("failed to save candidates: %v", err)
	}

	// Verify files exist
	if !fileExists(filepath.Join(tmpDir, stateFile)) {
		t.Error("state file should exist before clean")
	}
	if !fileExists(filepath.Join(tmpDir, logFile)) {
		t.Error("log file should exist before clean")
	}
	if !fileExists(filepath.Join(tmpDir, candidatesFile)) {
		t.Error("candidates file should exist before clean")
	}

	// Clean
	if err := mgr.Clean(); err != nil {
		t.Fatalf("failed to clean: %v", err)
	}

	// Verify files are gone
	if fileExists(filepath.Join(tmpDir, stateFile)) {
		t.Error("state file should not exist after clean")
	}
	if fileExists(filepath.Join(tmpDir, logFile)) {
		t.Error("log file should not exist after clean")
	}
	if fileExists(filepath.Join(tmpDir, candidatesFile)) {
		t.Error("candidates file should not exist after clean")
	}
}

func TestManager_Log(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	entries := []string{
		"# git pkgs bisect start",
		"git pkgs bisect bad abc123",
		"git pkgs bisect good def456",
	}

	for _, entry := range entries {
		if err := mgr.AppendLog(entry); err != nil {
			t.Fatalf("failed to append log: %v", err)
		}
	}

	lines, err := mgr.ReadLog()
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	if len(lines) != len(entries) {
		t.Errorf("expected %d log entries, got %d", len(entries), len(lines))
	}

	for i, entry := range entries {
		if i < len(lines) && lines[i] != entry {
			t.Errorf("log entry %d: expected %q, got %q", i, entry, lines[i])
		}
	}
}

func TestManager_Candidates(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir)

	candidates := []Candidate{
		{SHA: "abc123", Message: "First commit"},
		{SHA: "def456", Message: "Second commit"},
		{SHA: "ghi789", Message: "Third commit"},
	}

	if err := mgr.SaveCandidates(candidates); err != nil {
		t.Fatalf("failed to save candidates: %v", err)
	}

	loaded, err := mgr.LoadCandidates()
	if err != nil {
		t.Fatalf("failed to load candidates: %v", err)
	}

	if len(loaded) != len(candidates) {
		t.Errorf("expected %d candidates, got %d", len(candidates), len(loaded))
	}

	for i, c := range candidates {
		if i < len(loaded) {
			if loaded[i].SHA != c.SHA {
				t.Errorf("candidate %d SHA: expected %q, got %q", i, c.SHA, loaded[i].SHA)
			}
			if loaded[i].Message != c.Message {
				t.Errorf("candidate %d Message: expected %q, got %q", i, c.Message, loaded[i].Message)
			}
		}
	}
}

func TestManager_IsGood(t *testing.T) {
	mgr := NewManager(t.TempDir())

	state := &State{
		GoodRevs: []string{"abc123def456", "111222333444"},
	}

	tests := []struct {
		sha      string
		expected bool
	}{
		{"abc123def456", true},           // exact match
		{"abc123", true},                 // prefix match
		{"abc123def456789", true},        // sha is prefix of good rev
		{"111222333444", true},           // exact match second rev
		{"111222", true},                 // prefix match second rev
		{"bad123", false},                // not in list
		{"abc124", false},                // similar but different
	}

	for _, tc := range tests {
		result := mgr.IsGood(state, tc.sha)
		if result != tc.expected {
			t.Errorf("IsGood(%q): expected %v, got %v", tc.sha, tc.expected, result)
		}
	}
}

func TestManager_IsBad(t *testing.T) {
	mgr := NewManager(t.TempDir())

	state := &State{
		BadRev: "bad123def456",
	}

	tests := []struct {
		sha      string
		expected bool
	}{
		{"bad123def456", true},           // exact match
		{"bad123", true},                 // prefix match
		{"bad123def456789", true},        // sha is prefix of bad rev
		{"good123", false},               // different
		{"bad124", false},                // similar but different
	}

	for _, tc := range tests {
		result := mgr.IsBad(state, tc.sha)
		if result != tc.expected {
			t.Errorf("IsBad(%q): expected %v, got %v", tc.sha, tc.expected, result)
		}
	}
}

func TestManager_IsSkipped(t *testing.T) {
	mgr := NewManager(t.TempDir())

	state := &State{
		SkippedRevs: []string{"skip123", "skip456"},
	}

	tests := []struct {
		sha      string
		expected bool
	}{
		{"skip123", true},
		{"skip456", true},
		{"skip12", true},   // prefix
		{"other123", false},
	}

	for _, tc := range tests {
		result := mgr.IsSkipped(state, tc.sha)
		if result != tc.expected {
			t.Errorf("IsSkipped(%q): expected %v, got %v", tc.sha, tc.expected, result)
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
