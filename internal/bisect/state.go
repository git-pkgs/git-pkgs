package bisect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	stateFile     = "PKGS_BISECT_STATE"
	logFile       = "PKGS_BISECT_LOG"
	candidatesFile = "PKGS_BISECT_CANDIDATES"
)

type State struct {
	OriginalHead string   `json:"original_head"`
	OriginalRef  string   `json:"original_ref"`
	BadRev       string   `json:"bad_rev"`
	GoodRevs     []string `json:"good_revs"`
	SkippedRevs  []string `json:"skipped_revs"`
	Ecosystem    string   `json:"ecosystem,omitempty"`
	Package      string   `json:"package,omitempty"`
	Manifest     string   `json:"manifest,omitempty"`
	CurrentSHA   string   `json:"current_sha"`
}

type Candidate struct {
	SHA     string `json:"sha"`
	Message string `json:"message"`
}

type Manager struct {
	gitDir string
}

func NewManager(gitDir string) *Manager {
	return &Manager{gitDir: gitDir}
}

func (m *Manager) statePath() string {
	return filepath.Join(m.gitDir, stateFile)
}

func (m *Manager) logPath() string {
	return filepath.Join(m.gitDir, logFile)
}

func (m *Manager) candidatesPath() string {
	return filepath.Join(m.gitDir, candidatesFile)
}

func (m *Manager) InProgress() bool {
	_, err := os.Stat(m.statePath())
	return err == nil
}

func (m *Manager) Load() (*State, error) {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil, fmt.Errorf("no bisect in progress")
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("corrupted bisect state: %w", err)
	}

	return &state, nil
}

func (m *Manager) Save(state *State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath(), data, 0644)
}

func (m *Manager) SaveCandidates(candidates []Candidate) error {
	data, err := json.MarshalIndent(candidates, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.candidatesPath(), data, 0644)
}

func (m *Manager) LoadCandidates() ([]Candidate, error) {
	data, err := os.ReadFile(m.candidatesPath())
	if err != nil {
		return nil, err
	}

	var candidates []Candidate
	if err := json.Unmarshal(data, &candidates); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (m *Manager) AppendLog(entry string) error {
	f, err := os.OpenFile(m.logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, err = fmt.Fprintln(f, entry)
	return err
}

func (m *Manager) ReadLog() ([]string, error) {
	f, err := os.Open(m.logPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func (m *Manager) Clean() error {
	files := []string{m.statePath(), m.logPath(), m.candidatesPath()}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (m *Manager) IsGood(state *State, sha string) bool {
	for _, g := range state.GoodRevs {
		if strings.HasPrefix(sha, g) || strings.HasPrefix(g, sha) {
			return true
		}
	}
	return false
}

func (m *Manager) IsBad(state *State, sha string) bool {
	return strings.HasPrefix(sha, state.BadRev) || strings.HasPrefix(state.BadRev, sha)
}

func (m *Manager) IsSkipped(state *State, sha string) bool {
	for _, s := range state.SkippedRevs {
		if strings.HasPrefix(sha, s) || strings.HasPrefix(s, sha) {
			return true
		}
	}
	return false
}
