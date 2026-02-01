package analyzer

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/git-pkgs/manifests"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

func isSupplementFile(path string) bool {
	_, kind, ok := manifests.Identify(path)
	return ok && kind == manifests.Supplement
}

type Change struct {
	ManifestPath        string
	Ecosystem           string
	Kind                string
	Name                string
	PURL                string
	ChangeType          string // "added", "modified", "removed"
	Requirement         string
	PreviousRequirement string
	DependencyType      string
	Integrity           string
}

type SnapshotEntry struct {
	Ecosystem      string
	Kind           string
	PURL           string
	Requirement    string
	DependencyType string
	Integrity      string
}

type SnapshotKey struct {
	ManifestPath string
	Name         string
	Requirement  string
}

type Snapshot map[SnapshotKey]SnapshotEntry

type Result struct {
	Changes  []Change
	Snapshot Snapshot
}

type cachedDiff struct {
	added    []string
	modified []string
	deleted  []string
}

type Analyzer struct {
	blobCache map[string]*manifests.ParseResult
	diffCache map[string]*cachedDiff
	diffMu    sync.RWMutex
	repoPath  string
}

func New() *Analyzer {
	return &Analyzer{
		blobCache: make(map[string]*manifests.ParseResult),
		diffCache: make(map[string]*cachedDiff),
	}
}

// SetRepoPath sets the repository path for git shell commands.
func (a *Analyzer) SetRepoPath(path string) {
	a.repoPath = path
}

// PrefetchDiffs pre-computes diffs for all commits using a single git log command.
// This is much faster than individual git diff-tree calls.
func (a *Analyzer) PrefetchDiffs(commits []*object.Commit, numWorkers int) {
	if len(commits) == 0 || a.repoPath == "" {
		return
	}

	// Use git log with --name-status to get all diffs in one command
	lastSHA := commits[len(commits)-1].Hash.String()
	firstSHA := commits[0].Hash.String()

	// git log --name-status --format="COMMIT:%H" --reverse firstSHA^..lastSHA
	cmd := exec.Command("git", "log", "--name-status", "--format=COMMIT:%H", "--reverse", firstSHA+"^.."+lastSHA)
	cmd.Dir = a.repoPath

	output, err := cmd.Output()
	if err != nil {
		// Fallback for root commits: include first commit
		cmd = exec.Command("git", "log", "--name-status", "--format=COMMIT:%H", "--reverse", lastSHA)
		cmd.Dir = a.repoPath
		output, err = cmd.Output()
		if err != nil {
			return
		}
	}

	// Parse the output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentSHA string
	var currentDiff *cachedDiff

	for scanner.Scan() {
		line := scanner.Text()

		// Empty line - just skip
		if line == "" {
			continue
		}

		// COMMIT: line marks a new commit
		if strings.HasPrefix(line, "COMMIT:") {
			// Save previous commit
			if currentSHA != "" && currentDiff != nil {
				a.diffCache[currentSHA] = currentDiff
			}
			currentSHA = line[7:] // Remove "COMMIT:" prefix
			currentDiff = &cachedDiff{}
			continue
		}

		// Name-status line: A/M/D followed by tab, or R/C followed by digits and tab
		if currentDiff == nil || len(line) < 2 {
			continue
		}

		status := line[0]
		switch status {
		case 'A', 'M', 'D':
			if line[1] != '\t' {
				continue
			}
			path := line[2:]
			if _, _, ok := manifests.Identify(path); !ok {
				continue
			}
			switch status {
			case 'A':
				currentDiff.added = append(currentDiff.added, path)
			case 'M':
				currentDiff.modified = append(currentDiff.modified, path)
			case 'D':
				currentDiff.deleted = append(currentDiff.deleted, path)
			}

		case 'R', 'C':
			// Rename/Copy: R063\told_path\tnew_path or C063\told_path\tnew_path
			// Find the first tab to skip the status+percentage
			firstTab := strings.Index(line, "\t")
			if firstTab == -1 {
				continue
			}
			rest := line[firstTab+1:]
			secondTab := strings.Index(rest, "\t")
			if secondTab == -1 {
				continue
			}
			oldPath := rest[:secondTab]
			newPath := rest[secondTab+1:]

			// Treat rename as delete old + add new
			if _, _, ok := manifests.Identify(oldPath); ok {
				currentDiff.deleted = append(currentDiff.deleted, oldPath)
			}
			if _, _, ok := manifests.Identify(newPath); ok {
				currentDiff.added = append(currentDiff.added, newPath)
			}
		}
	}

	// Don't forget the last commit
	if currentSHA != "" && currentDiff != nil {
		a.diffCache[currentSHA] = currentDiff
	}
}

func (a *Analyzer) AnalyzeCommit(commit *object.Commit, previousSnapshot Snapshot) (*Result, error) {
	if len(commit.ParentHashes) > 1 {
		return nil, nil
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	var parentTree *object.Tree
	if commit.NumParents() > 0 {
		parent, err := commit.Parent(0)
		if err != nil {
			return nil, err
		}
		parentTree, err = parent.Tree()
		if err != nil {
			return nil, err
		}
	}

	// Check for cached diff first
	var added, modified, deleted []string
	a.diffMu.RLock()
	cached, hasCached := a.diffCache[commit.Hash.String()]
	a.diffMu.RUnlock()

	if hasCached {
		added = cached.added
		modified = cached.modified
		deleted = cached.deleted
	} else {
		// Fallback to go-git diff
		changes, err := object.DiffTree(parentTree, tree)
		if err != nil {
			return nil, err
		}

		for _, change := range changes {
			action, err := change.Action()
			if err != nil {
				continue
			}

			var path string
			if change.To.Name != "" {
				path = change.To.Name
			} else {
				path = change.From.Name
			}

			_, _, ok := manifests.Identify(path)
			if !ok {
				continue
			}

			switch action {
			case merkletrie.Insert:
				added = append(added, path)
			case merkletrie.Modify:
				modified = append(modified, path)
			case merkletrie.Delete:
				deleted = append(deleted, path)
			}
		}
	}

	if len(added) == 0 && len(modified) == 0 && len(deleted) == 0 {
		return nil, nil
	}

	result := &Result{
		Snapshot: copySnapshot(previousSnapshot),
	}

	for _, path := range added {
		if isSupplementFile(path) {
			continue
		}
		deps, err := a.parseManifestInTree(tree, path)
		if err != nil || deps == nil {
			continue
		}

		// Merge integrity hashes from supplement files in same directory
		supHashes := a.parseSupplementsInDir(tree, filepath.Dir(path))

		for _, dep := range deps.Dependencies {
			integrity := dep.Integrity
			if integrity == "" {
				if h, ok := supHashes[supplementKey{dep.Name, dep.Version}]; ok {
					integrity = h
				}
			}
			change := Change{
				ManifestPath:   path,
				Ecosystem:      deps.Ecosystem,
				Kind:           string(deps.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				ChangeType:     "added",
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
			}
			result.Changes = append(result.Changes, change)

			key := SnapshotKey{ManifestPath: path, Name: dep.Name, Requirement: dep.Version}
			result.Snapshot[key] = SnapshotEntry{
				Ecosystem:      deps.Ecosystem,
				Kind:           string(deps.Kind),
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
			}
		}
	}

	for _, path := range modified {
		if isSupplementFile(path) {
			continue
		}
		var beforeDeps *manifests.ParseResult
		if parentTree != nil {
			beforeDeps, _ = a.parseManifestInTree(parentTree, path)
		}
		afterDeps, err := a.parseManifestInTree(tree, path)
		if err != nil || afterDeps == nil {
			continue
		}

		// Merge integrity hashes from supplement files in same directory
		supHashes := a.parseSupplementsInDir(tree, filepath.Dir(path))

		// Build maps by name for change detection (modified = version changed)
		// But also track all name+version pairs for snapshot storage
		beforeByName := make(map[string]manifests.Dependency)
		beforeByNameVersion := make(map[string]bool)
		if beforeDeps != nil {
			for _, dep := range beforeDeps.Dependencies {
				beforeByName[dep.Name] = dep
				beforeByNameVersion[dep.Name+"\x00"+dep.Version] = true
			}
		}

		afterByName := make(map[string]manifests.Dependency)
		afterByNameVersion := make(map[string]bool)
		for _, dep := range afterDeps.Dependencies {
			afterByName[dep.Name] = dep
			afterByNameVersion[dep.Name+"\x00"+dep.Version] = true
		}

		// Remove all existing snapshot entries for this manifest before re-adding.
		// This handles stale entries that can accumulate when merge commits
		// (which are skipped) change the lockfile between snapshots.
		for key := range result.Snapshot {
			if key.ManifestPath == path {
				delete(result.Snapshot, key)
			}
		}

		// Process all dependencies in after, storing each unique name+version
		seen := make(map[string]bool)
		for _, dep := range afterDeps.Dependencies {
			nameVersion := dep.Name + "\x00" + dep.Version
			if seen[nameVersion] {
				continue
			}
			seen[nameVersion] = true

			integrity := dep.Integrity
			if integrity == "" {
				if h, ok := supHashes[supplementKey{dep.Name, dep.Version}]; ok {
					integrity = h
				}
			}

			key := SnapshotKey{ManifestPath: path, Name: dep.Name, Requirement: dep.Version}

			// Check if this exact name+version existed before
			if beforeByNameVersion[nameVersion] {
				// Same name+version exists, check if scope changed
				if before, ok := beforeByName[dep.Name]; ok && before.Version == dep.Version && before.Scope != dep.Scope {
					result.Changes = append(result.Changes, Change{
						ManifestPath:        path,
						Ecosystem:           afterDeps.Ecosystem,
						Kind:                string(afterDeps.Kind),
						Name:                dep.Name,
						PURL:                dep.PURL,
						ChangeType:          "modified",
						Requirement:         dep.Version,
						PreviousRequirement: before.Version,
						DependencyType:      string(dep.Scope),
						Integrity:           integrity,
					})
				}
			} else if before, exists := beforeByName[dep.Name]; exists {
				// Same name but different version - this is a "modified" change
				result.Changes = append(result.Changes, Change{
					ManifestPath:        path,
					Ecosystem:           afterDeps.Ecosystem,
					Kind:                string(afterDeps.Kind),
					Name:                dep.Name,
					PURL:                dep.PURL,
					ChangeType:          "modified",
					Requirement:         dep.Version,
					PreviousRequirement: before.Version,
					DependencyType:      string(dep.Scope),
					Integrity:           integrity,
				})
			} else {
				// Completely new package
				result.Changes = append(result.Changes, Change{
					ManifestPath:   path,
					Ecosystem:      afterDeps.Ecosystem,
					Kind:           string(afterDeps.Kind),
					Name:           dep.Name,
					PURL:           dep.PURL,
					ChangeType:     "added",
					Requirement:    dep.Version,
					DependencyType: string(dep.Scope),
					Integrity:      integrity,
				})
			}

			result.Snapshot[key] = SnapshotEntry{
				Ecosystem:      afterDeps.Ecosystem,
				Kind:           string(afterDeps.Kind),
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
			}
		}

		// Check for removed dependencies
		seenBefore := make(map[string]bool)
		if beforeDeps != nil {
			for _, dep := range beforeDeps.Dependencies {
				nameVersion := dep.Name + "\x00" + dep.Version
				if seenBefore[nameVersion] {
					continue
				}
				seenBefore[nameVersion] = true

				if !afterByNameVersion[nameVersion] {
					// This exact name+version is gone
					if _, stillExists := afterByName[dep.Name]; !stillExists {
						// Package completely removed (not just version change)
						result.Changes = append(result.Changes, Change{
							ManifestPath:   path,
							Ecosystem:      beforeDeps.Ecosystem,
							Kind:           string(beforeDeps.Kind),
							Name:           dep.Name,
							PURL:           dep.PURL,
							ChangeType:     "removed",
							Requirement:    dep.Version,
							DependencyType: string(dep.Scope),
							Integrity:      dep.Integrity,
						})
					}
					key := SnapshotKey{ManifestPath: path, Name: dep.Name, Requirement: dep.Version}
					delete(result.Snapshot, key)
				}
			}
		}
	}

	for _, path := range deleted {
		if isSupplementFile(path) {
			continue
		}
		var deps *manifests.ParseResult
		if parentTree != nil {
			deps, _ = a.parseManifestInTree(parentTree, path)
		}
		if deps == nil {
			continue
		}

		for _, dep := range deps.Dependencies {
			result.Changes = append(result.Changes, Change{
				ManifestPath:   path,
				Ecosystem:      deps.Ecosystem,
				Kind:           string(deps.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				ChangeType:     "removed",
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      dep.Integrity,
			})

			key := SnapshotKey{ManifestPath: path, Name: dep.Name, Requirement: dep.Version}
			delete(result.Snapshot, key)
		}
	}

	return result, nil
}

func (a *Analyzer) parseManifestInTree(tree *object.Tree, path string) (*manifests.ParseResult, error) {
	file, err := tree.File(path)
	if err != nil {
		return nil, err
	}

	content, err := file.Contents()
	if err != nil {
		return nil, err
	}

	cacheKey := file.Hash.String() + ":" + path
	if result, ok := a.blobCache[cacheKey]; ok {
		return result, nil
	}

	result, err := manifests.Parse(path, []byte(content))
	if err != nil {
		a.blobCache[cacheKey] = nil
		return nil, nil
	}

	a.blobCache[cacheKey] = result
	return result, nil
}

func (a *Analyzer) DependenciesAtCommit(commit *object.Commit) ([]Change, error) {
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	var deps []Change

	err = tree.Files().ForEach(func(f *object.File) error {
		_, _, ok := manifests.Identify(f.Name)
		if !ok {
			return nil
		}
		if isSupplementFile(f.Name) {
			return nil
		}

		result, err := a.parseManifestInTree(tree, f.Name)
		if err != nil || result == nil {
			return nil
		}

		supHashes := a.parseSupplementsInDir(tree, filepath.Dir(f.Name))

		for _, dep := range result.Dependencies {
			integrity := dep.Integrity
			if integrity == "" {
				if h, ok := supHashes[supplementKey{dep.Name, dep.Version}]; ok {
					integrity = h
				}
			}
			deps = append(deps, Change{
				ManifestPath:   f.Name,
				Ecosystem:      result.Ecosystem,
				Kind:           string(result.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
			})
		}

		return nil
	})

	return deps, err
}

// supplementKey identifies a dependency for supplement hash matching.
type supplementKey struct {
	name    string
	version string
}

// parseSupplementsInDir reads all supplement files in the same directory as the given path
// from the tree, and returns a map of name+version to integrity hash.
func (a *Analyzer) parseSupplementsInDir(tree *object.Tree, dir string) map[supplementKey]string {
	if tree == nil {
		return nil
	}

	hashes := make(map[supplementKey]string)

	_ = tree.Files().ForEach(func(f *object.File) error {
		fileDir := filepath.Dir(f.Name)
		if fileDir == "." {
			fileDir = ""
		}
		if dir == "." {
			dir = ""
		}
		if fileDir != dir {
			return nil
		}
		if !isSupplementFile(f.Name) {
			return nil
		}

		result, err := a.parseManifestInTree(tree, f.Name)
		if err != nil || result == nil {
			return nil
		}

		for _, dep := range result.Dependencies {
			if dep.Integrity != "" {
				hashes[supplementKey{dep.Name, dep.Version}] = dep.Integrity
			}
		}
		return nil
	})

	return hashes
}

func (a *Analyzer) DependenciesInWorkingDir(root string) ([]Change, error) {
	var deps []Change

	// Load gitignore patterns
	var matcher gitignore.Matcher
	if repo, err := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true}); err == nil {
		if wt, err := repo.Worktree(); err == nil {
			if patterns, err := gitignore.ReadPatterns(wt.Filesystem, nil); err == nil {
				matcher = gitignore.NewMatcher(patterns)
			}
		}
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		// Normalize to forward slashes for cross-platform consistency with git paths
		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			// Always skip .git
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			// Skip directories that match gitignore patterns
			if matcher != nil && matcher.Match(strings.Split(relPath, "/"), true) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip files that match gitignore patterns
		if matcher != nil && matcher.Match(strings.Split(relPath, "/"), false) {
			return nil
		}

		_, _, ok := manifests.Identify(relPath)
		if !ok {
			return nil
		}

		if isSupplementFile(relPath) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		result, err := manifests.Parse(relPath, content)
		if err != nil || result == nil {
			return nil
		}

		// Look for supplement files in the same directory
		supHashes := a.parseSupplementsInWorkingDir(filepath.Dir(path), filepath.Dir(relPath))

		for _, dep := range result.Dependencies {
			integrity := dep.Integrity
			if integrity == "" {
				if h, ok := supHashes[supplementKey{dep.Name, dep.Version}]; ok {
					integrity = h
				}
			}
			deps = append(deps, Change{
				ManifestPath:   relPath,
				Ecosystem:      result.Ecosystem,
				Kind:           string(result.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
			})
		}

		return nil
	})

	return deps, err
}

func (a *Analyzer) parseSupplementsInWorkingDir(absDir, relDir string) map[supplementKey]string {
	hashes := make(map[supplementKey]string)

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return hashes
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		relPath := filepath.ToSlash(filepath.Join(relDir, entry.Name()))
		if !isSupplementFile(relPath) {
			continue
		}

		content, err := os.ReadFile(filepath.Join(absDir, entry.Name()))
		if err != nil {
			continue
		}

		result, err := manifests.Parse(relPath, content)
		if err != nil || result == nil {
			continue
		}

		for _, dep := range result.Dependencies {
			if dep.Integrity != "" {
				hashes[supplementKey{dep.Name, dep.Version}] = dep.Integrity
			}
		}
	}

	return hashes
}

func copySnapshot(s Snapshot) Snapshot {
	if s == nil {
		return make(Snapshot)
	}
	result := make(Snapshot, len(s))
	for k, v := range s {
		result[k] = v
	}
	return result
}
