package analyzer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/git-pkgs/git-pkgs/internal/config"
	"github.com/git-pkgs/gitignore"
	"github.com/git-pkgs/manifests"
	"github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/utils/merkletrie"
)

func isSupplementFile(path string) bool {
	_, kind, ok := manifests.Identify(path)
	return ok && kind == manifests.Supplement
}

type Change struct {
	ManifestPath           string
	Ecosystem              string
	Kind                   string
	Name                   string
	PURL                   string
	ChangeType             string // "added", "modified", "removed"
	Requirement            string
	PreviousRequirement    string
	DependencyType         string
	PreviousDependencyType string
	Integrity              string
	Direct                 bool
}

type SnapshotEntry struct {
	Ecosystem      string
	Kind           string
	PURL           string
	Requirement    string
	DependencyType string
	Integrity      string
	Direct         bool
}

type SnapshotKey struct {
	ManifestPath string
	Name         string
	Requirement  string
}

type Snapshot map[SnapshotKey]SnapshotEntry

// ManifestLicense records the package license values declared by a manifest.
// Removed marks the manifest as absent from this commit onward.
type ManifestLicense struct {
	ManifestPath string
	Ecosystem    string
	Kind         string
	Licenses     []string
	LicenseFile  string
	Removed      bool
}

type Result struct {
	Changes          []Change
	Snapshot         Snapshot
	ManifestLicenses []ManifestLicense
}

type ManifestChanges struct {
	Added    []string
	Modified []string
	Deleted  []string
}

type Analyzer struct {
	blobCache       map[string]*manifests.ParseResult
	ecosystemFilter config.EcosystemFilter
}

func New() *Analyzer {
	return &Analyzer{
		blobCache: make(map[string]*manifests.ParseResult),
	}
}

// SetEcosystemFilter limits which ecosystems are analyzed.
func (a *Analyzer) SetEcosystemFilter(filter config.EcosystemFilter) {
	a.ecosystemFilter = filter
}

func (a *Analyzer) allowsEcosystem(ecosystem string) bool {
	return a.ecosystemFilter.Allows(ecosystem)
}

// ClearBlobCache replaces the blobCache with a fresh empty map,
// allowing the GC to reclaim all cached parse results.
func (a *Analyzer) ClearBlobCache() {
	a.blobCache = make(map[string]*manifests.ParseResult)
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

	diff, err := object.DiffTree(parentTree, tree)
	if err != nil {
		return nil, err
	}

	var changes ManifestChanges
	for _, change := range diff {
		action, err := change.Action()
		if err != nil {
			continue
		}

		path := change.To.Name
		if path == "" {
			path = change.From.Name
		}
		if _, _, ok := manifests.Identify(path); !ok {
			continue
		}

		switch action {
		case merkletrie.Insert:
			changes.Added = append(changes.Added, path)
		case merkletrie.Modify:
			changes.Modified = append(changes.Modified, path)
		case merkletrie.Delete:
			changes.Deleted = append(changes.Deleted, path)
		}
	}
	return a.analyzeManifestChanges(changes, previousSnapshot, tree, parentTree, true)
}

// AnalyzeCommitChanges applies known manifest paths and updates previousSnapshot
// in place. The caller must not retain an older view of that map.
func (a *Analyzer) AnalyzeCommitChanges(
	commit *object.Commit,
	previousSnapshot Snapshot,
	changes ManifestChanges,
) (*Result, error) {
	if len(commit.ParentHashes) > 1 || changes.empty() {
		return nil, nil
	}

	var tree, parentTree *object.Tree
	if len(changes.Added) > 0 || len(changes.Modified) > 0 {
		var err error
		tree, err = commit.Tree()
		if err != nil {
			return nil, err
		}
	}
	if commit.NumParents() > 0 && (len(changes.Modified) > 0 || len(changes.Deleted) > 0) {
		parent, err := commit.Parent(0)
		if err != nil {
			return nil, err
		}
		parentTree, err = parent.Tree()
		if err != nil {
			return nil, err
		}
	}
	return a.analyzeManifestChanges(changes, previousSnapshot, tree, parentTree, false)
}

func (c ManifestChanges) empty() bool {
	return len(c.Added) == 0 && len(c.Modified) == 0 && len(c.Deleted) == 0
}

//nolint:gocognit,gocyclo,maintidx // Manifest changes share one ordered snapshot mutation pass.
func (a *Analyzer) analyzeManifestChanges(
	changes ManifestChanges,
	previousSnapshot Snapshot,
	tree *object.Tree,
	parentTree *object.Tree,
	copyPrevious bool,
) (*Result, error) {
	if changes.empty() {
		return nil, nil
	}

	added, modified, deleted := changes.Added, changes.Modified, changes.Deleted

	snapshot := previousSnapshot
	if copyPrevious {
		snapshot = copySnapshot(previousSnapshot)
	} else if snapshot == nil {
		snapshot = make(Snapshot)
	}
	result := &Result{Snapshot: snapshot}

	for _, path := range added {
		if isSupplementFile(path) {
			continue
		}
		deps, err := a.parseManifestInTree(tree, path)
		if err != nil || deps == nil {
			continue
		}
		if !a.allowsEcosystem(deps.Ecosystem) {
			continue
		}
		result.addManifestLicense(path, deps, false)

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
				Direct:         dep.Direct,
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
				Direct:         dep.Direct,
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
		if !a.allowsEcosystem(afterDeps.Ecosystem) {
			for key := range result.Snapshot {
				if key.ManifestPath == path {
					delete(result.Snapshot, key)
				}
			}
			continue
		}
		result.addManifestLicense(path, afterDeps, false)

		// Merge integrity hashes from supplement files in same directory
		supHashes := a.parseSupplementsInDir(tree, filepath.Dir(path))

		// Build multi-maps by name for change detection, since lockfiles can
		// contain the same package at multiple versions (e.g. npm hoisting).
		beforeVersions := make(map[string][]manifests.Dependency)
		beforeByNameVersion := make(map[string]bool)
		if beforeDeps != nil {
			for _, dep := range beforeDeps.Dependencies {
				beforeVersions[dep.Name] = append(beforeVersions[dep.Name], dep)
				beforeByNameVersion[dep.Name+"\x00"+dep.Version] = true
			}
		}

		afterVersions := make(map[string][]manifests.Dependency)
		afterByNameVersion := make(map[string]bool)
		for _, dep := range afterDeps.Dependencies {
			afterVersions[dep.Name] = append(afterVersions[dep.Name], dep)
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
				for _, before := range beforeVersions[dep.Name] {
					if before.Version == dep.Version && before.Scope != dep.Scope {
						result.Changes = append(result.Changes, Change{
							ManifestPath:           path,
							Ecosystem:              afterDeps.Ecosystem,
							Kind:                   string(afterDeps.Kind),
							Name:                   dep.Name,
							PURL:                   dep.PURL,
							ChangeType:             "modified",
							Requirement:            dep.Version,
							DependencyType:         string(dep.Scope),
							PreviousDependencyType: string(before.Scope),
							Integrity:              integrity,
							Direct:                 dep.Direct,
						})
						break
					}
				}
			} else if versions, exists := beforeVersions[dep.Name]; exists {
				// Same name but different version - find which old version was replaced
				var previousVersion string
				for _, before := range versions {
					if !afterByNameVersion[dep.Name+"\x00"+before.Version] {
						previousVersion = before.Version
						break
					}
				}
				if previousVersion == "" {
					// All old versions still exist, this is a newly added version
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
						Direct:         dep.Direct,
					})
				} else {
					result.Changes = append(result.Changes, Change{
						ManifestPath:        path,
						Ecosystem:           afterDeps.Ecosystem,
						Kind:                string(afterDeps.Kind),
						Name:                dep.Name,
						PURL:                dep.PURL,
						ChangeType:          "modified",
						Requirement:         dep.Version,
						PreviousRequirement: previousVersion,
						DependencyType:      string(dep.Scope),
						Integrity:           integrity,
						Direct:              dep.Direct,
					})
				}
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
					Direct:         dep.Direct,
				})
			}

			result.Snapshot[key] = SnapshotEntry{
				Ecosystem:      afterDeps.Ecosystem,
				Kind:           string(afterDeps.Kind),
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
				Direct:         dep.Direct,
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
					if _, stillExists := afterVersions[dep.Name]; !stillExists {
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
							Direct:         dep.Direct,
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
		if !a.allowsEcosystem(deps.Ecosystem) {
			continue
		}
		result.addManifestLicense(path, deps, true)

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
				Direct:         dep.Direct,
			})

			key := SnapshotKey{ManifestPath: path, Name: dep.Name, Requirement: dep.Version}
			delete(result.Snapshot, key)
		}
	}

	return result, nil
}

func (r *Result) addManifestLicense(path string, parsed *manifests.ParseResult, removed bool) {
	if parsed == nil || parsed.Kind != manifests.Manifest {
		return
	}
	licenses := append([]string(nil), parsed.Licenses...)
	if licenses == nil {
		licenses = []string{}
	}
	r.ManifestLicenses = append(r.ManifestLicenses, ManifestLicense{
		ManifestPath: path,
		Ecosystem:    parsed.Ecosystem,
		Kind:         string(parsed.Kind),
		Licenses:     licenses,
		LicenseFile:  parsed.LicenseFile,
		Removed:      removed,
	})
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
	var deps []Change
	err := a.walkDependenciesAtCommit(commit, func(dep Change) {
		deps = append(deps, dep)
	})
	return deps, err
}

// SnapshotAtCommit returns dependency state parsed from the commit tree.
func (a *Analyzer) SnapshotAtCommit(commit *object.Commit) (Snapshot, error) {
	snapshot := make(Snapshot)
	err := a.walkDependenciesAtCommit(commit, func(dep Change) {
		key := SnapshotKey{
			ManifestPath: dep.ManifestPath,
			Name:         dep.Name,
			Requirement:  dep.Requirement,
		}
		snapshot[key] = SnapshotEntry{
			Ecosystem:      dep.Ecosystem,
			Kind:           dep.Kind,
			PURL:           dep.PURL,
			Requirement:    dep.Requirement,
			DependencyType: dep.DependencyType,
			Integrity:      dep.Integrity,
			Direct:         dep.Direct,
		}
	})
	return snapshot, err
}

func (a *Analyzer) walkDependenciesAtCommit(commit *object.Commit, visit func(Change)) error {
	tree, err := commit.Tree()
	if err != nil {
		return err
	}

	err = walkManifestPaths(tree, "", func(path string) error {
		result, err := a.parseManifestInTree(tree, path)
		if err != nil || result == nil {
			return nil
		}
		if !a.allowsEcosystem(result.Ecosystem) {
			return nil
		}

		supHashes := a.parseSupplementsInDir(tree, filepath.Dir(path))

		for _, dep := range result.Dependencies {
			integrity := dep.Integrity
			if integrity == "" {
				if h, ok := supHashes[supplementKey{dep.Name, dep.Version}]; ok {
					integrity = h
				}
			}
			visit(Change{
				ManifestPath:   path,
				Ecosystem:      result.Ecosystem,
				Kind:           string(result.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      integrity,
				Direct:         dep.Direct,
			})
		}

		return nil
	})
	return err
}

func walkManifestPaths(tree *object.Tree, prefix string, visit func(string) error) error {
	for _, entry := range tree.Entries {
		path := entry.Name
		if prefix != "" {
			path = prefix + "/" + entry.Name
		}
		if entry.Mode == filemode.Dir {
			child, err := tree.Tree(entry.Name)
			if err != nil {
				return err
			}
			if err := walkManifestPaths(child, path, visit); err != nil {
				return err
			}
			continue
		}
		if !entry.Mode.IsFile() || isSupplementFile(path) {
			continue
		}
		if _, _, ok := manifests.Identify(path); !ok {
			continue
		}
		if err := visit(path); err != nil {
			return err
		}
	}
	return nil
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

	// Get the target directory's tree directly instead of iterating all files
	var targetTree *object.Tree
	if dir == "" || dir == "." {
		targetTree = tree
	} else {
		var err error
		targetTree, err = tree.Tree(dir)
		if err != nil {
			// Directory doesn't exist in this tree
			return hashes
		}
	}

	// Iterate only direct entries in this directory (not recursive)
	for _, entry := range targetTree.Entries {
		// Skip subdirectories and non-regular files
		if !entry.Mode.IsFile() {
			continue
		}

		// Build the full path for identification
		var fullPath string
		if dir == "" || dir == "." {
			fullPath = entry.Name
		} else {
			fullPath = dir + "/" + entry.Name
		}

		if !isSupplementFile(fullPath) {
			continue
		}

		result, err := a.parseManifestInTree(tree, fullPath)
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

func readFileInRoot(r *os.Root, name string) ([]byte, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func (a *Analyzer) DependenciesInWorkingDir(root string, includeSubmodules bool) ([]Change, error) {
	var deps []Change

	// Scope all file reads to the repo directory. Manifest paths are
	// repo-controlled; a symlink named like a manifest could point anywhere.
	osRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("opening root %q: %w", root, err)
	}
	defer func() { _ = osRoot.Close() }()

	// Load gitignore patterns and submodule paths
	matcher := gitignore.New(root)
	var submodulePaths map[string]bool
	if repo, err := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true}); err == nil {
		if wt, err := repo.Worktree(); err == nil {
			// Load submodule paths only if we need to skip them
			if !includeSubmodules {
				if submodules, err := wt.Submodules(); err == nil {
					submodulePaths = make(map[string]bool, len(submodules))
					for _, submodule := range submodules {
						config := submodule.Config()
						path := filepath.ToSlash(config.Path)
						submodulePaths[path] = true
					}
				}
			}
		}
	}

	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		osRel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		// Normalize to forward slashes for cross-platform consistency with git paths
		relPath := filepath.ToSlash(osRel)

		if info.IsDir() {
			// Always skip .git
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			// Skip directories that match gitignore patterns
			if relPath != "." && matcher.Match(relPath+"/") {
				return filepath.SkipDir
			}
			// Skip git submodule directories
			if submodulePaths != nil && submodulePaths[relPath] {
				return filepath.SkipDir
			}
			// Pick up nested .gitignore files
			if relPath != "." {
				nestedIgnore := filepath.Join(path, ".gitignore")
				if _, err := os.Stat(nestedIgnore); err == nil {
					matcher.AddFromFile(nestedIgnore, relPath)
				}
			}
			return nil
		}

		// Skip files that match gitignore patterns
		if matcher.Match(relPath) {
			return nil
		}

		_, _, ok := manifests.Identify(relPath)
		if !ok {
			return nil
		}

		if isSupplementFile(relPath) {
			return nil
		}

		content, err := readFileInRoot(osRoot, osRel)
		if err != nil {
			return nil
		}

		result, err := manifests.Parse(relPath, content)
		if err != nil || result == nil {
			return nil
		}
		if !a.allowsEcosystem(result.Ecosystem) {
			return nil
		}

		// Look for supplement files in the same directory
		supHashes := a.parseSupplementsInWorkingDir(osRoot, filepath.Dir(osRel), filepath.Dir(relPath))

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
				Direct:         dep.Direct,
			})
		}

		return nil
	})

	return deps, err
}

func (a *Analyzer) parseSupplementsInWorkingDir(osRoot *os.Root, osDir, relDir string) map[supplementKey]string {
	hashes := make(map[supplementKey]string)

	d, err := osRoot.Open(osDir)
	if err != nil {
		return hashes
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
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

		content, err := readFileInRoot(osRoot, filepath.Join(osDir, entry.Name()))
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
