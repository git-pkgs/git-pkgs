package analyzer

import (
	"path/filepath"

	"github.com/git-pkgs/manifests"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

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
}

type Snapshot map[SnapshotKey]SnapshotEntry

type Result struct {
	Changes  []Change
	Snapshot Snapshot
}

type Analyzer struct {
	blobCache map[string]*manifests.ParseResult
}

func New() *Analyzer {
	return &Analyzer{
		blobCache: make(map[string]*manifests.ParseResult),
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

	changes, err := object.DiffTree(parentTree, tree)
	if err != nil {
		return nil, err
	}

	var added, modified, deleted []string
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

		_, _, ok := manifests.Identify(filepath.Base(path))
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

	if len(added) == 0 && len(modified) == 0 && len(deleted) == 0 {
		return nil, nil
	}

	result := &Result{
		Snapshot: copySnapshot(previousSnapshot),
	}

	for _, path := range added {
		deps, err := a.parseManifestInTree(tree, path)
		if err != nil || deps == nil {
			continue
		}

		for _, dep := range deps.Dependencies {
			change := Change{
				ManifestPath:   path,
				Ecosystem:      deps.Ecosystem,
				Kind:           string(deps.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				ChangeType:     "added",
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      dep.Integrity,
			}
			result.Changes = append(result.Changes, change)

			key := SnapshotKey{ManifestPath: path, Name: dep.Name}
			result.Snapshot[key] = SnapshotEntry{
				Ecosystem:      deps.Ecosystem,
				Kind:           string(deps.Kind),
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      dep.Integrity,
			}
		}
	}

	for _, path := range modified {
		var beforeDeps *manifests.ParseResult
		if parentTree != nil {
			beforeDeps, _ = a.parseManifestInTree(parentTree, path)
		}
		afterDeps, err := a.parseManifestInTree(tree, path)
		if err != nil || afterDeps == nil {
			continue
		}

		beforeMap := make(map[string]manifests.Dependency)
		if beforeDeps != nil {
			for _, dep := range beforeDeps.Dependencies {
				beforeMap[dep.Name] = dep
			}
		}

		afterMap := make(map[string]manifests.Dependency)
		for _, dep := range afterDeps.Dependencies {
			afterMap[dep.Name] = dep
		}

		for name, dep := range afterMap {
			key := SnapshotKey{ManifestPath: path, Name: name}
			if before, exists := beforeMap[name]; exists {
				if before.Version != dep.Version || before.Scope != dep.Scope {
					result.Changes = append(result.Changes, Change{
						ManifestPath:        path,
						Ecosystem:           afterDeps.Ecosystem,
						Kind:                string(afterDeps.Kind),
						Name:                name,
						PURL:                dep.PURL,
						ChangeType:          "modified",
						Requirement:         dep.Version,
						PreviousRequirement: before.Version,
						DependencyType:      string(dep.Scope),
						Integrity:           dep.Integrity,
					})
				}
			} else {
				result.Changes = append(result.Changes, Change{
					ManifestPath:   path,
					Ecosystem:      afterDeps.Ecosystem,
					Kind:           string(afterDeps.Kind),
					Name:           name,
					PURL:           dep.PURL,
					ChangeType:     "added",
					Requirement:    dep.Version,
					DependencyType: string(dep.Scope),
					Integrity:      dep.Integrity,
				})
			}

			result.Snapshot[key] = SnapshotEntry{
				Ecosystem:      afterDeps.Ecosystem,
				Kind:           string(afterDeps.Kind),
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      dep.Integrity,
			}
		}

		for name, dep := range beforeMap {
			if _, exists := afterMap[name]; !exists {
				result.Changes = append(result.Changes, Change{
					ManifestPath:   path,
					Ecosystem:      beforeDeps.Ecosystem,
					Kind:           string(beforeDeps.Kind),
					Name:           name,
					PURL:           dep.PURL,
					ChangeType:     "removed",
					Requirement:    dep.Version,
					DependencyType: string(dep.Scope),
					Integrity:      dep.Integrity,
				})

				key := SnapshotKey{ManifestPath: path, Name: name}
				delete(result.Snapshot, key)
			}
		}
	}

	for _, path := range deleted {
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

			key := SnapshotKey{ManifestPath: path, Name: dep.Name}
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
		_, _, ok := manifests.Identify(filepath.Base(f.Name))
		if !ok {
			return nil
		}

		result, err := a.parseManifestInTree(tree, f.Name)
		if err != nil || result == nil {
			return nil
		}

		for _, dep := range result.Dependencies {
			deps = append(deps, Change{
				ManifestPath:   f.Name,
				Ecosystem:      result.Ecosystem,
				Kind:           string(result.Kind),
				Name:           dep.Name,
				PURL:           dep.PURL,
				Requirement:    dep.Version,
				DependencyType: string(dep.Scope),
				Integrity:      dep.Integrity,
			})
		}

		return nil
	})

	return deps, err
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
