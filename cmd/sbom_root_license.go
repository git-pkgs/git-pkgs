package cmd

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/manifests"
	"github.com/git-pkgs/spdx"
	"github.com/go-git/go-git/v6/plumbing/object"
)

type projectLicenses struct {
	Expression string
	Names      []string
	Files      []projectLicenseFile
}

type projectLicenseFile struct {
	Path string
	Text string
}

func projectLicensesAtRevision(repo *git.Repository, revision string) (projectLicenses, []string, error) {
	if revision == "" {
		revision = "HEAD"
	}

	hash, err := repo.ResolveRevision(revision)
	if err != nil {
		return projectLicenses{}, nil, fmt.Errorf("resolving %q: %w", revision, err)
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return projectLicenses{}, nil, fmt.Errorf("getting commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return projectLicenses{}, nil, fmt.Errorf("getting commit tree: %w", err)
	}

	var declaredLicenses []string
	var warnings []string
	declaredFiles := make(map[string]string)
	for i := range tree.Entries {
		entry := &tree.Entries[i]
		if !entry.Mode.IsFile() {
			continue
		}
		file, err := tree.TreeEntryFile(entry)
		if err != nil {
			return projectLicenses{}, nil, fmt.Errorf("reading %s: %w", entry.Name, err)
		}
		_, kind, ok := manifests.Identify(file.Name)
		if !ok || kind != manifests.Manifest {
			continue
		}

		content, err := file.Contents()
		if err != nil {
			return projectLicenses{}, nil, fmt.Errorf("reading %s: %w", file.Name, err)
		}
		result, err := manifests.Parse(file.Name, []byte(content))
		if err != nil {
			continue
		}
		declaredLicenses = append(declaredLicenses, result.Licenses...)
		if result.LicenseFile != "" {
			licenseFile, warning, err := readProjectLicenseFile(tree, file.Name, result.LicenseFile)
			if err != nil {
				return projectLicenses{}, nil, err
			}
			if warning != "" {
				warnings = append(warnings, warning)
				continue
			}
			declaredFiles[licenseFile.Path] = licenseFile.Text
		}
	}
	licenses := normalizeProjectLicenses(declaredLicenses)
	licenses.Files = sortedProjectLicenseFiles(declaredFiles)
	return licenses, warnings, nil
}

func readProjectLicenseFile(
	tree *object.Tree,
	manifestPath, declaredPath string,
) (projectLicenseFile, string, error) {
	declaredPath = strings.TrimSpace(declaredPath)
	resolvedPath := path.Clean(path.Join(path.Dir(manifestPath), declaredPath))
	if declaredPath == "" || path.IsAbs(declaredPath) || resolvedPath == ".." || strings.HasPrefix(resolvedPath, "../") {
		return projectLicenseFile{}, "", fmt.Errorf("invalid license file path %q in %s", declaredPath, manifestPath)
	}

	file, err := tree.File(resolvedPath)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return projectLicenseFile{}, fmt.Sprintf(
				"license file %s declared by %s was not found", resolvedPath, manifestPath,
			), nil
		}
		return projectLicenseFile{}, "", fmt.Errorf(
			"reading license file %s declared by %s: %w", resolvedPath, manifestPath, err,
		)
	}
	content, err := file.Contents()
	if err != nil {
		return projectLicenseFile{}, "", fmt.Errorf(
			"reading license file %s declared by %s: %w", resolvedPath, manifestPath, err,
		)
	}
	if strings.TrimSpace(content) == "" {
		return projectLicenseFile{}, fmt.Sprintf(
			"license file %s declared by %s is empty", resolvedPath, manifestPath,
		), nil
	}
	return projectLicenseFile{Path: resolvedPath, Text: content}, "", nil
}

func sortedProjectLicenseFiles(files map[string]string) []projectLicenseFile {
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)

	result := make([]projectLicenseFile, 0, len(paths))
	for _, filePath := range paths {
		result = append(result, projectLicenseFile{Path: filePath, Text: files[filePath]})
	}
	return result
}

func normalizeProjectLicenses(values []string) projectLicenses {
	expressionSet := make(map[string]bool)
	nameSet := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		normalized, err := spdx.NormalizeExpressionLax(value)
		if err != nil || !spdx.Valid(normalized) {
			normalized, err = spdx.Normalize(value)
		}
		if err == nil && spdx.Valid(normalized) {
			expressionSet[normalized] = true
		} else {
			nameSet[value] = true
		}
	}

	expressions := sortedKeys(expressionSet)
	names := sortedKeys(nameSet)
	return projectLicenses{
		Expression: joinSPDXExpressions(expressions),
		Names:      names,
	}
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func joinSPDXExpressions(expressions []string) string {
	if len(expressions) == 0 {
		return ""
	}
	if len(expressions) == 1 {
		return expressions[0]
	}
	for i, expression := range expressions {
		if strings.Contains(expression, " AND ") || strings.Contains(expression, " OR ") {
			expressions[i] = "(" + expression + ")"
		}
	}
	joined, err := spdx.NormalizeExpression(strings.Join(expressions, " AND "))
	if err != nil {
		return ""
	}
	return joined
}
