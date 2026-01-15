package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addTreeCmd(rootCmd)
}

func addTreeCmd(parent *cobra.Command) {
	treeCmd := &cobra.Command{
		Use:   "tree",
		Short: "Display dependencies as a tree",
		Long:  `Show dependencies grouped by manifest and dependency type.`,
		RunE:  runTree,
	}

	treeCmd.Flags().String("commit", "", "Commit to show dependencies at (default: HEAD)")
	treeCmd.Flags().StringP("branch", "b", "", "Branch to query (default: first tracked branch)")
	treeCmd.Flags().StringP("ecosystem", "e", "", "Filter by ecosystem")
	treeCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	parent.AddCommand(treeCmd)
}

type TreeNode struct {
	Name     string      `json:"name"`
	Type     string      `json:"type,omitempty"`
	Children []*TreeNode `json:"children,omitempty"`
}

func runTree(cmd *cobra.Command, args []string) error {
	commitRef, _ := cmd.Flags().GetString("commit")
	branchName, _ := cmd.Flags().GetString("branch")
	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	var branchInfo *database.BranchInfo
	if branchName != "" {
		branchInfo, err = db.GetBranch(branchName)
		if err != nil {
			return fmt.Errorf("branch %q not found: %w", branchName, err)
		}
	} else {
		branchInfo, err = db.GetDefaultBranch()
		if err != nil {
			return fmt.Errorf("getting branch: %w", err)
		}
	}

	var deps []database.Dependency
	if commitRef == "" {
		deps, err = db.GetLatestDependencies(branchInfo.ID)
	} else {
		hash, resolveErr := repo.ResolveRevision(commitRef)
		if resolveErr != nil {
			return fmt.Errorf("resolving %q: %w", commitRef, resolveErr)
		}
		deps, err = db.GetDependenciesAtRef(hash.String(), branchInfo.ID)
	}
	if err != nil {
		return fmt.Errorf("getting dependencies: %w", err)
	}

	// Filter by ecosystem
	if ecosystem != "" {
		var filtered []database.Dependency
		for _, d := range deps {
			if strings.EqualFold(d.Ecosystem, ecosystem) {
				filtered = append(filtered, d)
			}
		}
		deps = filtered
	}

	if len(deps) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No dependencies found.")
		return nil
	}

	tree := buildTree(deps)

	switch format {
	case "json":
		return outputTreeJSON(cmd, tree)
	default:
		return outputTreeText(cmd, tree)
	}
}

func buildTree(deps []database.Dependency) []*TreeNode {
	// Group by manifest -> dependency type -> dependencies
	type manifestData struct {
		ecosystem string
		byType    map[string][]database.Dependency
	}

	byManifest := make(map[string]*manifestData)
	var manifestOrder []string

	for _, d := range deps {
		if _, exists := byManifest[d.ManifestPath]; !exists {
			byManifest[d.ManifestPath] = &manifestData{
				ecosystem: d.Ecosystem,
				byType:    make(map[string][]database.Dependency),
			}
			manifestOrder = append(manifestOrder, d.ManifestPath)
		}

		depType := d.DependencyType
		if depType == "" {
			depType = "runtime"
		}
		byManifest[d.ManifestPath].byType[depType] = append(byManifest[d.ManifestPath].byType[depType], d)
	}

	var tree []*TreeNode

	for _, manifestPath := range manifestOrder {
		data := byManifest[manifestPath]

		manifestNode := &TreeNode{
			Name: fmt.Sprintf("%s (%s)", manifestPath, data.ecosystem),
			Type: "manifest",
		}

		// Sort dependency types
		var depTypes []string
		for t := range data.byType {
			depTypes = append(depTypes, t)
		}
		sort.Strings(depTypes)

		for _, depType := range depTypes {
			typeDeps := data.byType[depType]

			typeNode := &TreeNode{
				Name: depType,
				Type: "group",
			}

			// Sort dependencies
			sort.Slice(typeDeps, func(i, j int) bool {
				return typeDeps[i].Name < typeDeps[j].Name
			})

			for _, d := range typeDeps {
				name := d.Name
				if d.Requirement != "" {
					name += " " + d.Requirement
				}
				typeNode.Children = append(typeNode.Children, &TreeNode{
					Name: name,
					Type: "dependency",
				})
			}

			manifestNode.Children = append(manifestNode.Children, typeNode)
		}

		tree = append(tree, manifestNode)
	}

	return tree
}

func outputTreeJSON(cmd *cobra.Command, tree []*TreeNode) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(tree)
}

func outputTreeText(cmd *cobra.Command, tree []*TreeNode) error {
	for _, manifest := range tree {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), manifest.Name)

		for i, group := range manifest.Children {
			isLastGroup := i == len(manifest.Children)-1
			groupPrefix := "├── "
			if isLastGroup {
				groupPrefix = "└── "
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s%s\n", groupPrefix, group.Name)

			for j, dep := range group.Children {
				isLastDep := j == len(group.Children)-1
				depPrefix := "│   ├── "
				if isLastGroup {
					depPrefix = "    ├── "
				}
				if isLastDep {
					if isLastGroup {
						depPrefix = "    └── "
					} else {
						depPrefix = "│   └── "
					}
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s%s\n", depPrefix, dep.Name)
			}
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
