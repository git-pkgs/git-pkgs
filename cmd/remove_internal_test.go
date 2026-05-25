package cmd

import (
	"testing"

	"github.com/git-pkgs/resolve"
)

func TestFindDepInTree(t *testing.T) {
	tree := []*resolve.Dep{
		{
			Name:    "express",
			Version: "4.18.2",
			Deps: []*resolve.Dep{
				{
					Name:    "accepts",
					Version: "1.3.8",
					Deps: []*resolve.Dep{
						{
							Name:    "mime-types",
							Version: "2.1.35",
						},
					},
				},
				{
					Name:    "body-parser",
					Version: "1.20.1",
				},
			},
		},
		{
			Name:    "lodash",
			Version: "4.17.21",
		},
	}

	tests := []struct {
		name           string
		pkg            string
		wantDirect     bool
		wantTransitive bool
	}{
		{
			name:           "direct dep found",
			pkg:            "express",
			wantDirect:     true,
			wantTransitive: false,
		},
		{
			name:           "direct dep without children",
			pkg:            "lodash",
			wantDirect:     true,
			wantTransitive: false,
		},
		{
			name:           "transitive dep at depth 1",
			pkg:            "accepts",
			wantDirect:     false,
			wantTransitive: true,
		},
		{
			name:           "transitive dep at depth 2",
			pkg:            "mime-types",
			wantDirect:     false,
			wantTransitive: true,
		},
		{
			name:           "not found at all",
			pkg:            "not-a-dep",
			wantDirect:     false,
			wantTransitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isDirect, isTransitive := findDepInTree(tree, tt.pkg)
			if isDirect != tt.wantDirect {
				t.Errorf("isDirect = %v, want %v", isDirect, tt.wantDirect)
			}
			if isTransitive != tt.wantTransitive {
				t.Errorf("isTransitive = %v, want %v", isTransitive, tt.wantTransitive)
			}
		})
	}
}

func TestFindDepInTreeEmpty(t *testing.T) {
	isDirect, isTransitive := findDepInTree(nil, "anything")
	if isDirect {
		t.Error("isDirect should be false for empty tree")
	}
	if isTransitive {
		t.Error("isTransitive should be false for empty tree")
	}
}
