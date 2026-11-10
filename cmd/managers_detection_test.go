package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func TestDetectManagersCompatibility(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []cmd.DetectedManager
	}{
		{
			name: "ecosystem order and public fields",
			files: map[string]string{
				"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{}}`,
				"Gemfile.lock":      "GEM\n  specs:\n\nDEPENDENCIES\n",
				"Cargo.toml":        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
				"go.mod":            "module example.com/app\n\ngo 1.26.0\n",
				"go.sum":            "",
			},
			want: []cmd.DetectedManager{
				{Name: "npm", Ecosystem: "npm", Lockfile: "package-lock.json"},
				{Name: "bundler", Ecosystem: "rubygems", Lockfile: "Gemfile.lock"},
				{Name: "cargo", Ecosystem: "cargo"},
				{Name: "gomod", Ecosystem: "go"},
			},
		},
		{
			name:  "npm manifest fallback",
			files: map[string]string{"package.json": `{"name":"app","private":true}`},
			want:  []cmd.DetectedManager{{Name: "npm", Ecosystem: "npm"}},
		},
		{
			name:  "python manifest fallback without tool section",
			files: map[string]string{"pyproject.toml": "[project]\nname = \"app\"\nversion = \"0.1.0\"\n"},
			want:  []cmd.DetectedManager{{Name: "uv", Ecosystem: "pypi"}},
		},
		{
			name: "python lockfile priority without manifest",
			files: map[string]string{
				"uv.lock":     "version = 1\nrevision = 3\nrequires-python = \">=3.12\"\n",
				"poetry.lock": "package = []\n[metadata]\nlock-version = \"2.1\"\n",
			},
			want: []cmd.DetectedManager{{Name: "uv", Ecosystem: "pypi", Lockfile: "uv.lock"}},
		},
		{
			name:  "poetry lockfile without manifest",
			files: map[string]string{"poetry.lock": "package = []\n[metadata]\nlock-version = \"2.1\"\n"},
			want:  []cmd.DetectedManager{{Name: "poetry", Ecosystem: "pypi", Lockfile: "poetry.lock"}},
		},
		{
			name: "yarn lockfile with berry config",
			files: map[string]string{
				"package.json": `{"name":"app","private":true}`,
				"yarn.lock":    "__metadata:\n  version: 8\n",
				".yarnrc.yml":  "nodeLinker: node-modules\n",
			},
			want: []cmd.DetectedManager{{Name: "yarn", Ecosystem: "npm", Lockfile: "yarn.lock"}},
		},
		{
			name:  "renv without activation file",
			files: map[string]string{"DESCRIPTION": "Package: app\nVersion: 0.1.0\n"},
			want:  []cmd.DetectedManager{{Name: "renv", Ecosystem: "cran"}},
		},
		{
			name: "nuget lockfile priority",
			files: map[string]string{
				"packages.config":     `<packages />`,
				"packages.lock.json":  `{"version":1,"dependencies":{}}`,
				"project.assets.json": `{"version":3,"targets":{},"libraries":{}}`,
			},
			want: []cmd.DetectedManager{{Name: "nuget", Ecosystem: "nuget", Lockfile: "packages.lock.json"}},
		},
		{
			name:  "nuget assets fallback",
			files: map[string]string{"project.assets.json": `{"version":3,"targets":{},"libraries":{}}`},
			want:  []cmd.DetectedManager{{Name: "nuget", Ecosystem: "nuget", Lockfile: "project.assets.json"}},
		},
		{
			name: "haskell lockfile priority",
			files: map[string]string{
				"cabal.project.freeze": "constraints: any.base ==4.20.0.0\n",
				"stack.yaml.lock":      "packages: []\nsnapshots: []\n",
			},
			want: []cmd.DetectedManager{{Name: "cabal", Ecosystem: "hackage", Lockfile: "cabal.project.freeze"}},
		},
		{
			name: "detection-only ecosystems",
			files: map[string]string{
				"Project.toml":      "[deps]\n",
				"Manifest.toml":     "manifest_format = \"2.0\"\n",
				"Cartfile":          "github \"Alamofire/Alamofire\" ~> 5.0\n",
				"Cartfile.resolved": "github \"Alamofire/Alamofire\" \"5.0.0\"\n",
				"elm.json":          `{"type":"application","source-directories":["src"],"elm-version":"0.19.1"}`,
				"dub.json":          `{"name":"app","dependencies":{}}`,
				"haxelib.json":      `{"name":"app","version":"0.1.0","dependencies":{}}`,
				"flake.nix":         "{ outputs = { self }: {}; }\n",
				"flake.lock":        `{"nodes":{"root":{}},"root":"root","version":7}`,
			},
			want: []cmd.DetectedManager{
				{Name: "pkg", Ecosystem: "julia", Lockfile: "Manifest.toml"},
				{Name: "carthage", Ecosystem: "carthage", Lockfile: "Cartfile.resolved"},
				{Name: "elm", Ecosystem: "elm"},
				{Name: "dub", Ecosystem: "dub"},
				{Name: "haxelib", Ecosystem: "haxelib"},
				{Name: "nix", Ecosystem: "nix", Lockfile: "flake.lock"},
			},
		},
		{
			name:  "go checksum file alone is insufficient",
			files: map[string]string{"go.sum": ""},
		},
		{
			name: "cabal wildcard manifest",
			files: map[string]string{
				"app.cabal": "cabal-version: 3.0\nname: app\nversion: 0.1.0.0\nbuild-type: Simple\n",
				"lib.cabal": "cabal-version: 3.0\nname: lib\nversion: 0.1.0.0\nbuild-type: Simple\n",
			},
			want: []cmd.DetectedManager{{Name: "cabal", Ecosystem: "hackage"}},
		},
		{
			name:  "vcpkg manifest is not a lockfile",
			files: map[string]string{"vcpkg.json": `{"name":"app","version":"0.1.0","dependencies":[]}`},
			want:  []cmd.DetectedManager{{Name: "vcpkg", Ecosystem: "vcpkg"}},
		},
		{
			name:  "nuget manifest fallback",
			files: map[string]string{"packages.config": `<packages />`},
			want:  []cmd.DetectedManager{{Name: "nuget", Ecosystem: "nuget"}},
		},
		{
			name: "expanded detection remains excluded",
			files: map[string]string{
				"Chart.yaml":          "apiVersion: v2\nname: app\nversion: 0.1.0\n",
				"Brewfile":            "brew 'jq'\n",
				"bun.lockb":           "binary lockfile",
				"npm-shrinkwrap.json": `{"lockfileVersion":3,"packages":{}}`,
				"deno.jsonc":          "{ // app\n}\n",
				"conda-lock.yml":      "version: 1\npackage: []\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDetectionFiles(t, dir, tt.files)
			got, err := cmd.DetectManagers(dir)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("DetectManagers = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestDetectManagersNpmLockfilePriority(t *testing.T) {
	files := map[string]string{
		"package.json":      `{"name":"app","private":true}`,
		"bun.lock":          `{"lockfileVersion":1,"workspaces":{"":{"name":"app"}},"packages":{}}`,
		"pnpm-lock.yaml":    "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
		"yarn.lock":         "# yarn lockfile v1\n",
		"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{}}`,
	}
	for _, choice := range []struct{ file, manager string }{
		{"bun.lock", "bun"},
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
	} {
		t.Run(choice.manager, func(t *testing.T) {
			dir := t.TempDir()
			writeDetectionFiles(t, dir, files)
			got, err := cmd.DetectManagers(dir)
			if err != nil {
				t.Fatal(err)
			}
			want := []cmd.DetectedManager{{Name: choice.manager, Ecosystem: "npm", Lockfile: choice.file}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("DetectManagers = %#v, want %#v", got, want)
			}
		})
		delete(files, choice.file)
	}
}

func TestDetectManagersOnlyCurrentDirectoryFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "package.json"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "app.cabal"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	writeDetectionFiles(t, filepath.Join(dir, "nested"), map[string]string{"Gemfile": "source 'https://rubygems.org'\n"})
	got, err := cmd.DetectManagers(dir)
	if err != nil || len(got) != 0 {
		t.Fatalf("DetectManagers = %#v, %v; want no managers", got, err)
	}
	if _, err := cmd.DetectManagers(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing directory error = %v, want os.ErrNotExist", err)
	}
}

func TestManagerDetectionCommandBoundary(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"install all", []string{"install", "--dry-run"}, "Detected: pnpm (pnpm-lock.yaml)\nWould run: [pnpm install]\nDetected: bundler\nWould run: [bundle install]\n"},
		{"filter ecosystem", []string{"install", "--dry-run", "-e", "gem"}, "Detected: bundler\nWould run: [bundle install]\n"},
		{"override manager", []string{"install", "--dry-run", "-e", "npm", "-m", "yarn"}, "Detected: yarn\nWould run: [yarn install]\n"},
		{"add with ecosystem", []string{"add", "lodash", "--dry-run", "-e", "npm"}, "Detected: pnpm (pnpm-lock.yaml)\nWould run: [pnpm add lodash]\n"},
		{"add override", []string{"add", "lodash", "--dry-run", "-e", "gem", "-m", "npm"}, "Detected: npm\nWould run: [npm install lodash]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeDetectionFiles(t, dir, map[string]string{
				"package.json":      `{"name":"app","private":true}`,
				"pnpm-lock.yaml":    "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
				"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{}}`,
				"Gemfile":           "source 'https://rubygems.org'\n",
			})
			defer chdir(t, dir)()
			root := cmd.NewRootCmd()
			root.SetArgs(tt.args)
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			if err := root.Execute(); err != nil {
				t.Fatal(err)
			}
			if got := out.String(); got != tt.want {
				t.Fatalf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManifestOnlyManagerCommandBoundary(t *testing.T) {
	dir := t.TempDir()
	writeDetectionFiles(t, dir, map[string]string{"package.json": `{"name":"app","private":true}`})
	defer chdir(t, dir)()
	for _, args := range [][]string{{"install", "--dry-run"}, {"add", "lodash", "--dry-run"}} {
		root := cmd.NewRootCmd()
		root.SetArgs(args)
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		want := "Detected: npm\nWould run: [npm install]\n"
		if args[0] == "add" {
			want = "Detected: npm\nWould run: [npm install lodash]\n"
		}
		if got := out.String(); got != want {
			t.Fatalf("%v output = %q, want %q", args, got, want)
		}
	}
}

func TestCabalManifestCommandBoundary(t *testing.T) {
	dir := t.TempDir()
	writeDetectionFiles(t, dir, map[string]string{
		"app.cabal": "cabal-version: 3.0\nname: app\nversion: 0.1.0.0\nbuild-type: Simple\n",
	})
	defer chdir(t, dir)()
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"install", "--dry-run"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	want := "Detected: cabal\nWould run: [cabal build --only-dependencies]\n"
	if got := out.String(); got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func writeDetectionFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
