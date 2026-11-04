package cmd_test

import (
	"encoding/json"
	"testing"
)

func TestHistorySwiftPURLMatchesNativeIdentity(t *testing.T) {
	dir := createTestRepo(t)
	addFileAndCommit(t, dir, "Package.resolved", `{"version":2,"pins":[
{"identity":"apple.swift-log","kind":"registry","location":"apple.swift-log","state":{"version":"1.2.3"}},
{"identity":"swift-nio","kind":"remoteSourceControl","location":"https://github.com/apple/swift-nio.git","state":{"version":"2.0.0"}}
]}`, "Add Swift dependencies")
	t.Cleanup(chdir(t, dir))
	run := func(args ...string) string {
		t.Helper()
		stdout, stderr, err := runCmd(t, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr)
		}
		return stdout
	}
	run("init", "--no-hooks")
	for _, tc := range []struct{ name, purl string }{
		{"apple.swift-log", "pkg:swift/apple/swift-log@1.2.3"},
		{"github.com/apple/swift-nio", "pkg:swift/github.com/apple/swift-nio@2.0.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain := run("history", tc.name, "--ecosystem", "swift", "--format", "json")
			var entries []any
			if err := json.Unmarshal([]byte(plain), &entries); err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("plain-name control: %s", plain)
			}
			byPURL := run("history", tc.purl, "--format", "json")
			if byPURL != plain {
				t.Fatalf("plain name finds history, PURL differs:\nplain: %s\nPURL: %s", plain, byPURL)
			}
		})
	}
}
