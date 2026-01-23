//go:build ignore

package main

import (
	"log"
	"os"
	"time"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/spf13/cobra/doc"
)

func main() {
	if err := os.MkdirAll("man", 0755); err != nil {
		log.Fatal(err)
	}

	header := &doc.GenManHeader{
		Title:   "GIT-PKGS",
		Section: "1",
		Date:    &time.Time{},
		Source:  "git-pkgs",
		Manual:  "Git Pkgs Manual",
	}

	rootCmd := cmd.NewRootCmd()
	if err := doc.GenManTree(rootCmd, header, "man"); err != nil {
		log.Fatal(err)
	}
}
