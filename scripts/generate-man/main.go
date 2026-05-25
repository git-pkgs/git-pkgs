package main

import (
	"log"
	"os"
	"time"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/spf13/cobra/doc"
)

const dirPerm = 0755

func main() {
	if err := os.MkdirAll("man", dirPerm); err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	header := &doc.GenManHeader{
		Title:   "GIT-PKGS",
		Section: "1",
		Date:    &now,
		Source:  "git-pkgs",
		Manual:  "Git Pkgs Manual",
	}

	rootCmd := cmd.NewRootCmd()
	if err := doc.GenManTree(rootCmd, header, "man"); err != nil {
		log.Fatal(err)
	}
}
