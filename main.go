package main

import (
	"os"

	"github.com/git-pkgs/git-pkgs/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
