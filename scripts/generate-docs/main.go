package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/git-pkgs/cmd"
	"github.com/spf13/cobra"
)

const (
	dirPerm  = 0755
	filePerm = 0644
)

func main() {
	dir := "docs/reference"
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		log.Fatal(err)
	}

	rootCmd := cmd.NewRootCmd()
	if err := genTree(rootCmd, dir); err != nil {
		log.Fatal(err)
	}
}

func genTree(cmd *cobra.Command, dir string) error {
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := genTree(c, dir); err != nil {
			return err
		}
	}

	basename := strings.ReplaceAll(cmd.CommandPath(), " ", "_") + ".md"
	filename := filepath.Join(dir, basename)

	name := strings.TrimSuffix(basename, ".md")
	title := strings.ReplaceAll(name, "_", " ")
	weight := 10
	if name == "git-pkgs" {
		weight = 1
	}

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "---\ntitle: \"%s\"\ndescription: \"%s\"\nweight: %d\n---\n", title, cmd.Short, weight)
	if err := genMarkdown(cmd, buf); err != nil {
		return err
	}

	return os.WriteFile(filename, buf.Bytes(), filePerm)
}

func genMarkdown(cmd *cobra.Command, buf *bytes.Buffer) error {
	cmd.InitDefaultHelpCmd()
	cmd.InitDefaultHelpFlag()

	buf.WriteString("\n" + cmd.Short + "\n")

	if len(cmd.Long) > 0 {
		buf.WriteString("\n" + cmd.Long + "\n")
	}

	if cmd.Runnable() {
		fmt.Fprintf(buf, "\n```\n%s\n```\n", cmd.UseLine())
	}

	if len(cmd.Example) > 0 {
		buf.WriteString("\n### Examples\n\n")
		fmt.Fprintf(buf, "```\n%s\n```\n", cmd.Example)
	}

	flags := cmd.NonInheritedFlags()
	flags.SetOutput(buf)
	if flags.HasAvailableFlags() {
		buf.WriteString("\n### Options\n\n```\n")
		flags.PrintDefaults()
		buf.WriteString("```\n")
	}

	parentFlags := cmd.InheritedFlags()
	parentFlags.SetOutput(buf)
	if parentFlags.HasAvailableFlags() {
		buf.WriteString("\n### Options inherited from parent commands\n\n```\n")
		parentFlags.PrintDefaults()
		buf.WriteString("```\n")
	}

	return nil
}
