package cmd

import (
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "unknown"
var commit = "unknown"
var date = "unknown"
var versionStr string

func init() {
	if version == "unknown" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				version = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					commit = s.Value
				case "vcs.time":
					date = s.Value
				}
			}
		}
	}
	versionStr = version
	if commit != "unknown" {
		versionStr += "\n          commit " + commit
	}
	if date != "unknown" {
		versionStr += "\n            date " + date
	}
}

const shortDesc = "Track package dependencies across git history"
const longDesc = `git-pkgs indexes package dependencies from manifest files across your git history,
enabling you to query what packages were used, when they changed, and identify
potential security vulnerabilities.`

func Execute() error {
	return NewRootCmd().Execute()
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:              "git-pkgs",
		Version:          versionStr,
		Short:            shortDesc,
		Long:             longDesc,
		SilenceUsage:      true,
		PersistentPreRun:  preRun,
		PersistentPostRun: postRun,
	}
	addPersistentFlags(cmd)

	// Add all subcommands
	addInitCmd(cmd)
	addReindexCmd(cmd)
	addUpgradeCmd(cmd)
	addListCmd(cmd)
	addShowCmd(cmd)
	addDiffCmd(cmd)
	addLogCmd(cmd)
	addHistoryCmd(cmd)
	addBlameCmd(cmd)
	addWhyCmd(cmd)
	addWhereCmd(cmd)
	addSearchCmd(cmd)
	addTreeCmd(cmd)
	addStatsCmd(cmd)
	addStaleCmd(cmd)
	addBranchCmd(cmd)
	addOutdatedCmd(cmd)
	addLicensesCmd(cmd)
	addIntegrityCmd(cmd)
	addSBOMCmd(cmd)
	addVulnsCmd(cmd)
	addInfoCmd(cmd)
	addHooksCmd(cmd)
	addCompletionsCmd(cmd)
	addSchemaCmd(cmd)
	addDiffDriverCmd(cmd)
	addDiffFileCmd(cmd)
	addBisectCmd(cmd)
	addEcosystemsCmd(cmd)

	// Package manager commands
	addInstallCmd(cmd)
	addAddCmd(cmd)
	addRemoveCmd(cmd)
	addUpdateCmd(cmd)
	addBrowseCmd(cmd)

	return cmd
}

func preRun(cmd *cobra.Command, args []string) {
	SetupOutput(cmd)
}

func postRun(cmd *cobra.Command, args []string) {
	CleanupOutput()
}

func addPersistentFlags(cmd *cobra.Command) {
	flags := cmd.PersistentFlags()
	flags.BoolP("quiet", "q", false, "Suppress non-essential output")
	flags.BoolP("pager", "p", false, "Use pager for output")
	flags.String("color", "auto", "When to colorize output: auto, always, never")
	flags.Bool("include-submodules", false, "Include git submodules when scanning for manifests")
}
