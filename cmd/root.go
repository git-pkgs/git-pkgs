package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "git-pkgs",
	Short: "Track package dependencies across git history",
	Long: `git-pkgs indexes package dependencies from manifest files across your git history,
enabling you to query what packages were used, when they changed, and identify
potential security vulnerabilities.`,
	SilenceUsage: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Update global flags
		NoColor, _ = cmd.Flags().GetBool("no-color")
		UsePager, _ = cmd.Flags().GetBool("pager")
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git-pkgs",
		Short: "Track package dependencies across git history",
		Long: `git-pkgs indexes package dependencies from manifest files across your git history,
enabling you to query what packages were used, when they changed, and identify
potential security vulnerabilities.`,
		SilenceUsage: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			NoColor, _ = c.Flags().GetBool("no-color")
			UsePager, _ = c.Flags().GetBool("pager")
		},
	}
	cmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress non-essential output")
	cmd.PersistentFlags().Bool("no-color", false, "Disable colored output")
	cmd.PersistentFlags().BoolP("pager", "p", false, "Use pager for output")
	addInitCmd(cmd)
	return cmd
}

func init() {
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress non-essential output")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolP("pager", "p", false, "Use pager for output")
}
