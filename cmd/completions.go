package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	addCompletionsCmd(rootCmd)
}

func addCompletionsCmd(parent *cobra.Command) {
	completionCmd := &cobra.Command{
		Use:   "completion [shell]",
		Short: "Generate shell completions",
		Long: `Generate shell completion scripts for git-pkgs.

To load completions:

Bash:
  $ source <(git pkgs completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ git pkgs completion bash > /etc/bash_completion.d/git-pkgs
  # macOS:
  $ git pkgs completion bash > $(brew --prefix)/etc/bash_completion.d/git-pkgs

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ git pkgs completion zsh > "${fpath[1]}/_git-pkgs"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ git pkgs completion fish | source
  # To load completions for each session, execute once:
  $ git pkgs completion fish > ~/.config/fish/completions/git-pkgs.fish

PowerShell:
  PS> git pkgs completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> git pkgs completion powershell > git-pkgs.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}

	parent.AddCommand(completionCmd)
}
