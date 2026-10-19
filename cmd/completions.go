package cmd

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

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

  # Add this to ~/.zshrc after compinit to complete both git-pkgs and git pkgs:
  $ source <(git pkgs completion zsh)

  # With Zsh's bundled Git completion, you can instead install an autoload file:
  $ git pkgs completion zsh > "${fpath[1]}/_git-pkgs"
  # Restart the shell after installing it. Git's own Zsh completion requires
  # the source command above so its _git_pkgs hook is defined at startup.

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
			out := cmd.OutOrStdout()
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(out, true)
			case "zsh":
				return generateZshCompletion(cmd.Root(), out)
			case "fish":
				return cmd.Root().GenFishCompletion(out, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(out)
			default:
				return fmt.Errorf("unknown shell: %s", args[0])
			}
		},
	}

	parent.AddCommand(completionCmd)
}

func generateZshCompletion(root *cobra.Command, out io.Writer) error {
	var script bytes.Buffer
	if err := root.GenZshCompletion(&script); err != nil {
		return err
	}
	// Keep Cobra's function separate from the Git adapters and their autoload entrypoint.
	completion := strings.ReplaceAll(script.String(), "_git-pkgs", "_git-pkgs_cobra")
	_, err := io.WriteString(out, completion+zshGitCompletion)
	return err
}

const zshGitCompletion = `
_git-pkgs() {
    local -a words=("${words[@]}")
    if [[ ${words[1]} == pkgs ]]; then
        words[1]=git-pkgs
    fi
    _git-pkgs_cobra "$@"
}

_git_pkgs() {
    emulate -L zsh
    setopt $_comp_options
    local -a words=("${words[@]:$__git_cmd_idx}")
    local CURRENT=$((cword - __git_cmd_idx + 1))
    _git-pkgs "$@"
    _ret=0
}

compdef _git-pkgs git-pkgs

if [[ $funcstack[1] == _git-pkgs ]]; then
    _git-pkgs "$@"
fi
`
