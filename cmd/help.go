package cmd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type helpCommandDoc struct {
	Name            string           `json:"name"`
	Use             string           `json:"use"`
	CommandPath     string           `json:"command_path"`
	Short           string           `json:"short,omitempty"`
	Long            string           `json:"long,omitempty"`
	Example         string           `json:"example,omitempty"`
	Aliases         []string         `json:"aliases,omitempty"`
	GroupID         string           `json:"group_id,omitempty"`
	Runnable        bool             `json:"runnable"`
	Hidden          bool             `json:"hidden,omitempty"`
	Deprecated      string           `json:"deprecated,omitempty"`
	Flags           []helpFlagDoc    `json:"flags,omitempty"`
	PersistentFlags []helpFlagDoc    `json:"persistent_flags,omitempty"`
	InheritedFlags  []helpFlagDoc    `json:"inherited_flags,omitempty"`
	Subcommands     []helpCommandDoc `json:"subcommands,omitempty"`
}

type helpFlagDoc struct {
	Name        string   `json:"name"`
	Shorthand   string   `json:"shorthand,omitempty"`
	Type        string   `json:"type"`
	Default     string   `json:"default"`
	Usage       string   `json:"usage,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Hidden      bool     `json:"hidden,omitempty"`
	Deprecated  string   `json:"deprecated,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
}

func addJSONHelpCommand(root *cobra.Command) {
	helpCmd := &cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		Long:  "Help provides help for any command in the application.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := getFormatFlag(cmd, formatText, formatJSON)
			if err != nil {
				return err
			}
			target, err := helpTargetCommand(root, args)
			if err != nil {
				return err
			}
			if format == formatJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				return encoder.Encode(buildHelpCommandDoc(target))
			}
			target.SetOut(cmd.OutOrStdout())
			target.SetErr(cmd.ErrOrStderr())
			return target.Help()
		},
	}
	helpCmd.Flags().StringP("format", "f", "text", "Output format: text, json")
	root.SetHelpCommand(helpCmd)
}

func helpTargetCommand(root *cobra.Command, args []string) (*cobra.Command, error) {
	if len(args) == 0 {
		return root, nil
	}
	target, remaining, err := root.Find(args)
	if err != nil {
		return nil, err
	}
	if len(remaining) > 0 {
		return nil, fmt.Errorf("unknown help topic %q", strings.Join(remaining, " "))
	}
	return target, nil
}

func buildHelpCommandDoc(cmd *cobra.Command) helpCommandDoc {
	doc := helpCommandDoc{
		Name:        cmd.Name(),
		Use:         cmd.UseLine(),
		CommandPath: cmd.CommandPath(),
		Short:       cmd.Short,
		Long:        cmd.Long,
		Example:     cmd.Example,
		Aliases:     append([]string(nil), cmd.Aliases...),
		GroupID:     cmd.GroupID,
		Runnable:    cmd.Runnable(),
		Hidden:      cmd.Hidden,
		Deprecated:  cmd.Deprecated,
	}

	doc.Flags = collectHelpFlags(cmd.LocalNonPersistentFlags())
	doc.PersistentFlags = collectHelpFlags(cmd.PersistentFlags())
	doc.InheritedFlags = collectHelpFlags(cmd.InheritedFlags())

	for _, child := range cmd.Commands() {
		if child.Hidden {
			continue
		}
		doc.Subcommands = append(doc.Subcommands, buildHelpCommandDoc(child))
	}

	return doc
}

func collectHelpFlags(flags *pflag.FlagSet) []helpFlagDoc {
	if flags == nil {
		return nil
	}
	var docs []helpFlagDoc
	flags.VisitAll(func(flag *pflag.Flag) {
		if flag.Hidden {
			return
		}
		docs = append(docs, helpFlagDoc{
			Name:        flag.Name,
			Shorthand:   flag.Shorthand,
			Type:        flag.Value.Type(),
			Default:     flag.DefValue,
			Usage:       flag.Usage,
			Required:    isRequiredFlag(flag),
			Hidden:      flag.Hidden,
			Deprecated:  flag.Deprecated,
			Annotations: helpFlagAnnotations(flag),
		})
	})
	return docs
}

func isRequiredFlag(flag *pflag.Flag) bool {
	if flag == nil || flag.Annotations == nil {
		return false
	}
	required := flag.Annotations[cobra.BashCompOneRequiredFlag]
	return len(required) > 0 && required[0] == "true"
}

func helpFlagAnnotations(flag *pflag.Flag) []string {
	if flag == nil || len(flag.Annotations) == 0 {
		return nil
	}
	annotations := make([]string, 0, len(flag.Annotations))
	for key, values := range flag.Annotations {
		annotations = append(annotations, key+"="+strings.Join(values, ","))
	}
	sort.Strings(annotations)
	return annotations
}
