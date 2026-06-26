package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func addNotesCmd(parent *cobra.Command) {
	notesCmd := &cobra.Command{
		Use:   "notes",
		Short: "Manage notes on packages",
		Long: `Attach arbitrary metadata and messages to packages identified by PURL.

Notes are keyed on (purl, namespace) pairs. A namespace lets you categorize
notes (e.g. "security", "audit", "review"). The default namespace is empty.`,
	}

	addCmd := &cobra.Command{
		Use:   "add <purl>",
		Short: "Add a note to a package",
		Long:  `Create a new note for a package. Errors if a note already exists for the purl+namespace unless --force is used.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runNotesAdd,
	}
	addCmd.Flags().StringP("message", "m", "", "Note message")
	addCmd.Flags().String("namespace", "", "Note namespace for categorization")
	addCmd.Flags().String("origin", "git-pkgs", "Tool or system that created this note")
	addCmd.Flags().StringArray("set", nil, "Set metadata key=value pair")
	addCmd.Flags().Bool("force", false, "Overwrite existing note")

	appendCmd := &cobra.Command{
		Use:   "append <purl>",
		Short: "Append to an existing note",
		Long:  `Append message text and merge metadata into an existing note. Creates a new note if none exists.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runNotesAppend,
	}
	appendCmd.Flags().StringP("message", "m", "", "Message to append")
	appendCmd.Flags().String("namespace", "", "Note namespace for categorization")
	appendCmd.Flags().String("origin", "git-pkgs", "Tool or system that created this note")
	appendCmd.Flags().StringArray("set", nil, "Set metadata key=value pair")

	importCmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import notes from a YAML or JSON file",
		Long:  `Import notes from a YAML or JSON file. Imported notes are upserted by purl+namespace.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runNotesImport,
	}
	importCmd.Flags().String("namespace", "", "Default namespace for imported notes")
	importCmd.Flags().String("origin", "git-pkgs", "Tool or system that created imported notes")

	showCmd := &cobra.Command{
		Use:   "show <purl>",
		Short: "Show a note for a package",
		Long:  `Display the note attached to a package.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runNotesShow,
	}
	showCmd.Flags().String("namespace", "", "Note namespace to show")
	showCmd.Flags().StringP("format", "f", "text", "Output format: text, json")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all notes",
		Long:  `List all notes, optionally filtered by namespace or purl substring.`,
		RunE:  runNotesList,
	}
	listCmd.Flags().String("namespace", "", "Filter by namespace")
	listCmd.Flags().String("purl-filter", "", "Filter by purl substring")
	listCmd.Flags().StringP("format", "f", "text", "Output format: text, json")

	removeCmd := &cobra.Command{
		Use:   "remove <purl>",
		Short: "Remove a note",
		Long:  `Delete the note for a package.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runNotesRemove,
	}
	removeCmd.Flags().String("namespace", "", "Note namespace to remove")

	namespacesCmd := &cobra.Command{
		Use:   "namespaces",
		Short: "List note namespaces",
		Long:  `Show all namespaces in use with the number of notes in each.`,
		RunE:  runNotesNamespaces,
	}
	namespacesCmd.Flags().String("purl-filter", "", "Filter by purl substring")
	namespacesCmd.Flags().StringP("format", "f", "text", "Output format: text, json")

	notesCmd.AddCommand(addCmd, appendCmd, importCmd, showCmd, listCmd, removeCmd, namespacesCmd)
	parent.AddCommand(notesCmd)
}

func runNotesAdd(cmd *cobra.Command, args []string) error {
	purl := args[0]
	message, _ := cmd.Flags().GetString("message")
	namespace, _ := cmd.Flags().GetString("namespace")
	origin, _ := cmd.Flags().GetString("origin")
	setPairs, _ := cmd.Flags().GetStringArray("set")
	force, _ := cmd.Flags().GetBool("force")

	metadata, err := parseMetadata(setPairs)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	existing, err := db.GetNote(purl, namespace)
	if err != nil {
		return fmt.Errorf("checking existing note: %w", err)
	}

	if existing != nil && !force {
		return fmt.Errorf("note already exists for %s (namespace %q). Use --force to overwrite", purl, namespace)
	}

	if existing != nil && force {
		err = db.UpdateNote(database.Note{
			PURL:      purl,
			Namespace: namespace,
			Origin:    origin,
			Message:   message,
			Metadata:  metadata,
		})
	} else {
		err = db.InsertNote(database.Note{
			PURL:      purl,
			Namespace: namespace,
			Origin:    origin,
			Message:   message,
			Metadata:  metadata,
		})
	}
	if err != nil {
		return fmt.Errorf("saving note: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added note for %s\n", purl)
	return nil
}

func runNotesAppend(cmd *cobra.Command, args []string) error {
	purl := args[0]
	message, _ := cmd.Flags().GetString("message")
	namespace, _ := cmd.Flags().GetString("namespace")
	origin, _ := cmd.Flags().GetString("origin")
	setPairs, _ := cmd.Flags().GetStringArray("set")

	metadata, err := parseMetadata(setPairs)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if err := db.AppendNote(purl, namespace, origin, message, metadata); err != nil {
		return fmt.Errorf("appending note: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Appended to note for %s\n", purl)
	return nil
}

type noteImportEntry struct {
	PURL      string            `json:"purl" yaml:"purl"`
	Namespace string            `json:"namespace" yaml:"namespace"`
	Origin    string            `json:"origin" yaml:"origin"`
	Message   string            `json:"message" yaml:"message"`
	Metadata  map[string]string `json:"metadata" yaml:"metadata"`
}

func runNotesImport(cmd *cobra.Command, args []string) error {
	path := args[0]
	namespace, _ := cmd.Flags().GetString("namespace")
	origin, _ := cmd.Flags().GetString("origin")

	notes, err := loadNotesImportFile(path, namespace, origin)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	for _, note := range notes {
		if err := db.InsertNote(note); err != nil {
			return fmt.Errorf("importing note for %s: %w", note.PURL, err)
		}
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Imported %d notes from %s\n", len(notes), path)
	return nil
}

func loadNotesImportFile(path, defaultNamespace, defaultOrigin string) ([]database.Note, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading notes file: %w", err)
	}

	var entries []noteImportEntry
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing notes file: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("notes file contains no notes")
	}

	notes := make([]database.Note, 0, len(entries))
	for i, entry := range entries {
		if strings.TrimSpace(entry.PURL) == "" {
			return nil, fmt.Errorf("note %d missing purl", i+1)
		}

		note := database.Note{
			PURL:      strings.TrimSpace(entry.PURL),
			Namespace: entry.Namespace,
			Origin:    entry.Origin,
			Message:   entry.Message,
			Metadata:  entry.Metadata,
		}
		if note.Namespace == "" {
			note.Namespace = defaultNamespace
		}
		if note.Origin == "" {
			note.Origin = defaultOrigin
		}
		notes = append(notes, note)
	}

	return notes, nil
}

func runNotesShow(cmd *cobra.Command, args []string) error {
	purl := args[0]
	namespace, _ := cmd.Flags().GetString("namespace")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	note, err := db.GetNote(purl, namespace)
	if err != nil {
		return fmt.Errorf("getting note: %w", err)
	}
	if note == nil {
		return fmt.Errorf("no note found for %s (namespace %q)", purl, namespace)
	}

	switch format {
	case formatJSON:
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(note)
	default:
		outputNoteText(cmd, note)
		return nil
	}
}

func runNotesList(cmd *cobra.Command, args []string) error {
	namespace, _ := cmd.Flags().GetString("namespace")
	purlFilter, _ := cmd.Flags().GetString("purl-filter")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	notes, err := db.ListNotes(namespace, purlFilter)
	if err != nil {
		return fmt.Errorf("listing notes: %w", err)
	}

	switch format {
	case formatJSON:
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(notes))
	default:
		if len(notes) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No notes found.")
			return nil
		}
		for _, n := range notes {
			line := n.PURL
			if n.Namespace != "" {
				line += " [" + n.Namespace + "]"
			}
			if n.Origin != "" && n.Origin != "git-pkgs" {
				line += " (origin: " + n.Origin + ")"
			}
			if n.Message != "" {
				first := strings.SplitN(n.Message, "\n", 2)[0]
				if len(first) > subjectTruncLen {
					first = first[:subjectTruncLen-3] + "..."
				}
				line += " - " + first
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		return nil
	}
}

func runNotesRemove(cmd *cobra.Command, args []string) error {
	purl := args[0]
	namespace, _ := cmd.Flags().GetString("namespace")

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if err := db.DeleteNote(purl, namespace); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed note for %s\n", purl)
	return nil
}

func runNotesNamespaces(cmd *cobra.Command, args []string) error {
	purlFilter, _ := cmd.Flags().GetString("purl-filter")
	format, err := getFormatFlag(cmd, formatText, formatJSON)
	if err != nil {
		return err
	}

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	namespaces, err := db.ListNoteNamespaces(purlFilter)
	if err != nil {
		return fmt.Errorf("listing namespaces: %w", err)
	}

	switch format {
	case formatJSON:
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(nonNilSlice(namespaces))
	default:
		if len(namespaces) == 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No notes found.")
			return nil
		}
		for _, ns := range namespaces {
			name := ns.Namespace
			if name == "" {
				name = "(default)"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-20s %d notes\n", name, ns.Count)
		}
		return nil
	}
}

func outputNoteText(cmd *cobra.Command, n *database.Note) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "PURL: %s\n", n.PURL)
	if n.Namespace != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Namespace: %s\n", n.Namespace)
	}
	if n.Origin != "" && n.Origin != "git-pkgs" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Origin: %s\n", n.Origin)
	}
	if n.Message != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", n.Message)
	}
	if len(n.Metadata) > 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nMetadata:")
		for k, v := range n.Metadata {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", k, v)
		}
	}
}

func parseMetadata(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		idx := strings.IndexByte(pair, '=')
		if idx < 1 {
			return nil, fmt.Errorf("invalid metadata format %q, expected key=value", pair)
		}
		m[pair[:idx]] = pair[idx+1:]
	}
	return m, nil
}
