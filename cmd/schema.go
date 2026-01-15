package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func init() {
	addSchemaCmd(rootCmd)
}

func addSchemaCmd(parent *cobra.Command) {
	schemaCmd := &cobra.Command{
		Use:   "schema",
		Short: "Display database schema",
		Long:  `Show the structure of the git-pkgs database.`,
		RunE:  runSchema,
	}

	schemaCmd.Flags().StringP("format", "f", "text", "Output format: text, sql, json, markdown")
	parent.AddCommand(schemaCmd)
}

type TableSchema struct {
	Name    string         `json:"name"`
	Columns []ColumnSchema `json:"columns"`
	Indexes []string       `json:"indexes,omitempty"`
}

type ColumnSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	PK       bool   `json:"pk,omitempty"`
}

func runSchema(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	db, err := database.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	tables, err := getSchemaInfo(db)
	if err != nil {
		return fmt.Errorf("getting schema: %w", err)
	}

	switch format {
	case "json":
		return outputSchemaJSON(cmd, tables)
	case "sql":
		return outputSchemaSQL(cmd, tables)
	case "markdown":
		return outputSchemaMarkdown(cmd, tables)
	default:
		return outputSchemaText(cmd, tables)
	}
}

func getSchemaInfo(db *database.DB) ([]TableSchema, error) {
	// Get table names
	rows, err := db.Query(`
		SELECT name FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%'
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var tableNames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tableNames = append(tableNames, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var tables []TableSchema
	for _, tableName := range tableNames {
		table := TableSchema{Name: tableName}

		// Get columns
		colRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
		if err != nil {
			return nil, err
		}

		for colRows.Next() {
			var cid int
			var name, colType string
			var notNull, pk int
			var dfltValue interface{}

			if err := colRows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
				_ = colRows.Close()
				return nil, err
			}

			table.Columns = append(table.Columns, ColumnSchema{
				Name:     name,
				Type:     colType,
				Nullable: notNull == 0,
				PK:       pk > 0,
			})
		}
		_ = colRows.Close()

		// Get indexes
		idxRows, err := db.Query(`
			SELECT name FROM sqlite_master
			WHERE type='index' AND tbl_name=? AND name NOT LIKE 'sqlite_%'
		`, tableName)
		if err != nil {
			return nil, err
		}

		for idxRows.Next() {
			var name string
			if err := idxRows.Scan(&name); err != nil {
				_ = idxRows.Close()
				return nil, err
			}
			table.Indexes = append(table.Indexes, name)
		}
		_ = idxRows.Close()

		tables = append(tables, table)
	}

	return tables, nil
}

func outputSchemaJSON(cmd *cobra.Command, tables []TableSchema) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(tables)
}

func outputSchemaSQL(cmd *cobra.Command, tables []TableSchema) error {
	for _, table := range tables {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CREATE TABLE %s (\n", table.Name)

		for i, col := range table.Columns {
			line := fmt.Sprintf("  %s %s", col.Name, col.Type)
			if col.PK {
				line += " PRIMARY KEY"
			}
			if !col.Nullable {
				line += " NOT NULL"
			}
			if i < len(table.Columns)-1 {
				line += ","
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), ");")
		_, _ = fmt.Fprintln(cmd.OutOrStdout())

		for _, idx := range table.Indexes {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CREATE INDEX %s ON %s(...);\n", idx, table.Name)
		}
		if len(table.Indexes) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
	}

	return nil
}

func outputSchemaMarkdown(cmd *cobra.Command, tables []TableSchema) error {
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "# Database Schema")
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	for _, table := range tables {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "## %s\n\n", table.Name)

		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "| Column | Type | Nullable | PK |")
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "|--------|------|----------|----|")

		for _, col := range table.Columns {
			nullable := "yes"
			if !col.Nullable {
				nullable = "no"
			}
			pk := ""
			if col.PK {
				pk = "yes"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "| %s | %s | %s | %s |\n",
				col.Name, col.Type, nullable, pk)
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout())

		if len(table.Indexes) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "**Indexes:**")
			for _, idx := range table.Indexes {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "- %s\n", idx)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
		}
	}

	return nil
}

func outputSchemaText(cmd *cobra.Command, tables []TableSchema) error {
	for _, table := range tables {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", table.Name)
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", len(table.Name)))

		// Find max column name length
		maxNameLen := 0
		maxTypeLen := 0
		for _, col := range table.Columns {
			if len(col.Name) > maxNameLen {
				maxNameLen = len(col.Name)
			}
			if len(col.Type) > maxTypeLen {
				maxTypeLen = len(col.Type)
			}
		}

		for _, col := range table.Columns {
			flags := ""
			if col.PK {
				flags = "PK"
			}
			if !col.Nullable && !col.PK {
				flags = "NOT NULL"
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %-*s  %-*s  %s\n",
				maxNameLen, col.Name, maxTypeLen, col.Type, flags)
		}

		if len(table.Indexes) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout())
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  Indexes:")
			for _, idx := range table.Indexes {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    - %s\n", idx)
			}
		}

		_, _ = fmt.Fprintln(cmd.OutOrStdout())
	}

	return nil
}
