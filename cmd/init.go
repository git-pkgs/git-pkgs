package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/git-pkgs/git-pkgs/internal/indexer"
	"github.com/spf13/cobra"
)

func init() {
	addInitCmd(rootCmd)
}

func addInitCmd(parent *cobra.Command) {
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize git-pkgs database for this repository",
		Long: `Initialize the git-pkgs database in the current git repository.
This creates a SQLite database in .git/pkgs.sqlite3 and indexes
all dependency changes from the git history.`,
		RunE: runInit,
	}

	initCmd.Flags().BoolP("force", "f", false, "Recreate database even if it exists")
	initCmd.Flags().StringP("branch", "b", "", "Branch to analyze (default: current branch)")
	initCmd.Flags().String("since", "", "Start analysis from a specific commit")
	initCmd.Flags().Bool("no-hooks", false, "Skip installing git hooks")
	initCmd.Flags().String("cpuprofile", "", "Write CPU profile to file")
	initCmd.Flags().String("memprofile", "", "Write memory profile to file")
	initCmd.Flags().Int("batch-size", 0, "Batch size for bulk inserts (default 500)")
	initCmd.Flags().Int("snapshot-interval", 0, "Store snapshot every N commits with changes (default 50)")
	_ = initCmd.Flags().MarkHidden("batch-size")
	_ = initCmd.Flags().MarkHidden("snapshot-interval")
	parent.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	quiet, _ := cmd.Flags().GetBool("quiet")
	force, _ := cmd.Flags().GetBool("force")
	branch, _ := cmd.Flags().GetString("branch")
	since, _ := cmd.Flags().GetString("since")
	noHooks, _ := cmd.Flags().GetBool("no-hooks")
	cpuProfile, _ := cmd.Flags().GetString("cpuprofile")
	memProfile, _ := cmd.Flags().GetString("memprofile")
	batchSize, _ := cmd.Flags().GetInt("batch-size")
	snapshotInterval, _ := cmd.Flags().GetInt("snapshot-interval")

	// CPU profiling
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			return fmt.Errorf("creating CPU profile: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("starting CPU profile: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	dbPath := repo.DatabasePath()
	if database.Exists(dbPath) && !force {
		if !quiet {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Database already exists. Use --force to recreate.")
		}
		return nil
	}

	db, err := database.Create(dbPath)
	if err != nil {
		return fmt.Errorf("creating database: %w", err)
	}
	defer func() { _ = db.Close() }()

	idx := indexer.New(repo, db, indexer.Options{
		Branch:           branch,
		Since:            since,
		Output:           cmd.OutOrStdout(),
		Quiet:            quiet,
		BatchSize:        batchSize,
		SnapshotInterval: snapshotInterval,
	})

	result, err := idx.Run()
	if err != nil {
		return fmt.Errorf("indexing: %w", err)
	}

	if !quiet {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nDone! Analyzed %d commits, found %d with dependency changes (%d total changes)\n",
			result.CommitsAnalyzed, result.CommitsWithChanges, result.TotalChanges)
	}

	if !noHooks {
		if err := installHooks(repo); err != nil && !quiet {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Warning: could not install hooks: %v\n", err)
		}
	}

	// Memory profiling
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			return fmt.Errorf("creating memory profile: %w", err)
		}
		defer func() { _ = f.Close() }()
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("writing memory profile: %w", err)
		}
	}

	return nil
}
