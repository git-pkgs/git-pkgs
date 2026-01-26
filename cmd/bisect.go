package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/git-pkgs/git-pkgs/internal/bisect"
	"github.com/git-pkgs/git-pkgs/internal/database"
	"github.com/git-pkgs/git-pkgs/internal/git"
	"github.com/spf13/cobra"
)

func addBisectCmd(parent *cobra.Command) {
	bisectCmd := &cobra.Command{
		Use:   "bisect",
		Short: "Find the commit that introduced a dependency-related change",
		Long: `Binary search through commits with dependency changes to find when
a specific change was introduced. Works like git bisect but only considers
commits that modified dependencies, making it faster for dependency-related issues.

Subcommands:
  start    Begin a bisect session
  good     Mark a commit as good (before the problem)
  bad      Mark a commit as bad (has the problem)
  skip     Skip a commit that can't be tested
  run      Automate bisect with a script
  reset    End the bisect session
  log      Show the bisect log`,
	}

	// start subcommand
	startCmd := &cobra.Command{
		Use:   "start [<bad> [<good>...]]",
		Short: "Start a bisect session",
		Long: `Begin a new bisect session. Optionally specify the bad (newer) and good (older)
commits on the command line.

Filtering options narrow which commits are considered:
  --ecosystem  Only commits changing dependencies in this ecosystem
  --package    Only commits touching this specific package
  --manifest   Only commits changing this manifest file`,
		RunE: runBisectStart,
	}
	startCmd.Flags().StringP("ecosystem", "e", "", "Only consider commits changing this ecosystem")
	startCmd.Flags().String("package", "", "Only consider commits touching this package")
	startCmd.Flags().String("manifest", "", "Only consider commits changing this manifest")

	// good subcommand
	goodCmd := &cobra.Command{
		Use:   "good [<rev>...]",
		Short: "Mark commits as good",
		Long:  `Mark one or more commits as good (before the problem was introduced).`,
		RunE:  runBisectGood,
	}

	// bad subcommand
	badCmd := &cobra.Command{
		Use:   "bad [<rev>]",
		Short: "Mark a commit as bad",
		Long:  `Mark a commit as bad (the problem is present).`,
		RunE:  runBisectBad,
	}

	// skip subcommand
	skipCmd := &cobra.Command{
		Use:   "skip [<rev>...]",
		Short: "Skip commits that can't be tested",
		Long:  `Skip one or more commits that cannot be tested (e.g., won't build).`,
		RunE:  runBisectSkip,
	}

	// run subcommand
	runCmd := &cobra.Command{
		Use:   "run <cmd> [<args>...]",
		Short: "Automate bisect with a command",
		Long: `Automatically run a command at each bisect step. The command's exit code
determines whether the commit is good or bad:
  Exit 0     = good
  Exit 1-124 = bad
  Exit 125   = skip (can't test this commit)
  Exit 126+  = abort bisect`,
		RunE:                       runBisectRun,
		DisableFlagParsing:         true,
		SuggestionsMinimumDistance: 2,
	}

	// reset subcommand
	resetCmd := &cobra.Command{
		Use:   "reset",
		Short: "End the bisect session",
		Long:  `End the current bisect session and return to the original HEAD.`,
		RunE:  runBisectReset,
	}

	// log subcommand
	logCmd := &cobra.Command{
		Use:   "log",
		Short: "Show the bisect log",
		Long:  `Show the log of bisect operations performed in the current session.`,
		RunE:  runBisectLog,
	}

	bisectCmd.AddCommand(startCmd, goodCmd, badCmd, skipCmd, runCmd, resetCmd, logCmd)
	parent.AddCommand(bisectCmd)
}

func runBisectStart(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())

	if mgr.InProgress() {
		return fmt.Errorf("bisect already in progress. Use 'git pkgs bisect reset' to abort")
	}

	dbPath := repo.DatabasePath()
	if !database.Exists(dbPath) {
		return fmt.Errorf("database not found. Run 'git pkgs init' first")
	}

	// Check for clean working directory
	if !isWorkingDirectoryClean() {
		return fmt.Errorf("working directory is not clean. Please commit or stash your changes")
	}

	// Get current HEAD
	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("getting HEAD: %w", err)
	}

	originalRef := ""
	if head.Name().IsBranch() {
		originalRef = head.Name().Short()
	}

	state := &bisect.State{
		OriginalHead: head.Hash().String(),
		OriginalRef:  originalRef,
	}

	// Get filter options
	state.Ecosystem, _ = cmd.Flags().GetString("ecosystem")
	state.Package, _ = cmd.Flags().GetString("package")
	state.Manifest, _ = cmd.Flags().GetString("manifest")

	// Parse positional arguments: [bad [good...]]
	if len(args) > 0 {
		badSHA, err := resolveRev(repo, args[0])
		if err != nil {
			return fmt.Errorf("resolving bad revision %q: %w", args[0], err)
		}
		state.BadRev = badSHA
	}
	if len(args) > 1 {
		for _, arg := range args[1:] {
			goodSHA, err := resolveRev(repo, arg)
			if err != nil {
				return fmt.Errorf("resolving good revision %q: %w", arg, err)
			}
			state.GoodRevs = append(state.GoodRevs, goodSHA)
		}
	}

	if err := mgr.Save(state); err != nil {
		return fmt.Errorf("saving bisect state: %w", err)
	}

	_ = mgr.AppendLog("# git pkgs bisect start")

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Bisect session started.")

	if state.Ecosystem != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Filtering by ecosystem: %s\n", state.Ecosystem)
	}
	if state.Package != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Filtering by package: %s\n", state.Package)
	}
	if state.Manifest != "" {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Filtering by manifest: %s\n", state.Manifest)
	}

	// If we have both good and bad, start bisecting
	if state.BadRev != "" && len(state.GoodRevs) > 0 {
		return doBisectStep(cmd, repo, mgr, state)
	}

	if state.BadRev == "" {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Mark a bad commit with 'git pkgs bisect bad <rev>'")
	} else {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Bad commit: %s\n", state.BadRev[:7])
	}
	if len(state.GoodRevs) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Mark a good commit with 'git pkgs bisect good <rev>'")
	}

	return nil
}

func runBisectGood(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())
	state, err := mgr.Load()
	if err != nil {
		return err
	}

	// If no args, use current HEAD
	revs := args
	if len(revs) == 0 {
		head, err := repo.Head()
		if err != nil {
			return fmt.Errorf("getting HEAD: %w", err)
		}
		revs = []string{head.Hash().String()}
	}

	for _, rev := range revs {
		sha, err := resolveRev(repo, rev)
		if err != nil {
			return fmt.Errorf("resolving revision %q: %w", rev, err)
		}
		state.GoodRevs = append(state.GoodRevs, sha)
		_ = mgr.AppendLog(fmt.Sprintf("git pkgs bisect good %s", sha[:7]))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Marked %s as good\n", sha[:7])
	}

	if err := mgr.Save(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	if state.BadRev != "" && len(state.GoodRevs) > 0 {
		return doBisectStep(cmd, repo, mgr, state)
	}

	if state.BadRev == "" {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Mark a bad commit with 'git pkgs bisect bad <rev>'")
	}

	return nil
}

func runBisectBad(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())
	state, err := mgr.Load()
	if err != nil {
		return err
	}

	var sha string
	if len(args) > 0 {
		sha, err = resolveRev(repo, args[0])
		if err != nil {
			return fmt.Errorf("resolving revision %q: %w", args[0], err)
		}
	} else {
		head, err := repo.Head()
		if err != nil {
			return fmt.Errorf("getting HEAD: %w", err)
		}
		sha = head.Hash().String()
	}

	state.BadRev = sha
	_ = mgr.AppendLog(fmt.Sprintf("git pkgs bisect bad %s", sha[:7]))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Marked %s as bad\n", sha[:7])

	if err := mgr.Save(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	if len(state.GoodRevs) > 0 {
		return doBisectStep(cmd, repo, mgr, state)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Mark a good commit with 'git pkgs bisect good <rev>'")
	return nil
}

func runBisectSkip(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())
	state, err := mgr.Load()
	if err != nil {
		return err
	}

	revs := args
	if len(revs) == 0 {
		head, err := repo.Head()
		if err != nil {
			return fmt.Errorf("getting HEAD: %w", err)
		}
		revs = []string{head.Hash().String()}
	}

	for _, rev := range revs {
		sha, err := resolveRev(repo, rev)
		if err != nil {
			return fmt.Errorf("resolving revision %q: %w", rev, err)
		}
		state.SkippedRevs = append(state.SkippedRevs, sha)
		_ = mgr.AppendLog(fmt.Sprintf("git pkgs bisect skip %s", sha[:7]))
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Skipped %s\n", sha[:7])
	}

	if err := mgr.Save(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	if state.BadRev != "" && len(state.GoodRevs) > 0 {
		return doBisectStep(cmd, repo, mgr, state)
	}

	return nil
}

func runBisectRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: git pkgs bisect run <cmd> [<args>...]")
	}

	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())
	state, err := mgr.Load()
	if err != nil {
		return err
	}

	if state.BadRev == "" || len(state.GoodRevs) == 0 {
		return fmt.Errorf("need both bad and good commits before running")
	}

	_ = mgr.AppendLog(fmt.Sprintf("# git pkgs bisect run %s", strings.Join(args, " ")))

	for {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "running '%s'\n", strings.Join(args, "' '"))

		// Run the command
		c := exec.Command(args[0], args[1:]...)
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = cmd.ErrOrStderr()
		c.Stdin = os.Stdin

		err := c.Run()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				return fmt.Errorf("running command: %w", err)
			}
		}

		// Get current HEAD for logging
		head, _ := repo.Head()
		currentSHA := head.Hash().String()[:7]

		var result string
		switch {
		case exitCode == 0:
			result = "good"
			state.GoodRevs = append(state.GoodRevs, head.Hash().String())
		case exitCode >= 1 && exitCode <= 124:
			result = "bad"
			state.BadRev = head.Hash().String()
		case exitCode == 125:
			result = "skip"
			state.SkippedRevs = append(state.SkippedRevs, head.Hash().String())
		default:
			return fmt.Errorf("bisect run aborted (exit code %d)", exitCode)
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s\n", currentSHA, result)
		_ = mgr.AppendLog(fmt.Sprintf("git pkgs bisect %s %s # %s", result, currentSHA, getCommitSubject(repo, currentSHA)))

		if err := mgr.Save(state); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		// Check if we found the culprit
		done, culprit, err := checkBisectComplete(repo, mgr, state)
		if err != nil {
			return err
		}
		if done {
			return printCulprit(cmd, repo, culprit)
		}

		// Continue to next step
		if err := doBisectStep(cmd, repo, mgr, state); err != nil {
			if strings.Contains(err.Error(), "first bad commit") {
				return nil // Already printed
			}
			return err
		}
	}
}

func runBisectReset(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())

	if !mgr.InProgress() {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No bisect in progress.")
		return nil
	}

	state, err := mgr.Load()
	if err != nil {
		// State is corrupted, just clean up
		_ = mgr.Clean()
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Bisect session cleaned up.")
		return nil
	}

	// Restore original HEAD
	if state.OriginalRef != "" {
		if err := gitCheckout(state.OriginalRef); err != nil {
			return fmt.Errorf("restoring original branch: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Switched back to branch '%s'\n", state.OriginalRef)
	} else if state.OriginalHead != "" {
		if err := gitCheckout(state.OriginalHead); err != nil {
			return fmt.Errorf("restoring original HEAD: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Restored to %s\n", state.OriginalHead[:7])
	}

	if err := mgr.Clean(); err != nil {
		return fmt.Errorf("cleaning up bisect state: %w", err)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Bisect session ended.")
	return nil
}

func runBisectLog(cmd *cobra.Command, args []string) error {
	repo, err := git.OpenRepository(".")
	if err != nil {
		return fmt.Errorf("not in a git repository: %w", err)
	}

	mgr := bisect.NewManager(repo.GitDir())

	if !mgr.InProgress() {
		return fmt.Errorf("no bisect in progress")
	}

	lines, err := mgr.ReadLog()
	if err != nil {
		return fmt.Errorf("reading bisect log: %w", err)
	}

	for _, line := range lines {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), line)
	}

	return nil
}

func doBisectStep(cmd *cobra.Command, repo *git.Repository, mgr *bisect.Manager, state *bisect.State) error {
	db, err := database.Open(repo.DatabasePath())
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return fmt.Errorf("getting branch: %w", err)
	}

	// Get candidates between good and bad
	// Use the oldest good commit as the start point
	oldestGood := state.GoodRevs[0]
	for _, g := range state.GoodRevs[1:] {
		gPos, _ := db.GetCommitPosition(g, branchInfo.ID)
		oldestPos, _ := db.GetCommitPosition(oldestGood, branchInfo.ID)
		if gPos < oldestPos {
			oldestGood = g
		}
	}

	candidates, err := db.GetBisectCandidates(database.BisectOptions{
		BranchID:     branchInfo.ID,
		StartSHA:     oldestGood,
		EndSHA:       state.BadRev,
		Ecosystem:    state.Ecosystem,
		PackageName:  state.Package,
		ManifestPath: state.Manifest,
	})
	if err != nil {
		return fmt.Errorf("getting bisect candidates: %w", err)
	}

	// Filter out good, bad, and skipped commits
	var remaining []database.BisectCandidate
	for _, c := range candidates {
		if mgr.IsGood(state, c.SHA) || mgr.IsBad(state, c.SHA) || mgr.IsSkipped(state, c.SHA) {
			continue
		}
		remaining = append(remaining, c)
	}

	if len(remaining) == 0 {
		// We've found the culprit - it's the bad commit
		return printCulprit(cmd, repo, state.BadRev)
	}

	// Pick the middle candidate
	mid := len(remaining) / 2
	target := remaining[mid]

	// Checkout the target commit
	if err := gitCheckout(target.SHA); err != nil {
		return fmt.Errorf("checking out %s: %w", target.SHA[:7], err)
	}

	state.CurrentSHA = target.SHA
	if err := mgr.Save(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	// Calculate steps remaining (log2 of remaining commits)
	steps := 0
	for n := len(remaining); n > 1; n /= 2 {
		steps++
	}

	subject := target.Message
	if idx := strings.Index(subject, "\n"); idx > 0 {
		subject = subject[:idx]
	}
	if len(subject) > 60 {
		subject = subject[:57] + "..."
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Bisecting: %d dependency changes left to test (roughly %d steps)\n",
		len(remaining), steps)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s\n", Yellow(target.SHA[:7]), subject)

	return nil
}

func checkBisectComplete(repo *git.Repository, mgr *bisect.Manager, state *bisect.State) (bool, string, error) {
	db, err := database.Open(repo.DatabasePath())
	if err != nil {
		return false, "", err
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := db.GetDefaultBranch()
	if err != nil {
		return false, "", err
	}

	oldestGood := state.GoodRevs[0]
	for _, g := range state.GoodRevs[1:] {
		gPos, _ := db.GetCommitPosition(g, branchInfo.ID)
		oldestPos, _ := db.GetCommitPosition(oldestGood, branchInfo.ID)
		if gPos < oldestPos {
			oldestGood = g
		}
	}

	candidates, err := db.GetBisectCandidates(database.BisectOptions{
		BranchID:     branchInfo.ID,
		StartSHA:     oldestGood,
		EndSHA:       state.BadRev,
		Ecosystem:    state.Ecosystem,
		PackageName:  state.Package,
		ManifestPath: state.Manifest,
	})
	if err != nil {
		return false, "", err
	}

	var remaining []database.BisectCandidate
	for _, c := range candidates {
		if mgr.IsGood(state, c.SHA) || mgr.IsBad(state, c.SHA) || mgr.IsSkipped(state, c.SHA) {
			continue
		}
		remaining = append(remaining, c)
	}

	if len(remaining) == 0 {
		return true, state.BadRev, nil
	}

	return false, "", nil
}

func printCulprit(cmd *cobra.Command, repo *git.Repository, sha string) error {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s is the first bad commit\n", sha)

	// Get commit details
	hash, err := repo.ResolveRevision(sha)
	if err != nil {
		return nil
	}

	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout())
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "commit %s\n", sha)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Author: %s <%s>\n", commit.Author.Name, commit.Author.Email)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Date:   %s\n", commit.Author.When.Format("Mon Jan 2 15:04:05 2006 -0700"))
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	lines := strings.Split(strings.TrimSpace(commit.Message), "\n")
	for _, line := range lines {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", line)
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout())

	// Show dependency changes
	db, err := database.Open(repo.DatabasePath())
	if err == nil {
		defer func() { _ = db.Close() }()

		changes, err := db.GetChangesForCommit(sha)
		if err == nil && len(changes) > 0 {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Dependencies changed:")
			for _, c := range changes {
				symbol := "~"
				color := Yellow
				switch c.ChangeType {
				case "added":
					symbol = "+"
					color = Green
				case "removed":
					symbol = "-"
					color = Red
				}

				version := c.Requirement
				if c.PreviousRequirement != "" && c.ChangeType == "modified" {
					version = c.PreviousRequirement + " -> " + c.Requirement
				}

				depType := ""
				if c.DependencyType != "" && c.DependencyType != "runtime" {
					depType = fmt.Sprintf(" (%s)", c.DependencyType)
				}

				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  %s %s%s%s\n",
					color(symbol), c.Name, Dim("@"+version), Dim(depType))
			}
		}
	}

	return nil
}

func resolveRev(repo *git.Repository, rev string) (string, error) {
	hash, err := repo.ResolveRevision(rev)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func gitCheckout(ref string) error {
	cmd := exec.Command("git", "checkout", ref)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func isWorkingDirectoryClean() bool {
	cmd := exec.Command("git", "status", "--porcelain")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(output))) == 0
}

func getCommitSubject(repo *git.Repository, sha string) string {
	hash, err := repo.ResolveRevision(sha)
	if err != nil {
		return ""
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return ""
	}
	msg := commit.Message
	if idx := strings.Index(msg, "\n"); idx > 0 {
		msg = msg[:idx]
	}
	return strings.TrimSpace(msg)
}
