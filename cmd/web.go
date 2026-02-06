package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
)

func addWebCmd(parent *cobra.Command) {
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Start a local web server to browse dependency data",
		Long: `Start a read-only HTTP server on localhost to browse dependency data.

Opens a dashboard showing stats, dependencies, package history,
vulnerabilities and notes. Ctrl-C stops the server.

Examples:
  git-pkgs web                    # start on port 8080
  git-pkgs web --port 3000        # start on port 3000
  git-pkgs web --no-browser       # don't open browser
  git-pkgs web -b feature         # browse a specific branch`,
		RunE: runWeb,
	}

	webCmd.Flags().IntP("port", "P", 8080, "Port to listen on")
	webCmd.Flags().Bool("no-browser", false, "Don't automatically open the browser")
	webCmd.Flags().StringP("branch", "b", "", "Branch to browse (default: first tracked branch)")
	parent.AddCommand(webCmd)
}

func runWeb(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")
	branchName, _ := cmd.Flags().GetString("branch")

	_, db, err := openDatabase()
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	branchInfo, err := resolveBranch(db, branchName)
	if err != nil {
		return err
	}

	templates, err := newWebTemplates()
	if err != nil {
		return fmt.Errorf("loading templates: %w", err)
	}

	srv := &webServer{
		db:        db,
		branch:    branchInfo,
		templates: templates,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", srv.handleDashboard)
	mux.HandleFunc("GET /dependencies", srv.handleDependencies)
	mux.HandleFunc("GET /package/{ecosystem}/{name...}", srv.handlePackage)
	mux.Handle("GET /static/", http.StripPrefix("/static/", webStaticHandler()))

	addr := fmt.Sprintf("localhost:%d", port)
	url := fmt.Sprintf("http://%s", addr)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Check port is available
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("port %d is already in use", port)
	}
	_ = ln.Close()

	go func() {
		<-ctx.Done()
		_ = httpServer.Close()
	}()

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Serving %s branch at %s\n", branchInfo.Name, url)
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Press Ctrl-C to stop")

	if !noBrowser {
		openBrowser(url)
	}

	err = httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "\nStopped")
		return nil
	}
	return err
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("explorer", url)
	default:
		return
	}
	_ = cmd.Start()
}
