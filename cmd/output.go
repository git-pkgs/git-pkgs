package cmd

import (
	"os"
	"os/exec"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// NoColor disables color output when true
	NoColor bool
	// UsePager enables pager for long output
	UsePager bool
)

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// IsColorEnabled returns true if color output should be used
func IsColorEnabled() bool {
	if NoColor {
		return false
	}

	// Check NO_COLOR environment variable (standard)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Check TERM for dumb terminals
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	// Check if stdout is a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return false
	}

	return true
}

// Colorize wraps text with color codes if color is enabled
func Colorize(text, color string) string {
	if !IsColorEnabled() {
		return text
	}
	return color + text + colorReset
}

// Red returns text in red
func Red(text string) string {
	return Colorize(text, colorRed)
}

// Green returns text in green
func Green(text string) string {
	return Colorize(text, colorGreen)
}

// Yellow returns text in yellow
func Yellow(text string) string {
	return Colorize(text, colorYellow)
}

// Blue returns text in blue
func Blue(text string) string {
	return Colorize(text, colorBlue)
}

// Cyan returns text in cyan
func Cyan(text string) string {
	return Colorize(text, colorCyan)
}

// Bold returns text in bold
func Bold(text string) string {
	return Colorize(text, colorBold)
}

// Dim returns text in dim/faded style
func Dim(text string) string {
	return Colorize(text, colorDim)
}

// GetPager returns the pager command to use
func GetPager() string {
	if pager := os.Getenv("GIT_PKGS_PAGER"); pager != "" {
		return pager
	}
	if pager := os.Getenv("PAGER"); pager != "" {
		return pager
	}
	// Default pagers
	if runtime.GOOS == "windows" {
		return "more"
	}
	if _, err := exec.LookPath("less"); err == nil {
		return "less -R"
	}
	return ""
}

// SetupPager configures output to go through a pager if available
func SetupPager(cmd *cobra.Command) func() {
	if !UsePager {
		return func() {}
	}

	pagerCmd := GetPager()
	if pagerCmd == "" {
		return func() {}
	}

	// Check if stdout is a terminal
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode() & os.ModeCharDevice) == 0 {
		return func() {}
	}

	// Create pipe to pager
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}

	oldStdout := os.Stdout
	os.Stdout = w

	// Start pager process
	var pager *exec.Cmd
	if runtime.GOOS == "windows" {
		pager = exec.Command("cmd", "/c", pagerCmd)
	} else {
		pager = exec.Command("sh", "-c", pagerCmd)
	}
	pager.Stdin = r
	pager.Stdout = oldStdout
	pager.Stderr = os.Stderr

	if err := pager.Start(); err != nil {
		os.Stdout = oldStdout
		return func() {}
	}

	return func() {
		_ = w.Close()
		_ = pager.Wait()
		os.Stdout = oldStdout
	}
}
