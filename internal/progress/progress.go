package progress

import (
	"fmt"
	"io"
	"os"

	"github.com/mattn/go-isatty"
)

const clearLine = "\r\033[K"

// Reporter writes status output. On a terminal, Update overwrites a single
// status line in place; on a non-terminal, each Update is printed on its own
// line so logs remain readable. A nil *Reporter is a no-op so callers can
// pass it around without checking for quiet mode.
type Reporter struct {
	w     io.Writer
	isTTY bool
	live  bool
}

func New(w io.Writer) *Reporter {
	if w == nil {
		return nil
	}
	r := &Reporter{w: w}
	if f, ok := w.(*os.File); ok {
		r.isTTY = isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())
	}
	return r
}

// Update prints a transient status line. Subsequent Updates replace it on a
// TTY; on a non-TTY each call prints a new line.
func (r *Reporter) Update(format string, a ...any) {
	if r == nil {
		return
	}
	if r.isTTY {
		_, _ = fmt.Fprintf(r.w, clearLine+format, a...)
		r.live = true
		return
	}
	_, _ = fmt.Fprintf(r.w, format+"\n", a...)
}

// Println prints a line that should remain in the output, clearing any
// pending Update first so it is not overwritten or concatenated.
func (r *Reporter) Println(format string, a ...any) {
	if r == nil {
		return
	}
	r.Clear()
	_, _ = fmt.Fprintf(r.w, format+"\n", a...)
}

// Clear erases the current Update line on a TTY. It is a no-op otherwise.
func (r *Reporter) Clear() {
	if r == nil {
		return
	}
	if r.isTTY && r.live {
		_, _ = fmt.Fprint(r.w, clearLine)
		r.live = false
	}
}
