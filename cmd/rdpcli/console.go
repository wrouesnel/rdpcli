package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/wrouesnel/rdpcli/internal/console"
	"github.com/wrouesnel/rdpcli/internal/rdp"
	"github.com/wrouesnel/rdpcli/internal/screen"
	"github.com/wrouesnel/rdpcli/internal/viewer"
)

// launchLine is typed into the Run box, followed by the first calibration
// command. conhost.exe is named explicitly so the console is a classic
// console window even where Windows Terminal is the default terminal.
// PSReadLine is removed because it ignores the Unicode key events rdpcli
// types with. Calibrating from the command line means nothing is typed
// until the console is known to be on screen.
var launchLine = `conhost.exe powershell.exe -NoLogo -NoProfile -NoExit -Command Remove-Module PSReadLine;`

// runBoxMax is the longest command the Run box accepts.
const runBoxMax = 259

// promptRE matches PowerShell's default prompt line.
var promptRE = regexp.MustCompile(`^PS .*>$`)

func cmdConsole(args []string) int {
	f := newConnFlags("console", "console HOST[:PORT] -u USER [-c COMMAND] [options]")
	command := f.fs.String("c", "", "PowerShell command to run; its output is printed and its status is the exit code")
	width := f.fs.Int("output-width", 0, "format output for this many columns (default: this terminal's width, or 120)")
	tty := f.fs.Bool("t", false, "interactive: run PowerShell (or -c's command) in a pseudo console connected to this terminal; Ctrl+] detaches")
	keep := f.fs.Bool("keep", false, "leave the console window open on the remote desktop")
	cmdTimeout := f.fs.Duration("command-timeout", time.Minute, "time limit for the command to finish")
	noInteractive := f.fs.Bool("no-interactive", false, "never ask for help in the browser viewer; fail instead (for scripts)")
	listen := f.fs.String("listen", "127.0.0.1:0", "address for the browser viewer, if it is needed")
	debug := f.fs.String("debug", "", "save a screenshot of each step in this directory")
	host, ok := f.parse(args)
	if !ok {
		return 2
	}
	if strings.ContainsAny(*command, "\r\n") {
		status("-c: the command must be a single line")
		return 2
	}
	start := time.Now()
	cfg, err := f.config(host, false, start)
	if err != nil {
		status("%v", err)
		return 2
	}
	if *debug != "" {
		if err := os.MkdirAll(*debug, 0o755); err != nil {
			status("%v", err)
			return 2
		}
	}

	ctx, stop := interruptContext()
	defer stop()

	fb := screen.New()
	onEvent := func(ev rdp.Event) {
		if ev.Activated {
			fb.Resize(ev.Width, ev.Height)
		}
		if len(ev.Bitmaps) > 0 {
			fb.Draw(ev.Bitmaps)
		}
	}
	lctx, lcancel := context.WithTimeout(ctx, *f.timeout)
	h := &handoff{fb: fb, listen: *listen, disabled: *noInteractive}
	s, err := openSession(lctx, cfg, start, sessionOpts{
		onEvent:     onEvent,
		onConn:      h.setConn,
		interactive: !*noInteractive,
	})
	lcancel()
	if err != nil {
		status("%v", err)
		return 1
	}
	defer h.close()
	d := newDesktop(ctx, s, fb, onEvent, *debug)
	defer d.close()

	// Let the session finish switching to this connection before typing.
	if err := d.settle(time.Second, 10*time.Second); err != nil {
		status("%v", err)
		return 1
	}

	if s.logon == nil {
		if err := h.ask(d, "complete the logon on the remote desktop, then press Continue."); err != nil {
			status("%v", err)
			return 1
		}
	}

	var r *console.Reader
	for {
		r, err = launchConsole(d)
		if err == nil {
			break
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, rdp.ErrDisconnected) {
			status("%v", err)
			return 1
		}
		status("%v", err)
		if err := h.ask(d, fmt.Sprintf("rdpcli could not open a PowerShell console (%v). "+
			"Close anything in the way (dialogs, prompts), then press Continue to try again.", err)); err != nil {
			status("%v", err)
			return 1
		}
	}
	g := r.Grid
	status("console ready: %dx%d cells of %dx%d px", g.Cols, g.Rows, g.CellW, g.CellH)

	code := 0
	if *tty {
		st, err := runTTY(d, r, ttyCommandLine(*command), *width)
		switch {
		case errors.Is(err, errDetached):
			status("detached")
			code = 1
		case err != nil:
			status("%v", err)
			code = 1
		case st != 0:
			code = st & 0xFF
			if code == 0 {
				code = 1
			}
		}
	} else if *command != "" {
		w := *width
		if w <= 0 {
			w = terminalWidth()
		}
		out, st, err := runPaged(d, r, *command, w, *cmdTimeout)
		os.Stdout.WriteString(out)
		switch {
		case err != nil:
			status("%v", err)
			code = 1
		case st != 0:
			code = st & 0xFF
			if code == 0 {
				code = 1
			}
		}
	} else {
		scr := r.Read(d.snapshot())
		for _, l := range trimBlank(scr.Lines) {
			fmt.Println(l)
		}
	}
	if !*keep {
		closeConsole(d)
	}
	return code
}

// closeConsole exits the console: "q" stops a transfer the helper may
// still be showing (after an error), Escape clears whatever is on the
// prompt line, then exit.
func closeConsole(d *desktop) {
	if d.typeText("q") != nil || d.sleep(300*time.Millisecond) != nil {
		return
	}
	if d.chord(rdp.ScanEsc) != nil || d.sleep(100*time.Millisecond) != nil {
		return
	}
	if d.typeText("exit\n") == nil {
		d.sleep(500 * time.Millisecond)
	}
}

// launchConsole opens a maximised PowerShell console with Win+R and
// calibrates the reader on it.
func launchConsole(d *desktop) (*console.Reader, error) {
	first, second := newNonce(), newNonce()
	line := launchLine + console.CalibrationCommand(first)
	if len(line) > runBoxMax {
		return nil, fmt.Errorf("launch command is %d characters, more than the Run box takes", len(line))
	}
	steps := []struct {
		name string
		do   func() error
	}{
		{"", func() error { return d.chord(rdp.ScanLeftWin, rdp.ScanR) }},
		{"run-box", func() error { return d.sleep(1500 * time.Millisecond) }},
		{"", func() error { return d.chord(rdp.ScanLeftCtrl, rdp.ScanA) }}, // replace the last command shown
		{"", func() error { return d.typeText(line) }},
		{"typed", func() error { return d.typeText("\n") }},
	}
	for _, st := range steps {
		if err := st.do(); err != nil {
			return nil, err
		}
		if st.name != "" {
			d.debugShot(st.name)
		}
	}
	if _, err := waitCalibration(d, first, 15*time.Second); err != nil {
		d.debugShot("no-console")
		return nil, fmt.Errorf("console did not appear: %w", err)
	}
	d.debugShot("launched")

	// The console is up and has the keyboard: maximise it and calibrate
	// again at the new size.
	if err := d.chord(rdp.ScanLeftWin, rdp.ScanUp); err != nil {
		return nil, err
	}
	if err := d.sleep(time.Second); err != nil {
		return nil, err
	}
	if err := d.typeText(console.CalibrationCommand(second) + "\n"); err != nil {
		return nil, err
	}
	r, err := waitCalibration(d, second, 10*time.Second)
	if err != nil {
		d.debugShot("no-recalibration")
		return nil, fmt.Errorf("console stopped responding after maximising: %w", err)
	}
	d.debugShot("calibrated")
	return r, nil
}

func newNonce() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:]) % 1000000000
}

// waitCalibration waits for the calibration rows with the given nonce and
// the prompt after them.
func waitCalibration(d *desktop, nonce uint32, timeout time.Duration) (*console.Reader, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error = console.ErrNoCalibration
	for time.Now().Before(deadline) {
		if err := d.sleep(200 * time.Millisecond); err != nil {
			return nil, err
		}
		r, err := console.Calibrate(d.snapshot())
		switch {
		case err != nil:
			lastErr = err
		case r.Nonce != nonce:
			lastErr = errors.New("found another console's calibration rows, not this one's")
		case r.HasCursor():
			return r, nil
		}
	}
	return nil, lastErr
}

// installHelper types the paging helper into the console and clears it.
// Nothing more is typed until the cleared prompt is seen: keys typed while
// cls runs can be lost.
func installHelper(d *desktop, r *console.Reader) error {
	if err := d.typeFast(console.HelperFunction + "\ncls\n"); err != nil {
		return err
	}
	_, err := waitScreen(d, r, 20*time.Second, clearedPrompt)
	d.debugShot("helper")
	if err != nil {
		return fmt.Errorf("installing the helper: %w", err)
	}
	return nil
}

// clearedPrompt matches a cleared console: a bare prompt on row 0 with the
// cursor after it, and nothing else.
func clearedPrompt(s console.Screen) bool {
	if s.CursorRow != 0 || !atPrompt(s) {
		return false
	}
	for _, l := range s.Lines[1:] {
		if l != "" {
			return false
		}
	}
	return true
}

// Paging timing: how long a page may stay unreadable on screen before
// asking for a redraw, and how long an acknowledged page may stay before
// acknowledging it again.
const (
	redrawAfter = 2 * time.Second
	reackAfter  = 2 * time.Second
)

// runPaged runs command through the helper and collects its output page by
// page. It returns the output text and the command's status.
func runPaged(d *desktop, r *console.Reader, command string, width int, timeout time.Duration) (string, int, error) {
	if err := installHelper(d, r); err != nil {
		return "", 0, err
	}
	id := newNonce()
	if err := d.typeFast(console.RunLine(command, id, width) + "\n"); err != nil {
		return "", 0, err
	}
	d.debugShot("run")
	var data strings.Builder
	next := uint32(0)
	pages := uint32(0)
	st := 0
	deadline := time.Now().Add(timeout)
	var badSince, ackedAt time.Time
	started := time.Now()
	for {
		if time.Now().After(deadline) {
			d.debugShot("page-timeout")
			return "", 0, fmt.Errorf("timed out after %v waiting for page %d", timeout, next)
		}
		if err := d.sleep(50 * time.Millisecond); err != nil {
			return "", 0, err
		}
		scr := r.Read(d.snapshot())
		p, ok := r.ReadPage(scr)
		switch {
		case ok && p.ID == id && p.Seq == next:
			// A new page: take it and acknowledge it.
			data.WriteString(p.Data)
			pages, st = p.Pages, p.Status
			next++
			badSince = time.Time{}
			if err := d.typeFast(console.AckKey(p.Seq)); err != nil {
				return "", 0, err
			}
			ackedAt = time.Now()
			if next == pages {
				out, err := console.DecodeOutput(data.String())
				if err != nil {
					return "", 0, err
				}
				if _, err := waitScreen(d, r, 10*time.Second, clearedPrompt); err != nil {
					status("helper did not return to the prompt: %v", err)
				}
				if pages > 1 {
					status("received %d pages in %.1fs", pages, time.Since(started).Seconds())
				}
				return normalizeOutput(out), st, nil
			}
		case ok && p.ID == id && p.Seq == next-1 && next > 0:
			// Still showing the page already taken: the acknowledgement
			// may have been lost. Repeating it is harmless.
			if time.Since(ackedAt) > reackAfter {
				if err := d.typeFast(console.AckKey(p.Seq)); err != nil {
					return "", 0, err
				}
				ackedAt = time.Now()
			}
		case next == 0 && atPrompt(scr) && time.Since(started) > time.Second:
			// Back at the prompt without a page: the helper failed.
			d.debugShot("helper-failed")
			return strings.Join(trimBlank(scr.Lines), "\n") + "\n", 0,
				errors.New("the helper did not start a transfer; the console shows the output above")
		case !ok && strings.HasPrefix(firstLine(scr), "RDPCLI1 "):
			// A page that does not check out: still being drawn, or
			// misdrawn. Ask for a redraw if it stays that way.
			if badSince.IsZero() {
				badSince = time.Now()
			} else if time.Since(badSince) > redrawAfter {
				d.debugShot(fmt.Sprintf("bad-page-%d", next))
				if err := d.typeFast("r"); err != nil {
					return "", 0, err
				}
				badSince = time.Time{}
			}
		}
	}
}

// atPrompt reports whether the cursor sits after a PowerShell prompt.
func atPrompt(s console.Screen) bool {
	if s.CursorRow < 0 {
		return false
	}
	line := s.Lines[s.CursorRow]
	return s.CursorCol == len([]rune(line))+1 && promptRE.MatchString(line)
}

func firstLine(s console.Screen) string {
	if len(s.Lines) == 0 {
		return ""
	}
	return s.Lines[0]
}

// normalizeOutput converts CRLF to LF and drops the blank line Out-String
// ends with.
func normalizeOutput(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// terminalWidth is stdout's terminal width, or 120 when it is not a
// terminal.
func terminalWidth() int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 120
}

// waitScreen waits until the console matches want on two reads in a row.
func waitScreen(d *desktop, r *console.Reader, timeout time.Duration, want func(console.Screen) bool) (console.Screen, error) {
	deadline := time.Now().Add(timeout)
	var scr console.Screen
	matched := false
	for time.Now().Before(deadline) {
		if err := d.sleep(100 * time.Millisecond); err != nil {
			return scr, err
		}
		scr = r.Read(d.snapshot())
		if want(scr) {
			if matched {
				return scr, nil
			}
			matched = true
		} else {
			matched = false
		}
	}
	return scr, errors.New("timed out waiting for the console")
}

func trimBlank(lines []string) []string {
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// handoff brings up the browser viewer when rdpcli needs the user to do
// something on the remote desktop, such as completing a logon.
type handoff struct {
	fb       *screen.Framebuffer
	listen   string
	disabled bool

	conn   *rdp.Conn
	v      *viewer.Server
	srv    *http.Server
	cancel context.CancelFunc
}

func (h *handoff) setConn(c *rdp.Conn) {
	h.conn = c
	if h.v != nil {
		h.v.SetInput(c.SendInput)
	}
}

// ask shows msg in the viewer (starting it if needed) and waits for the
// user to press Continue.
func (h *handoff) ask(d *desktop, msg string) error {
	if h.disabled {
		return fmt.Errorf("needs a person: %s (not asking: --no-interactive)", msg)
	}
	if h.v == nil {
		ln, err := net.Listen("tcp", h.listen)
		if err != nil {
			return fmt.Errorf("viewer: %w", err)
		}
		h.v = viewer.New(h.fb)
		h.v.SetInput(h.conn.SendInput)
		h.srv = &http.Server{Handler: h.v.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go h.srv.Serve(ln)
		var vctx context.Context
		vctx, h.cancel = context.WithCancel(context.Background())
		go h.v.Run(vctx)
		h.v.SetStatus("rdpcli console")
		fmt.Fprintf(os.Stderr, "rdpcli: needs you in the browser viewer: http://%s%s\n", ln.Addr(), h.v.Path())
	}
	status("waiting for you: %s", msg)
	select {
	case <-h.v.AskContinue(msg):
		status("continuing")
		return nil
	case <-d.ctx.Done():
		return d.ctx.Err()
	case err := <-d.done:
		d.done <- err
		if err == nil {
			err = rdp.ErrDisconnected
		}
		return err
	}
}

func (h *handoff) close() {
	if h.v == nil {
		return
	}
	h.v.SetInput(nil)
	h.v.SetStatus("rdpcli finished")
	time.Sleep(200 * time.Millisecond) // let the browser see it
	h.cancel()
	h.srv.Close()
}
