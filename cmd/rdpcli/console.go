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
	command := f.fs.String("c", "", "PowerShell command to run; its output is printed (one window's worth for now)")
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
	if *command != "" {
		out, err := runCommand(d, r, *command, *cmdTimeout)
		for _, l := range out {
			fmt.Println(l)
		}
		if err != nil {
			status("%v", err)
			code = 1
		}
	} else {
		scr := r.Read(d.snapshot())
		for _, l := range trimBlank(scr.Lines) {
			fmt.Println(l)
		}
	}
	if !*keep {
		if err := d.typeText("exit\n"); err == nil {
			d.sleep(500 * time.Millisecond)
		}
	}
	return code
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

// runCommand clears the console, runs one command line and returns its
// output, read off the screen once the prompt is back.
func runCommand(d *desktop, r *console.Reader, command string, timeout time.Duration) ([]string, error) {
	if err := d.typeText("cls\n"); err != nil {
		return nil, err
	}
	if _, err := waitPrompt(d, r, 0, 10*time.Second); err != nil {
		return nil, fmt.Errorf("clearing the console: %w", err)
	}
	first := r.Read(d.snapshot()).Lines[0] // the bare prompt
	if err := d.typeText(command + "\n"); err != nil {
		return nil, err
	}
	// The echoed command line may wrap over several rows.
	echo := first + " " + command
	echoRows := (len([]rune(echo)) + r.Grid.Cols - 1) / r.Grid.Cols
	scr, err := waitPrompt(d, r, echoRows, timeout)
	d.debugShot("command-done")
	if err != nil {
		return trimBlank(scr.Lines), err
	}
	out := scr.Lines[echoRows:scr.CursorRow]
	if !strings.HasPrefix(scr.Lines[0], first) {
		err = errors.New("the output was longer than the console window; only its end was captured")
		out = scr.Lines[:scr.CursorRow]
	}
	return trimBlank(out), err
}

// waitPrompt waits until the cursor sits after a prompt on row minRow or
// below, and the screen has stopped changing.
func waitPrompt(d *desktop, r *console.Reader, minRow int, timeout time.Duration) (console.Screen, error) {
	deadline := time.Now().Add(timeout)
	var prev string
	var scr console.Screen
	for time.Now().Before(deadline) {
		if err := d.sleep(150 * time.Millisecond); err != nil {
			return scr, err
		}
		scr = r.Read(d.snapshot())
		cur := strings.Join(scr.Lines, "\n")
		if scr.CursorRow >= minRow && scr.CursorRow >= 0 {
			line := scr.Lines[scr.CursorRow]
			// Scrolling can leave the window short of the bottom row, so
			// only the cursor's row is checked.
			if scr.CursorCol == len([]rune(line))+1 && promptRE.MatchString(line) && cur == prev {
				return scr, nil
			}
		}
		prev = cur
	}
	return scr, errors.New("timed out waiting for the PowerShell prompt")
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
