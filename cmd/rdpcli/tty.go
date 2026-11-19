package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/term"

	"github.com/wrouesnel/rdpcli/internal/console"
)

// detachKey (Ctrl+]) ends an interactive session from this side.
const detachKey = 0x1d

// errDetached means the user ended the session with the detach key.
var errDetached = errors.New("detached")

// Interactive link timing and sizes.
const (
	ttyPoll       = 15 * time.Millisecond
	ttyReread     = 300 * time.Millisecond // read the screen this often even without updates
	ttyReack      = time.Second            // acknowledge a page again if it stays up this long
	ttyFrameRetry = 1500 * time.Millisecond
	ttyRedraw     = 1500 * time.Millisecond // ask for a redraw after a bad page stays this long
	ttyFrameMax   = 192                     // input bytes per frame
	ttyStartLimit = 20 * time.Second
	ttyKeepalive  = 15 * time.Second // the helper gives up after 60s without a key
)

// ttyCommandLine is the command line run in the pseudo console: an
// interactive PowerShell, or PowerShell running command.
func ttyCommandLine(command string) string {
	if command == "" {
		return "powershell.exe -NoLogo"
	}
	u := utf16.Encode([]rune(command))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return "powershell.exe -NoLogo -NoProfile -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

// ttySize is the local terminal's size, or a default when stdout is not a
// terminal.
func ttySize(defCols int) (cols, rows int) {
	if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil && c > 0 && r > 0 {
		return c, r
	}
	if defCols <= 0 {
		defCols = 120
	}
	return defCols, 40
}

// installPty compiles the pseudo console helper in the console.
func installPty(d *desktop, r *console.Reader) error {
	if err := d.typeFast(strings.Join(console.PtyInstallLines(), "\n") + "\n"); err != nil {
		return err
	}
	scr, err := waitScreen(d, r, time.Minute, atPrompt)
	d.debugShot("pty-helper")
	if err != nil {
		return fmt.Errorf("installing the terminal helper: %w", err)
	}
	if !clearedPrompt(scr) {
		return fmt.Errorf("installing the terminal helper failed; the console shows:\n%s", strings.Join(trimBlank(scr.Lines), "\n"))
	}
	return nil
}

// runTTY runs cmdline in a pseudo console on the remote side, connected to
// this terminal, and returns its exit code.
func runTTY(d *desktop, r *console.Reader, cmdline string, defCols int) (int, error) {
	if err := installPty(d, r); err != nil {
		return 0, err
	}
	cols, rows := ttySize(defCols)
	id := newNonce()
	if err := d.typeFast(console.PtyRunLine(cmdline, id, cols, rows) + "\n"); err != nil {
		return 0, err
	}
	d.debugShot("pty-run")

	inFd := int(os.Stdin.Fd())
	if term.IsTerminal(inFd) {
		old, err := term.MakeRaw(inFd)
		if err != nil {
			return 0, err
		}
		defer term.Restore(inFd, old)
	}
	input := make(chan []byte, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				input <- bytes.Clone(buf[:n])
			}
			if err != nil {
				close(input)
				return
			}
		}
	}()

	t := &ttyLink{d: d, r: r, id: id, started: time.Now(), typedAt: time.Now(), cols: cols, rows: rows}
	ended := false
	defer func() {
		if !ended {
			t.resetTerminal()
		}
	}()
	tick := time.NewTicker(ttyPoll)
	defer tick.Stop()
	for {
		select {
		case b, ok := <-input:
			if !ok {
				input = nil
				break
			}
			if i := bytes.IndexByte(b, detachKey); i >= 0 {
				t.pending = append(t.pending, b[:i]...)
				return 0, t.finish(".q", errDetached)
			}
			t.pending = append(t.pending, b...)
		case <-tick.C:
		case <-d.ctx.Done():
			return 0, d.ctx.Err()
		case err := <-d.done:
			d.done <- err
			return 0, fmt.Errorf("connection lost: %v", err)
		}
		st, done, err := t.step()
		if done {
			ended = err == nil
			return st, err
		}
		if err != nil {
			return st, err
		}
	}
}

// ttyLink is the state of an interactive session on rdpcli's side.
type ttyLink struct {
	d       *desktop
	r       *console.Reader
	id      uint32
	started time.Time
	seen    bool // a page from this session has been read

	next    uint32 // next page to take
	ackedAt time.Time

	inSeq     uint32 // input frames the helper has applied
	frame     string // the frame in flight, if any
	frameAt   time.Time
	pending   []byte // input not yet sent
	resize    string
	cols      int
	rows      int
	sizedAt   time.Time
	readAt    time.Time
	typedAt   time.Time
	updateAt  time.Time
	badSince  time.Time
	altScreen bool // the program switched the terminal to the alternate screen
}

// trackModes notes terminal modes the program's output turns on that
// resetTerminal must turn off if the session ends early.
func (t *ttyLink) trackModes(b []byte) {
	on := bytes.LastIndex(b, []byte("\x1b[?1049h"))
	off := bytes.LastIndex(b, []byte("\x1b[?1049l"))
	if on > off {
		t.altScreen = true
	} else if off > on {
		t.altScreen = false
	}
}

// resetTerminal undoes what the pseudo console sets on the terminal when
// the session ends without the program exiting: the pseudo console only
// turns its modes off itself on a normal exit. They are focus reporting
// and win32-input-mode, which the pseudo console asks for at the start,
// plus the alternate screen and a hidden cursor, which full-screen
// programs leave behind.
func (t *ttyLink) resetTerminal() {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	s := "\x1b[m\x1b[?25h\x1b[?1004l\x1b[?9001l"
	if t.altScreen {
		s += "\x1b[?1049l"
	}
	os.Stdout.WriteString(s + "\r\n")
}

// step reads the screen if it may have changed and sends what is due.
// done is set, with the program's exit code, when the program has ended.
func (t *ttyLink) step() (status int, done bool, err error) {
	now := time.Now()
	if now.Sub(t.sizedAt) > 500*time.Millisecond {
		t.sizedAt = now
		if c, r, err := term.GetSize(int(os.Stdout.Fd())); err == nil && (c != t.cols || r != t.rows) && c > 0 && r > 0 {
			t.cols, t.rows = c, r
			t.resize = fmt.Sprintf("%d,%d", c, r)
		}
	}

	if u := t.d.fb.LastUpdate(); u != t.updateAt || now.Sub(t.readAt) > ttyReread {
		t.updateAt, t.readAt = u, now
		img := t.d.snapshot()
		p, header, ok := t.r.ReadStream(img)
		switch {
		case ok && p.ID == t.id:
			t.seen = true
			t.badSince = time.Time{}
			if t.frame != "" && int32(p.InSeq-t.inSeq) > 0 {
				t.inSeq, t.frame = p.InSeq, ""
			}
			switch {
			case p.Seq == t.next && len(p.Data) > 0:
				if _, err := os.Stdout.Write(p.Data); err != nil {
					return 0, false, err
				}
				t.trackModes(p.Data)
				t.next++
				t.ackedAt = now
				if err := t.keys(console.AckKey(p.Seq)); err != nil {
					return 0, false, err
				}
			case p.Seq == t.next && !p.Running:
				return p.Status, true, t.finish("q", nil)
			case p.Seq+1 == t.next && now.Sub(t.ackedAt) > ttyReack:
				// The acknowledgement may have been lost.
				t.ackedAt = now
				if err := t.keys("." + console.AckKey(p.Seq)); err != nil {
					return 0, false, err
				}
			}
		case header && !ok:
			// Still being drawn, or misdrawn.
			if t.badSince.IsZero() {
				t.badSince = now
			} else if now.Sub(t.badSince) > ttyRedraw {
				t.badSince = time.Time{}
				t.d.debugShot(fmt.Sprintf("bad-page-%d", t.next))
				if err := t.keys(".r"); err != nil {
					return 0, false, err
				}
			}
		case !t.seen && now.Sub(t.started) > time.Second:
			scr := t.r.Read(img)
			if atPrompt(scr) {
				t.d.debugShot("pty-failed")
				return 0, false, fmt.Errorf("the terminal helper did not start; the console shows:\n%s",
					strings.Join(trimBlank(scr.Lines), "\n"))
			}
			if now.Sub(t.started) > ttyStartLimit {
				return 0, false, errors.New("the terminal helper did not start")
			}
		}
	}

	if !t.seen {
		return 0, false, nil
	}
	switch {
	case t.frame == "" && t.resize != "":
		t.frame = console.InputFrame('w', t.inSeq, []byte(t.resize))
		t.resize = ""
		return 0, false, t.sendFrame("")
	case t.frame == "" && len(t.pending) > 0:
		n := min(len(t.pending), ttyFrameMax)
		t.frame = console.InputFrame('i', t.inSeq, t.pending[:n])
		t.pending = t.pending[n:]
		return 0, false, t.sendFrame("")
	case t.frame != "" && now.Sub(t.frameAt) > ttyFrameRetry:
		// The frame was lost or damaged: send it again, after a "." that
		// ends whatever the helper made of it.
		return 0, false, t.sendFrame(".")
	case now.Sub(t.typedAt) > ttyKeepalive:
		return 0, false, t.keys(".")
	}
	return 0, false, nil
}

// keys types s into the console.
func (t *ttyLink) keys(s string) error {
	t.typedAt = time.Now()
	return t.d.typeFast(s)
}

func (t *ttyLink) sendFrame(prefix string) error {
	t.frameAt = time.Now()
	return t.keys(prefix + t.frame)
}

// finish types keys that end the helper, waits for it to return to the
// prompt and returns err.
func (t *ttyLink) finish(keys string, err error) error {
	if e := t.keys(keys); e != nil {
		return e
	}
	if _, e := waitScreen(t.d, t.r, 10*time.Second, clearedPrompt); e != nil && err == nil {
		status("the terminal helper did not return to the prompt: %v", e)
	}
	return err
}
