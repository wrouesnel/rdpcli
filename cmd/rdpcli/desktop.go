package main

import (
	"context"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"time"

	"github.com/wrouesnel/rdpcli/internal/rdp"
	"github.com/wrouesnel/rdpcli/internal/screen"
)

// desktop is a logged-on session whose screen is kept up to date in the
// background, for commands that drive the desktop with keys and read the
// result off the screen.
type desktop struct {
	ctx      context.Context
	stopPump context.CancelFunc
	s        *session
	fb       *screen.Framebuffer
	done     chan error // receives the pump's result
	debug    string     // directory for step screenshots, if set
	shots    int
}

func newDesktop(ctx context.Context, s *session, fb *screen.Framebuffer, onEvent func(rdp.Event), debug string) *desktop {
	pctx, cancel := context.WithCancel(ctx)
	d := &desktop{ctx: ctx, stopPump: cancel, s: s, fb: fb, done: make(chan error, 1), debug: debug}
	go func() { d.done <- s.pump(pctx, onEvent) }()
	return d
}

// close stops reading screen updates and disconnects.
func (d *desktop) close() {
	d.stopPump()
	err := <-d.done
	d.done <- err
	d.s.close()
}

// sleep waits, failing early if the connection ends or ctx is cancelled.
func (d *desktop) sleep(dur time.Duration) error {
	select {
	case <-d.ctx.Done():
		return d.ctx.Err()
	case err := <-d.done:
		d.done <- err
		if err == nil {
			err = rdp.ErrDisconnected
		}
		return err
	case <-time.After(dur):
		return nil
	}
}

// settle waits until the screen has been still for quiet, at most max.
// Windows ignores input for a moment after a client connects, while it
// switches the session to the new connection; the screen redrawing is the
// visible sign of that.
func (d *desktop) settle(quiet, max time.Duration) error {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if time.Since(d.fb.LastUpdate()) >= quiet {
			return nil
		}
		if err := d.sleep(100 * time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

// Typing pace: the Run box's autocomplete drops characters that arrive
// faster than it can process them, so text goes in small chunks.
const (
	typeChunk = 6 // characters per chunk
	typeDelay = 40 * time.Millisecond
)

// typeText types s with Unicode key events, paced.
func (d *desktop) typeText(s string) error {
	runes := []rune(s)
	for len(runes) > 0 {
		n := min(len(runes), typeChunk)
		if err := d.s.conn.SendInput(rdp.TextEvents(string(runes[:n]))...); err != nil {
			return err
		}
		runes = runes[n:]
		if err := d.sleep(typeDelay); err != nil {
			return err
		}
	}
	return nil
}

// chord presses keys in order and releases them in reverse, e.g. Win+R.
func (d *desktop) chord(keys ...rdp.Scancode) error {
	var evs []rdp.InputEvent
	for _, k := range keys {
		evs = append(evs, rdp.Key(k, true))
	}
	for i := len(keys) - 1; i >= 0; i-- {
		evs = append(evs, rdp.Key(keys[i], false))
	}
	return d.s.conn.SendInput(evs...)
}

// snapshot returns the current desktop image.
func (d *desktop) snapshot() *image.RGBA {
	return d.fb.Snapshot(image.Rectangle{})
}

// debugShot saves the screen as a numbered PNG when --debug is set.
func (d *desktop) debugShot(name string) {
	if d.debug == "" {
		return
	}
	d.shots++
	path := filepath.Join(d.debug, fmt.Sprintf("%02d-%s.png", d.shots, name))
	f, err := os.Create(path)
	if err != nil {
		status("debug: %v", err)
		return
	}
	defer f.Close()
	if err := png.Encode(f, d.snapshot()); err != nil {
		status("debug: %v", err)
	}
}
