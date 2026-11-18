// Command rdpcli is a command-line client for Windows Remote Desktop.
package main

import (
	"context"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/wrouesnel/rdpcli/internal/rdp"
	"github.com/wrouesnel/rdpcli/internal/screen"
)

const usage = `usage: rdpcli <command> [options]

commands:
  connect HOST[:PORT]      open an authenticated RDP session, wait for logon, disconnect
  screenshot HOST[:PORT]   log on and save the remote desktop as a PNG
  view HOST[:PORT]         show and control the remote desktop in a local browser page
  console HOST[:PORT]      open a PowerShell console, run a command, print what it shows

Run "rdpcli <command> -h" for command options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "connect":
		os.Exit(cmdConnect(args))
	case "screenshot":
		os.Exit(cmdScreenshot(args))
	case "view":
		os.Exit(cmdView(args))
	case "console":
		os.Exit(cmdConsole(args))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "rdpcli: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdConnect(args []string) int {
	f := newConnFlags("connect", "connect HOST[:PORT] -u USER [options]")
	hold := f.fs.Duration("hold", 0, "stay connected this long after logon before disconnecting")
	host, ok := f.parse(args)
	if !ok {
		return 2
	}
	start := time.Now()
	cfg, err := f.config(host, true, start)
	if err != nil {
		status("%v", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *f.timeout)
	defer cancel()
	s, err := openSession(ctx, cfg, start, sessionOpts{})
	if err != nil {
		status("%v", err)
		return 1
	}
	if *hold > 0 {
		hctx, hcancel := context.WithTimeout(context.Background(), *hold)
		defer hcancel()
		if err := s.pump(hctx, nil); err != nil {
			status("%v", err)
			s.conn.Close()
			return 1
		}
	}
	status("disconnecting")
	s.close()
	return 0
}

func cmdScreenshot(args []string) int {
	f := newConnFlags("screenshot", "screenshot HOST[:PORT] -u USER -o FILE.png [options]")
	out := f.fs.String("o", "", "output PNG file (required)")
	settle := f.fs.Duration("settle", 2*time.Second, "after logon, wait until the screen has not changed for this long")
	maxWait := f.fs.Duration("max-wait", 20*time.Second, "after logon, wait at most this long for the screen to settle")
	host, ok := f.parse(args)
	if !ok {
		return 2
	}
	if *out == "" {
		f.fs.Usage()
		return 2
	}
	start := time.Now()
	cfg, err := f.config(host, false, start)
	if err != nil {
		status("%v", err)
		return 2
	}

	fb := screen.New()
	lastUpdate := time.Now()
	onEvent := func(ev rdp.Event) {
		if ev.Activated {
			fb.Resize(ev.Width, ev.Height)
		}
		if len(ev.Bitmaps) > 0 {
			fb.Draw(ev.Bitmaps)
			lastUpdate = time.Now()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *f.timeout)
	defer cancel()
	s, err := openSession(ctx, cfg, start, sessionOpts{onEvent: onEvent})
	if err != nil {
		status("%v", err)
		return 1
	}
	defer s.close()

	// Wait for the desktop to finish drawing.
	deadline := time.Now().Add(*maxWait)
	for time.Now().Before(deadline) {
		wctx, wcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		err := s.pump(wctx, onEvent)
		wcancel()
		if err != nil {
			status("%v", err)
			return 1
		}
		if time.Since(lastUpdate) >= *settle {
			break
		}
	}

	file, err := os.Create(*out)
	if err != nil {
		status("%v", err)
		return 1
	}
	img := fb.Snapshot(image.Rectangle{})
	if err := png.Encode(file, img); err != nil {
		file.Close()
		status("writing %s: %v", *out, err)
		return 1
	}
	if err := file.Close(); err != nil {
		status("writing %s: %v", *out, err)
		return 1
	}
	status("wrote %s (%dx%d)", *out, img.Rect.Dx(), img.Rect.Dy())
	return 0
}

// interruptContext returns a context cancelled on Ctrl-C or SIGTERM.
func interruptContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
