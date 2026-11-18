package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/wrouesnel/rdpcli/internal/rdp"
	"github.com/wrouesnel/rdpcli/internal/screen"
	"github.com/wrouesnel/rdpcli/internal/viewer"
)

func cmdView(args []string) int {
	f := newConnFlags("view", "view HOST[:PORT] -u USER [options]")
	listen := f.fs.String("listen", "127.0.0.1:0", "address for the local viewer web page")
	viewOnly := f.fs.Bool("view-only", false, "do not send keyboard or mouse input")
	host, ok := f.parse(args)
	if !ok {
		return 2
	}
	start := time.Now()
	cfg, err := f.config(host, false, start)
	if err != nil {
		status("%v", err)
		return 2
	}

	fb := screen.New()
	v := viewer.New(fb)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		status("viewer: %v", err)
		return 1
	}
	srv := &http.Server{Handler: v.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, stop := interruptContext()
	defer stop()
	go v.Run(ctx)

	fmt.Printf("viewer: http://%s%s\n", ln.Addr(), v.Path())
	v.SetStatus("connecting to %s…", host)

	opened := false // openSession reports logons before it returns
	onEvent := func(ev rdp.Event) {
		if ev.Activated {
			fb.Resize(ev.Width, ev.Height)
		}
		if len(ev.Bitmaps) > 0 {
			fb.Draw(ev.Bitmaps)
		}
		if ev.LoggedOn != nil && opened {
			// Logged on by hand after the session opened.
			who := describeLogon(ev.LoggedOn)
			status("logged on as %s, session id %d", who, ev.LoggedOn.SessionID)
			v.SetStatus("%s on %s (session %d)", who, host, ev.LoggedOn.SessionID)
		}
	}
	opts := sessionOpts{onEvent: onEvent, interactive: !*viewOnly}
	if !*viewOnly {
		opts.onConn = func(c *rdp.Conn) { v.SetInput(c.SendInput) }
	}
	lctx, lcancel := context.WithTimeout(ctx, *f.timeout)
	s, err := openSession(lctx, cfg, start, opts)
	lcancel()
	if err != nil {
		status("%v", err)
		v.SetStatus("connection failed: %v", err)
		time.Sleep(500 * time.Millisecond) // let the browser see it
		return 1
	}
	opened = true
	if s.logon != nil {
		v.SetStatus("%s on %s (session %d)", describeLogon(s.logon), host, s.logon.SessionID)
	} else {
		v.SetStatus("%s: not logged on yet; complete the logon on the screen", host)
	}
	status("viewing; press Ctrl-C to disconnect")

	err = s.pump(ctx, onEvent)
	if err != nil && !errors.Is(err, context.Canceled) {
		status("%v", err)
		v.SetStatus("disconnected: %v", err)
		time.Sleep(500 * time.Millisecond)
		s.conn.Close()
		return 1
	}
	status("disconnecting")
	v.SetInput(nil)
	v.SetStatus("disconnected")
	s.close()
	return 0
}
