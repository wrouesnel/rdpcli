package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/wrouesnel/rdpcli/internal/rdp"
)

// connFlags are the connection options shared by all commands.
type connFlags struct {
	fs        *flag.FlagSet
	user      *string
	passStdin *bool
	insecure  *bool
	pin       *string
	console   *bool
	timeout   *time.Duration
	width     *uint
	height    *uint
	verbose   *bool
}

func newConnFlags(name, usageLine string) *connFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: rdpcli "+usageLine)
		fs.PrintDefaults()
	}
	return &connFlags{
		fs:        fs,
		user:      fs.String("u", "", `user name: user, DOMAIN\user or user@domain`),
		passStdin: fs.Bool("password-stdin", false, "read the password from the first line of stdin"),
		insecure:  fs.Bool("tls-insecure", false, "do not verify the server's TLS certificate"),
		pin:       fs.String("tls-sha256", "", "accept only a server certificate with this SHA-256 fingerprint"),
		console:   fs.Bool("admin", false, "connect to the console (administrative) session"),
		timeout:   fs.Duration("timeout", time.Minute, "time limit for connecting and logging on"),
		width:     fs.Uint("width", 1024, "desktop width"),
		height:    fs.Uint("height", 768, "desktop height"),
		verbose:   fs.Bool("v", false, "trace the protocol exchange"),
	}
}

// parse parses args (host before or after the flags) and returns host:port.
func (f *connFlags) parse(args []string) (string, bool) {
	var host string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host, args = args[0], args[1:]
	}
	if err := f.fs.Parse(args); err != nil {
		return "", false
	}
	if host == "" && f.fs.NArg() > 0 {
		host = f.fs.Arg(0)
	}
	if host == "" || *f.user == "" {
		f.fs.Usage()
		return "", false
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "3389")
	}
	return host, true
}

// config builds the connection configuration, reading the password.
func (f *connFlags) config(host string, headless bool, start time.Time) (rdp.Config, error) {
	password, err := readPassword(*f.passStdin)
	if err != nil {
		return rdp.Config{}, err
	}
	tcfg, err := tlsConfig(*f.insecure, *f.pin)
	if err != nil {
		return rdp.Config{}, err
	}
	domain, user := splitUser(*f.user)
	cfg := rdp.Config{
		Addr: host, Domain: domain, User: user, Password: password,
		Width: uint16(*f.width), Height: uint16(*f.height),
		Console: *f.console, Headless: headless, TLS: tcfg,
	}
	if *f.verbose {
		cfg.Logf = func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "[%7.3fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, a...))
		}
	}
	return cfg, nil
}

// splitUser accepts DOMAIN\user, user@domain or a bare user name.
func splitUser(s string) (domain, user string) {
	if i := strings.IndexByte(s, '\\'); i >= 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		return s[i+1:], s[:i]
	}
	return "", s
}

// readPassword takes the password from RDPCLI_PASSWORD, from stdin when
// asked, or by prompting on the terminal. It never comes from argv.
func readPassword(fromStdin bool) (string, error) {
	if pw, ok := os.LookupEnv("RDPCLI_PASSWORD"); ok {
		return pw, nil
	}
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no password: set RDPCLI_PASSWORD, use --password-stdin, or run on a terminal")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(pw), err
}

func tlsConfig(insecure bool, pin string) (*tls.Config, error) {
	cfg := &tls.Config{}
	if pin != "" {
		want, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(pin), ":", ""))
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("--tls-sha256 must be a hex SHA-256 fingerprint")
		}
		// Pinning replaces chain verification: self-signed RDP certificates
		// are the norm.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			got := sha256.Sum256(raw[0])
			if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
				return fmt.Errorf("server certificate fingerprint %x does not match --tls-sha256", got)
			}
			return nil
		}
	} else if insecure {
		cfg.InsecureSkipVerify = true
	}
	return cfg, nil
}

const (
	maxAttempts = 3
	retryDelay  = 2 * time.Second
)

type result struct {
	ev  rdp.Event
	err error
}

// session is a logged-on connection plus the goroutine reading its events.
type session struct {
	conn   *rdp.Conn
	events chan result
	logon  *rdp.LogonInfo
}

// status prints a progress message to stderr.
func status(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "rdpcli: "+format+"\n", a...)
}

// sessionOpts adjust openSession.
type sessionOpts struct {
	// onEvent, if set, sees every event, including those before logon (the
	// server starts drawing before it reports the logon).
	onEvent func(rdp.Event)
	// onConn, if set, is called with each new connection before its
	// events are read, e.g. to route input to it.
	onConn func(*rdp.Conn)
	// interactive: if the session is active but the logon has not been
	// reported within logonGrace, return it anyway (session.logon is nil)
	// so a user can complete the logon by hand, e.g. through a legal
	// notice, a password change or a logon screen.
	interactive bool
}

// logonGrace is how long an interactive open waits for an automatic logon.
const logonGrace = 5 * time.Second

// openSession connects and logs on, retrying the transient "dropped before
// logon" case.
func openSession(ctx context.Context, cfg rdp.Config, start time.Time, opts sessionOpts) (*session, error) {
	for attempt := 1; ; attempt++ {
		s, retry, err := tryLogOn(ctx, cfg, start, opts)
		if err == nil {
			return s, nil
		}
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) {
			err = fmt.Errorf("%w\nuse --tls-sha256 to pin the server certificate or --tls-insecure to skip verification", err)
		}
		if !retry || attempt == maxAttempts {
			return nil, err
		}
		status("%v; server dropped the session before logon, retrying (%d/%d)", err, attempt+1, maxAttempts)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryDelay):
		}
	}
}

// tryLogOn makes one attempt. retry reports a failure worth retrying: the
// server dropping an activated connection before logon without giving a
// reason, which Windows does when a new connection races the teardown of
// the previous one to the same session.
func tryLogOn(ctx context.Context, cfg rdp.Config, start time.Time, opts sessionOpts) (*session, bool, error) {
	conn, err := rdp.Dial(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("connect: %w", err)
	}
	status("connected to %s: %s, certificate sha256 %s", cfg.Addr, conn.Protocol, conn.CertSHA256)
	if opts.onConn != nil {
		opts.onConn(conn)
	}

	s := &session{conn: conn, events: make(chan result, 16)}
	go func() {
		for {
			ev, err := conn.Next()
			s.events <- result{ev, err}
			if err != nil {
				return
			}
		}
	}()

	activated := false
	var grace <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return nil, false, errors.New("timed out waiting for logon")
		case <-grace:
			status("no automatic logon after %v; continuing so the logon can be completed by hand", logonGrace)
			return s, false, nil
		case res := <-s.events:
			if res.err != nil {
				conn.Close()
				return nil, activated && res.err == rdp.ErrDisconnected, res.err
			}
			if opts.onEvent != nil {
				opts.onEvent(res.ev)
			}
			switch {
			case res.ev.Activated:
				activated = true
				if opts.interactive && grace == nil {
					grace = time.After(logonGrace)
				}
				status("session activated (%dx%d) after %.1fs", res.ev.Width, res.ev.Height, time.Since(start).Seconds())
			case res.ev.LogonError != nil:
				status("server: %s", res.ev.LogonError)
			case res.ev.LoggedOn != nil:
				s.logon = res.ev.LoggedOn
				who := describeLogon(s.logon)
				status("logged on as %s, session id %d, after %.1fs", who, s.logon.SessionID, time.Since(start).Seconds())
				return s, false, nil
			}
		}
	}
}

// pump delivers events to onEvent until ctx is done or the connection ends.
func (s *session) pump(ctx context.Context, onEvent func(rdp.Event)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case res := <-s.events:
			if res.err != nil {
				return res.err
			}
			if onEvent != nil {
				onEvent(res.ev)
			}
		}
	}
}

// close disconnects gracefully and waits briefly for the server to close
// its side (see rdp.Conn.Disconnect), then closes the connection.
func (s *session) close() {
	defer s.conn.Close()
	if err := s.conn.Disconnect(); err != nil {
		return
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case res := <-s.events:
			if res.err != nil {
				return
			}
		case <-timeout:
			status("server did not close the connection; closing anyway")
			return
		}
	}
}

// describeLogon names the logged-on user as DOMAIN\user.
func describeLogon(l *rdp.LogonInfo) string {
	if l.Domain != "" {
		return l.Domain + `\` + l.User
	}
	return l.User
}
