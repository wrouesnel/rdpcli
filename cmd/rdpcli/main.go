// Command rdpcli is a command-line client for Windows Remote Desktop.
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

const usage = `usage: rdpcli <command> [options]

commands:
  connect HOST[:PORT]   open an authenticated RDP session, wait for logon, disconnect

Run "rdpcli <command> -h" for command options.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connect":
		os.Exit(cmdConnect(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "rdpcli: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
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

func cmdConnect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: rdpcli connect HOST[:PORT] -u USER [options]")
		fs.PrintDefaults()
	}
	userFlag := fs.String("u", "", `user name: user, DOMAIN\user or user@domain`)
	passStdin := fs.Bool("password-stdin", false, "read the password from the first line of stdin")
	insecure := fs.Bool("tls-insecure", false, "do not verify the server's TLS certificate")
	pin := fs.String("tls-sha256", "", "accept only a server certificate with this SHA-256 fingerprint")
	console := fs.Bool("admin", false, "connect to the console (administrative) session")
	hold := fs.Duration("hold", 0, "stay connected this long after logon before disconnecting")
	timeout := fs.Duration("timeout", time.Minute, "time limit for connecting and logging on")
	width := fs.Uint("width", 1024, "desktop width")
	height := fs.Uint("height", 768, "desktop height")
	verbose := fs.Bool("v", false, "trace the protocol exchange")

	// Allow the host before or after the flags.
	var host string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		host, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if host == "" && fs.NArg() > 0 {
		host = fs.Arg(0)
	}
	if host == "" || *userFlag == "" {
		fs.Usage()
		return 2
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "3389")
	}

	password, err := readPassword(*passStdin)

	if err != nil {
		fmt.Fprintln(os.Stderr, "rdpcli:", err)
		return 1
	}
	tcfg, err := tlsConfig(*insecure, *pin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rdpcli:", err)
		return 2
	}

	domain, user := splitUser(*userFlag)
	cfg := rdp.Config{
		Addr: host, Domain: domain, User: user, Password: password,
		Width: uint16(*width), Height: uint16(*height),
		Console: *console, TLS: tcfg,
	}
	start := time.Now()
	if *verbose {
		cfg.Logf = func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "[%7.3fs] %s\n", time.Since(start).Seconds(), fmt.Sprintf(format, a...))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var sess *session
	var logon *rdp.LogonInfo
	for attempt := 1; ; attempt++ {
		var retry bool
		sess, logon, retry, err = logOn(ctx, cfg, host, start)
		if err == nil {
			break
		}
		fmt.Fprintln(os.Stderr, "rdpcli:", err)
		var ce *tls.CertificateVerificationError
		if errors.As(err, &ce) {
			fmt.Fprintln(os.Stderr, "rdpcli: use --tls-sha256 to pin the server certificate or --tls-insecure to skip verification")
		}
		if !retry || attempt == maxAttempts {
			return 1
		}
		fmt.Fprintf(os.Stderr, "rdpcli: server dropped the session before logon; retrying (%d/%d)\n", attempt+1, maxAttempts)
		select {
		case <-ctx.Done():
			return 1
		case <-time.After(retryDelay):
		}
	}
	defer sess.conn.Close()

	who := logon.User
	if logon.Domain != "" {
		who = logon.Domain + `\` + who
	}
	if who == "" {
		who = user
	}
	fmt.Printf("logged on as %s, session id %d, after %.1fs\n", who, logon.SessionID, time.Since(start).Seconds())

	if *hold > 0 {
		deadline := time.After(*hold)
	wait:
		for {
			select {
			case <-deadline:
				break wait
			case res := <-sess.events:
				if res.err != nil {
					fmt.Fprintln(os.Stderr, "rdpcli:", res.err)
					return 1
				}
			}
		}
	}
	fmt.Println("disconnecting")
	if err := sess.conn.Disconnect(); err != nil {
		fmt.Fprintln(os.Stderr, "rdpcli: disconnect:", err)
		return 1
	}
	// Wait for the server to close its side; see Conn.Disconnect.
	select {
	case res := <-sess.events:
		for res.err == nil {
			res = <-sess.events
		}
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "rdpcli: server did not close the connection; closing anyway")
	}
	return 0
}

const (
	maxAttempts = 3
	retryDelay  = 2 * time.Second
)

type result struct {
	ev  rdp.Event
	err error
}

// session is a connection plus the goroutine reading its events.
type session struct {
	conn   *rdp.Conn
	events chan result
}

// logOn connects and waits for the server to report the user logon. retry
// reports a failure worth retrying: the server dropping an activated
// connection before logon without giving a reason. Windows does this when a
// new connection races the teardown of the previous one to the same session.
func logOn(ctx context.Context, cfg rdp.Config, host string, start time.Time) (*session, *rdp.LogonInfo, bool, error) {
	conn, err := rdp.Dial(ctx, cfg)
	if err != nil {
		return nil, nil, false, fmt.Errorf("connect: %w", err)
	}
	fmt.Printf("connected to %s: %s, certificate sha256 %s\n", host, conn.Protocol, conn.CertSHA256)

	s := &session{conn: conn, events: make(chan result)}
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
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return nil, nil, false, errors.New("timed out waiting for logon")
		case res := <-s.events:
			if res.err != nil {
				conn.Close()
				return nil, nil, activated && res.err == rdp.ErrDisconnected, res.err
			}
			switch {
			case res.ev.Activated:
				activated = true
				fmt.Printf("session activated after %.1fs\n", time.Since(start).Seconds())
			case res.ev.LogonError != nil:
				fmt.Printf("server: %s\n", res.ev.LogonError)
			case res.ev.LoggedOn != nil:
				return s, res.ev.LoggedOn, false, nil
			}
		}
	}
}
