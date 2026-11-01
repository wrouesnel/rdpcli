// Package rdp implements an RDP client connection ([MS-RDPBCGR]) far enough
// to establish an authenticated, activated session.
package rdp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/wrouesnel/rdpcli/internal/credssp"
)

// Config describes how to connect.
type Config struct {
	Addr       string // host:port
	Domain     string
	User       string
	Password   string
	Width      uint16
	Height     uint16
	ClientName string
	// Console requests the console (administrative) session.
	Console bool
	// TLS is the TLS configuration; ServerName is set from Addr if empty.
	TLS *tls.Config
	// Logf, if set, receives protocol trace messages.
	Logf func(format string, args ...any)
}

// Conn is an established RDP connection.
type Conn struct {
	cfg       Config
	conn      net.Conn
	tls       *tls.Conn
	br        *bufio.Reader
	userID    uint16
	ioChannel uint16
	shareID   uint32

	// CertSHA256 is the hex SHA-256 fingerprint of the server certificate.
	CertSHA256 string
	// Protocol is the negotiated security protocol (e.g. "HYBRID").
	Protocol string
	// ServerVersion is the RDP version from the server core data.
	ServerVersion uint32

	lastErrorInfo uint32
}

func (c *Conn) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
	}
}

// Dial connects, negotiates TLS, authenticates with CredSSP (NLA) and runs
// the connection sequence through capability exchange.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	if cfg.Width == 0 {
		cfg.Width, cfg.Height = 1024, 768
	}
	if cfg.ClientName == "" {
		cfg.ClientName = "rdpcli"
	}

	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	c := &Conn{cfg: cfg, conn: raw}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	if err := c.connect(); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return c, nil
}

func (c *Conn) connect() error {
	// 1. X.224 connection request / confirm with security negotiation.
	if _, err := c.conn.Write(tpkt(x224ConnectionRequest(c.cfg.User, protocolSSL|protocolHybrid))); err != nil {
		return err
	}
	f, err := readFrame(bufio.NewReader(c.conn))
	if err != nil {
		return fmt.Errorf("rdp: reading connection confirm: %w", err)
	}
	selected, err := parseConnectionConfirm(f.body)
	if err != nil {
		return err
	}
	switch selected {
	case protocolHybrid:
		c.Protocol = "HYBRID (TLS + CredSSP)"
	case protocolSSL:
		c.Protocol = "SSL (TLS only)"
	default:
		return fmt.Errorf("rdp: server selected unsupported security protocol 0x%x", selected)
	}
	c.logf("x224: server selected %s", c.Protocol)

	// 2. TLS.
	tlsCfg := c.cfg.TLS.Clone()
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.MaxVersion == 0 {
		// Windows Server 2025 aborts CredSSP with a TLS internal_error alert
		// when TLS 1.3 is negotiated; FreeRDP works there over TLS 1.2.
		tlsCfg.MaxVersion = tls.VersionTLS12
	}
	if tlsCfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(c.cfg.Addr)
		tlsCfg.ServerName = host
	}
	c.tls = tls.Client(c.conn, tlsCfg)
	if err := c.tls.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake: %w", err)
	}
	state := c.tls.ConnectionState()
	leaf := state.PeerCertificates[0]
	sum := sha256.Sum256(leaf.Raw)
	c.CertSHA256 = hex.EncodeToString(sum[:])
	c.logf("tls: %s, server certificate %q sha256=%s",
		tls.VersionName(state.Version), leaf.Subject.CommonName, c.CertSHA256)
	c.br = bufio.NewReader(c.tls)

	// 3. CredSSP / NLA.
	if selected == protocolHybrid {
		pub, err := credssp.SubjectPublicKey(leaf)
		if err != nil {
			return err
		}
		if err := credssp.Authenticate(c.tls, pub, credssp.Credentials{
			Domain: c.cfg.Domain, User: c.cfg.User, Password: c.cfg.Password,
		}); err != nil {
			return err
		}
		c.logf("credssp: authenticated")
	}

	// 4. MCS connect with GCC conference create.
	blocks := append(clientCoreData(c.cfg.Width, c.cfg.Height, c.cfg.ClientName, selected),
		clientSecurityData()...)
	blocks = append(blocks, clientNetworkData()...)
	blocks = append(blocks, clientClusterData(c.cfg.Console)...)
	if err := c.writeX224(mcsConnectInitial(gccConferenceCreateRequest(blocks))); err != nil {
		return err
	}
	p, err := c.readX224()
	if err != nil {
		return fmt.Errorf("rdp: reading MCS connect response: %w", err)
	}
	gcc, err := parseMCSConnectResponse(p)
	if err != nil {
		return err
	}
	sblocks, err := gccServerBlocks(gcc)
	if err != nil {
		return err
	}
	sd, err := parseServerData(sblocks)
	if err != nil {
		return err
	}
	if sd.encryptionLevel != 0 {
		return fmt.Errorf("rdp: server requires legacy RDP encryption (level %d) on top of TLS", sd.encryptionLevel)
	}
	c.ioChannel = sd.ioChannel
	c.ServerVersion = sd.version
	c.logf("mcs: connected, server version 0x%08x, I/O channel %d", sd.version, sd.ioChannel)

	// 5. Erect domain, attach user, join channels.
	if err := c.writeX224(mcsErectDomain()); err != nil {
		return err
	}
	if err := c.writeX224(mcsAttachUser()); err != nil {
		return err
	}
	if p, err = c.readX224(); err != nil {
		return err
	}
	if c.userID, err = parseAttachUserConfirm(p); err != nil {
		return err
	}
	for _, ch := range []uint16{c.userID, c.ioChannel} {
		if err := c.writeX224(mcsChannelJoin(c.userID, ch)); err != nil {
			return err
		}
		if p, err = c.readX224(); err != nil {
			return err
		}
		if err := parseChannelJoinConfirm(p, ch); err != nil {
			return err
		}
	}
	c.logf("mcs: user channel %d, joined channels %d and %d", c.userID, c.userID, c.ioChannel)

	// 6. Client Info (carries the logon credentials for the session).
	host, _, _ := net.SplitHostPort(c.conn.LocalAddr().String())
	if err := c.sendIO(clientInfoPDU(c.cfg.Domain, c.cfg.User, c.cfg.Password, host)); err != nil {
		return err
	}

	// 7. Licensing.
	data, err := c.readIO()
	if err != nil {
		return fmt.Errorf("rdp: waiting for licensing: %w", err)
	}
	r := newR(data)
	if flags := r.u16(); flags&secLicensePkt == 0 {
		return fmt.Errorf("rdp: expected licensing PDU, got security flags 0x%04x", flags)
	}
	r.u16() // flagsHi
	if err := parseLicensing(r.rest()); err != nil {
		return err
	}
	c.logf("license: server reports valid client")
	return nil
}

func (c *Conn) writeX224(p []byte) error {
	w := io.Writer(c.conn)
	if c.tls != nil {
		w = c.tls
	}
	_, err := w.Write(tpkt(x224Data(p)))
	return err
}

func (c *Conn) readX224() ([]byte, error) {
	for {
		f, err := readFrame(c.br)
		if err != nil {
			return nil, err
		}
		if f.fastPath {
			continue
		}
		if len(f.body) < 3 || f.body[1] != 0xF0 {
			return nil, fmt.Errorf("rdp: expected X.224 data TPDU")
		}
		return f.body[3:], nil
	}
}

func (c *Conn) sendIO(data []byte) error {
	return c.writeX224(mcsSendData(c.userID, c.ioChannel, data))
}

// ErrDisconnected is returned when the server ends the connection.
var ErrDisconnected = errors.New("rdp: server disconnected")

// readIO returns the next Send Data Indication payload on the I/O channel,
// skipping fast-path output and data on other channels.
func (c *Conn) readIO() ([]byte, error) {
	for {
		p, err := c.readX224()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, c.disconnectError()
			}
			return nil, err
		}
		r := newR(p)
		switch r.u8() >> 2 {
		case mcsSendDataIndication:
			r.u16be() // initiator
			ch := r.u16be()
			r.u8() // priority / segmentation
			n := perReadLen(r)
			data := r.take(n)
			if r.err != nil {
				return nil, fmt.Errorf("rdp: truncated MCS data indication")
			}
			if ch != c.ioChannel {
				c.logf("mcs: ignoring %d bytes on channel %d", len(data), ch)
				continue
			}
			return data, nil
		case mcsDisconnectProviderUltimatum:
			return nil, c.disconnectError()
		default:
			c.logf("mcs: ignoring PDU type %d", p[0]>>2)
		}
	}
}

func (c *Conn) disconnectError() error {
	if c.lastErrorInfo != 0 {
		return fmt.Errorf("%w (error info 0x%08x: %s)", ErrDisconnected,
			c.lastErrorInfo, errorInfoName(c.lastErrorInfo))
	}
	return ErrDisconnected
}

func (c *Conn) sendData(pduType2 uint8, body []byte) error {
	return c.sendIO(shareData(c.shareID, c.userID, pduType2, body))
}

// Event is something the session reported while running.
type Event struct {
	Activated  bool        // capability exchange and finalization completed
	LoggedOn   *LogonInfo  // the user session logon completed
	LogonError *LogonError // a logon error or warning
}

// Next processes server PDUs until something of interest happens.
func (c *Conn) Next() (Event, error) {
	for {
		data, err := c.readIO()
		if err != nil {
			return Event{}, err
		}
		r := newR(data)
		total := r.u16()
		if total == 0x8000 { // flow control PDU
			continue
		}
		pduType := r.u16() & 0x0F
		r.u16() // pduSource
		if r.err != nil {
			return Event{}, fmt.Errorf("rdp: truncated share control header")
		}
		switch pduType {
		case pduTypeDemandActive:
			if err := c.activate(r); err != nil {
				return Event{}, err
			}
		case pduTypeDeactivateAll:
			c.logf("share: deactivate all; waiting for reactivation")
		case pduTypeData:
			ev, ok, err := c.handleData(r)
			if err != nil {
				return Event{}, err
			}
			if ok {
				return ev, nil
			}
		case pduTypeServerRedir:
			return Event{}, fmt.Errorf("rdp: server requested redirection, which is not supported")
		default:
			c.logf("share: ignoring PDU type %d", pduType)
		}
	}
}

func (c *Conn) activate(r *rbuf) error {
	c.shareID = r.u32()
	srcLen := int(r.u16())
	r.u16() // lengthCombinedCapabilities
	r.skip(srcLen)
	n := r.u16()
	r.u16() // pad
	sc := parseServerCaps(r, n)
	if r.err != nil {
		return fmt.Errorf("rdp: truncated Demand Active PDU")
	}
	c.logf("share: demand active, share id 0x%08x, server capabilities: %s",
		c.shareID, strings.Join(sc.names, " "))
	width, height, bpp := c.cfg.Width, c.cfg.Height, uint16(16)
	if sc.bpp != 0 {
		width, height, bpp = sc.width, sc.height, sc.bpp
	}
	c.logf("share: session %dx%d at %d bpp", width, height, bpp)

	if err := c.sendIO(confirmActivePDU(c.shareID, c.userID, width, height, bpp)); err != nil {
		return err
	}
	for _, pdu := range []struct {
		t    uint8
		body []byte
	}{
		{pduType2Synchronize, synchronizeBody()},
		{pduType2Control, controlBody(ctrlActionCooperate)},
		{pduType2Control, controlBody(ctrlActionRequestControl)},
		{pduType2FontList, fontListBody()},
	} {
		if err := c.sendData(pdu.t, pdu.body); err != nil {
			return err
		}
	}
	c.logf("share: sent confirm active and finalization PDUs")
	return nil
}

func (c *Conn) handleData(r *rbuf) (Event, bool, error) {
	r.u32() // shareId
	r.u8()  // pad
	r.u8()  // streamId
	r.u16() // uncompressedLength
	pduType2 := r.u8()
	compressed := r.u8()
	r.u16() // compressedLength
	body := r.rest()
	if r.err != nil {
		return Event{}, false, fmt.Errorf("rdp: truncated share data header")
	}
	if compressed&0x20 != 0 { // PACKET_COMPRESSED
		c.logf("share: ignoring compressed %s PDU", pduType2Names[pduType2])
		return Event{}, false, nil
	}

	switch pduType2 {
	case pduType2FontMap:
		// Last PDU of connection finalization; stop display updates.
		if err := c.sendData(pduType2SuppressOutput, suppressOutputBody()); err != nil {
			return Event{}, false, err
		}
		c.logf("share: connection finalized")
		return Event{Activated: true}, true, nil
	case pduType2SaveSessionInfo:
		info, loggedOn, logonErr := parseSaveSessionInfo(body)
		if logonErr != nil {
			return Event{LogonError: logonErr}, true, nil
		}
		if loggedOn {
			return Event{LoggedOn: &info}, true, nil
		}
	case pduType2SetErrorInfo:
		br := newR(body)
		c.lastErrorInfo = br.u32()
		if c.lastErrorInfo != 0 {
			c.logf("share: error info 0x%08x (%s)", c.lastErrorInfo, errorInfoName(c.lastErrorInfo))
		}
	case pduType2Control:
		br := newR(body)
		c.logf("share: control action %d", br.u16())
	default:
		name := pduType2Names[pduType2]
		if name == "" {
			name = fmt.Sprintf("type %d", pduType2)
		}
		c.logf("share: data PDU %s (%d bytes)", name, len(body))
	}
	return Event{}, false, nil
}

// Disconnect tells the server this client is leaving: an MCS Disconnect
// Provider Ultimatum followed by a TLS close_notify. The user session is left
// running, disconnected, as when a normal RDP client window is closed.
//
// The server then closes the connection, which a goroutine blocked in Next
// observes as ErrDisconnected. Waiting for that before calling Close matters:
// a new connection that arrives while the server is still tearing this one
// down can be dropped right after activation.
func (c *Conn) Disconnect() error {
	if c.tls == nil {
		return nil
	}
	c.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := c.writeX224(mcsDisconnect()); err != nil {
		return err
	}
	return c.tls.CloseWrite()
}

// Close closes the network connection immediately.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Some common Set Error Info codes ([MS-RDPBCGR] 2.2.5.1.1).
var errorInfoNames = map[uint32]string{
	0x00000001: "ERRINFO_RPC_INITIATED_DISCONNECT",
	0x00000002: "ERRINFO_RPC_INITIATED_LOGOFF",
	0x00000003: "ERRINFO_IDLE_TIMEOUT",
	0x00000004: "ERRINFO_LOGON_TIMEOUT",
	0x00000005: "ERRINFO_DISCONNECTED_BY_OTHERCONNECTION",
	0x00000006: "ERRINFO_OUT_OF_MEMORY",
	0x00000007: "ERRINFO_SERVER_DENIED_CONNECTION",
	0x00000009: "ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES",
	0x0000000A: "ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED",
	0x0000000B: "ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER",
	0x0000000C: "ERRINFO_LOGOFF_BY_USER",
	0x000010C9: "ERRINFO_UNKNOWN_DATA_PDU_TYPE",
	0x000010CA: "ERRINFO_UNKNOWN_PDU_TYPE",
	0x000010CB: "ERRINFO_DATA_PDU_SEQUENCE",
	0x000010CD: "ERRINFO_CONTROL_PDU_SEQUENCE",
	0x000010D4: "ERRINFO_CONFIRM_ACTIVE_WRONG_SHAREID",
	0x000010D5: "ERRINFO_CONFIRM_ACTIVE_WRONG_ORIGINATOR",
	0x000010E2: "ERRINFO_SHARE_DATA_TOO_SHORT",
	0x000010E3: "ERRINFO_BAD_SUPPRESS_OUTPUT_PDU",
	0x000010E5: "ERRINFO_CONFIRM_ACTIVE_PDU_TOO_SHORT",
	0x000010E7: "ERRINFO_CAPABILITY_SET_TOO_SMALL",
	0x000010E8: "ERRINFO_CAPABILITY_SET_TOO_LARGE",
	0x000010E9: "ERRINFO_NO_CURSOR_CACHE",
	0x000010EA: "ERRINFO_BAD_CAPABILITIES",
}

func errorInfoName(code uint32) string {
	if n, ok := errorInfoNames[code]; ok {
		return n
	}
	return "see MS-RDPBCGR 2.2.5.1.1"
}
