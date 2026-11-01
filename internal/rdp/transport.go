package rdp

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Requested security protocols for RDP_NEG_REQ ([MS-RDPBCGR] 2.2.1.1.1).
const (
	protocolRDP    = 0x00000000
	protocolSSL    = 0x00000001
	protocolHybrid = 0x00000002
)

// tpkt wraps payload in a TPKT header (RFC 1006).
func tpkt(payload []byte) []byte {
	out := make([]byte, 4, 4+len(payload))
	out[0] = 3
	binary.BigEndian.PutUint16(out[2:], uint16(4+len(payload)))
	return append(out, payload...)
}

// x224Data wraps payload in an X.224 Data TPDU header.
func x224Data(payload []byte) []byte {
	return append([]byte{0x02, 0xF0, 0x80}, payload...)
}

// frame is one PDU read off the wire: either a slow-path (TPKT) PDU or a
// fast-path output PDU.
type frame struct {
	fastPath bool
	header   byte   // fast-path header byte
	body     []byte // TPKT payload, or fast-path PDU body
}

func readFrame(r *bufio.Reader) (frame, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return frame{}, err
	}
	if b0 == 3 {
		var h [3]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return frame{}, err
		}
		n := int(binary.BigEndian.Uint16(h[1:]))
		if n < 4 {
			return frame{}, fmt.Errorf("rdp: bad TPKT length %d", n)
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return frame{}, err
		}
		return frame{body: body}, nil
	}
	if b0&0x03 != 0 {
		return frame{}, fmt.Errorf("rdp: unexpected frame header byte 0x%02x", b0)
	}
	l1, err := r.ReadByte()
	if err != nil {
		return frame{}, err
	}
	n, hdrLen := int(l1), 2
	if l1&0x80 != 0 {
		l2, err := r.ReadByte()
		if err != nil {
			return frame{}, err
		}
		n, hdrLen = int(l1&0x7f)<<8|int(l2), 3
	}
	if n < hdrLen {
		return frame{}, fmt.Errorf("rdp: bad fast-path length %d", n)
	}
	body := make([]byte, n-hdrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return frame{}, err
	}
	return frame{fastPath: true, header: b0, body: body}, nil
}

// x224ConnectionRequest builds the X.224 Connection Request TPDU carrying
// the routing cookie and an RDP Negotiation Request.
func x224ConnectionRequest(cookieUser string, protocols uint32) []byte {
	var body wbuf
	body.bytes(0xE0, 0, 0, 0, 0, 0) // CR, dst-ref, src-ref, class 0
	if cookieUser != "" {
		if len(cookieUser) > 9 {
			cookieUser = cookieUser[:9]
		}
		body.bytes([]byte("Cookie: mstshash=" + cookieUser + "\r\n")...)
	}
	body.bytes(0x01, 0x00) // TYPE_RDP_NEG_REQ, flags
	body.u16(8)
	body.u32(protocols)
	return append([]byte{byte(len(body.b))}, body.b...)
}

// negFailureNames maps RDP_NEG_FAILURE codes ([MS-RDPBCGR] 2.2.1.2.2).
var negFailureNames = map[uint32]string{
	1: "SSL_REQUIRED_BY_SERVER",
	2: "SSL_NOT_ALLOWED_BY_SERVER",
	3: "SSL_CERT_NOT_ON_SERVER",
	4: "INCONSISTENT_FLAGS",
	5: "HYBRID_REQUIRED_BY_SERVER",
	6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

// parseConnectionConfirm returns the security protocol the server selected.
func parseConnectionConfirm(p []byte) (uint32, error) {
	if len(p) < 7 || p[1]&0xF0 != 0xD0 {
		return 0, errors.New("rdp: expected X.224 Connection Confirm")
	}
	li := int(p[0])
	if li <= 6 || len(p) < 15 {
		return 0, errors.New("rdp: server did not negotiate (legacy RDP security is not supported)")
	}
	switch p[7] {
	case 0x02: // TYPE_RDP_NEG_RSP
		return binary.LittleEndian.Uint32(p[11:15]), nil
	case 0x03: // TYPE_RDP_NEG_FAILURE
		code := binary.LittleEndian.Uint32(p[11:15])
		return 0, fmt.Errorf("rdp: server refused negotiation: %s (%d)", negFailureNames[code], code)
	default:
		return 0, fmt.Errorf("rdp: unknown negotiation response type 0x%02x", p[7])
	}
}
