package rdp

import (
	"bytes"
	"errors"
	"fmt"
)

// T.125 MCS and T.124 GCC encoding, limited to what an RDP client needs.

// MCS DomainMCSPDU choice indexes (PER, top 6 bits of the first byte).
const (
	mcsErectDomainRequest          = 1
	mcsDisconnectProviderUltimatum = 8
	mcsAttachUserRequest           = 10
	mcsAttachUserConfirm           = 11
	mcsChannelJoinRequest          = 14
	mcsChannelJoinConfirm          = 15
	mcsSendDataRequest             = 25
	mcsSendDataIndication          = 26
)

const mcsBaseChannelID = 1001

// --- BER -------------------------------------------------------------------

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func berTLV(tag []byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	out := append(append([]byte{}, tag...), berLen(len(c))...)
	return append(out, c...)
}

func berInt(v int) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if v == 0 {
			break
		}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return berTLV([]byte{0x02}, b)
}

func berDomainParameters(v ...int) []byte {
	var parts [][]byte
	for _, x := range v {
		parts = append(parts, berInt(x))
	}
	return berTLV([]byte{0x30}, parts...)
}

// berRead reads one BER TLV, returning its tag bytes and contents.
func berRead(r *rbuf) (tag []byte, content []byte) {
	start := r.off
	t := r.u8()
	if t&0x1f == 0x1f {
		for {
			b := r.u8()
			if r.err != nil || b&0x80 == 0 {
				break
			}
		}
	}
	tag = r.b[start:min(r.off, len(r.b))]
	n := int(r.u8())
	if n&0x80 != 0 {
		k := n & 0x7f
		n = 0
		for i := 0; i < k; i++ {
			n = n<<8 | int(r.u8())
		}
	}
	return tag, r.take(n)
}

// mcsConnectInitial builds the MCS Connect-Initial PDU carrying GCC user data.
func mcsConnectInitial(userData []byte) []byte {
	return berTLV([]byte{0x7f, 0x65},
		berTLV([]byte{0x04}, []byte{1}),    // callingDomainSelector
		berTLV([]byte{0x04}, []byte{1}),    // calledDomainSelector
		berTLV([]byte{0x01}, []byte{0xff}), // upwardFlag
		berDomainParameters(34, 2, 0, 1, 0, 1, 0xffff, 2),
		berDomainParameters(1, 1, 1, 1, 0, 1, 0x420, 2),
		berDomainParameters(0xffff, 0xfc17, 0xffff, 1, 0, 1, 0xffff, 2),
		berTLV([]byte{0x04}, userData),
	)
}

// parseMCSConnectResponse returns the GCC user data of a Connect-Response.
func parseMCSConnectResponse(p []byte) ([]byte, error) {
	tag, body := berRead(newR(p))
	if !bytes.Equal(tag, []byte{0x7f, 0x66}) {
		return nil, fmt.Errorf("rdp: expected MCS Connect-Response, got tag %x", tag)
	}
	r := newR(body)
	_, result := berRead(r)
	if len(result) != 1 || result[0] != 0 {
		return nil, fmt.Errorf("rdp: MCS connect failed, result %x", result)
	}
	berRead(r) // calledConnectId
	berRead(r) // domainParameters
	_, userData := berRead(r)
	if r.err != nil {
		return nil, fmt.Errorf("rdp: malformed MCS Connect-Response: %w", r.err)
	}
	return userData, nil
}

// --- PER / domain PDUs ------------------------------------------------------

func perLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(n>>8), byte(n)}
}

func perReadLen(r *rbuf) int {
	b := int(r.u8())
	if b&0x80 == 0 {
		return b
	}
	return (b&0x7f)<<8 | int(r.u8())
}

func mcsErectDomain() []byte {
	return []byte{mcsErectDomainRequest << 2, 0x01, 0x00, 0x01, 0x00}
}

func mcsAttachUser() []byte {
	return []byte{mcsAttachUserRequest << 2}
}

func mcsChannelJoin(userID, channelID uint16) []byte {
	var w wbuf
	w.u8(mcsChannelJoinRequest << 2)
	w.u16be(userID - mcsBaseChannelID)
	w.u16be(channelID)
	return w.b
}

func mcsSendData(userID, channelID uint16, data []byte) []byte {
	var w wbuf
	w.u8(mcsSendDataRequest << 2)
	w.u16be(userID - mcsBaseChannelID)
	w.u16be(channelID)
	w.u8(0x70) // high priority, begin and end of segment
	w.bytes(perLen(len(data))...)
	w.bytes(data...)
	return w.b
}

func mcsDisconnect() []byte {
	// DisconnectProviderUltimatum, reason rn-user-requested.
	return []byte{mcsDisconnectProviderUltimatum<<2 | 0x01, 0x80}
}

func parseAttachUserConfirm(p []byte) (uint16, error) {
	r := newR(p)
	if r.u8()>>2 != mcsAttachUserConfirm {
		return 0, errors.New("rdp: expected MCS Attach-User-Confirm")
	}
	if res := r.u8(); res != 0 {
		return 0, fmt.Errorf("rdp: attach user failed, result %d", res)
	}
	id := r.u16be()
	if r.err != nil {
		return 0, errors.New("rdp: short Attach-User-Confirm")
	}
	return id + mcsBaseChannelID, nil
}

func parseChannelJoinConfirm(p []byte, want uint16) error {
	r := newR(p)
	if r.u8()>>2 != mcsChannelJoinConfirm {
		return errors.New("rdp: expected MCS Channel-Join-Confirm")
	}
	res := r.u8()
	r.u16be() // initiator
	req := r.u16be()
	if r.err != nil {
		return errors.New("rdp: short Channel-Join-Confirm")
	}
	if res != 0 {
		return fmt.Errorf("rdp: join of channel %d failed, result %d", want, res)
	}
	if req != want {
		return fmt.Errorf("rdp: join confirm for channel %d, wanted %d", req, want)
	}
	return nil
}

// --- GCC ---------------------------------------------------------------------

// gccConferenceCreateRequest wraps client data blocks in a GCC Conference
// Create Request ([MS-RDPBCGR] 2.2.1.3, T.124).
func gccConferenceCreateRequest(blocks []byte) []byte {
	var ccr wbuf
	ccr.bytes(0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 'D', 'u', 'c', 'a')
	ccr.bytes(perLen(len(blocks))...)
	ccr.bytes(blocks...)

	var out wbuf
	out.bytes(0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01) // T.124 object identifier
	out.bytes(perLen(len(ccr.b))...)
	out.bytes(ccr.b...)
	return out.b
}

// gccServerBlocks extracts the server data blocks from a GCC Conference
// Create Response, which follow the "McDn" H.221 key.
func gccServerBlocks(p []byte) ([]byte, error) {
	i := bytes.Index(p, []byte("McDn"))
	if i < 0 {
		return nil, errors.New("rdp: no server data in GCC Conference Create Response")
	}
	r := newR(p[i+4:])
	n := perReadLen(r)
	blocks := r.take(n)
	if r.err != nil {
		return nil, errors.New("rdp: truncated GCC server data")
	}
	return blocks, nil
}
