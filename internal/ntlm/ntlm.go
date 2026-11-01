// Package ntlm implements the client side of NTLMv2 authentication with
// extended session security, signing and sealing, as specified in [MS-NLMP].
// It provides exactly what CredSSP needs: the three-message handshake and
// message sealing/unsealing.
package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Negotiate flags ([MS-NLMP] 2.2.2.5).
const (
	FlagUnicode                        = 0x00000001
	FlagRequestTarget                  = 0x00000004
	FlagSign                           = 0x00000010
	FlagSeal                           = 0x00000020
	FlagNTLM                           = 0x00000200
	FlagAlwaysSign                     = 0x00008000
	FlagExtendedSessionSecurity        = 0x00080000
	FlagTargetInfo                     = 0x00800000
	FlagVersion                        = 0x02000000
	Flag128                            = 0x20000000
	FlagKeyExch                        = 0x40000000
	Flag56                             = 0x80000000
	defaultFlags                uint32 = Flag56 | FlagKeyExch | Flag128 | FlagVersion | FlagTargetInfo |
		FlagExtendedSessionSecurity | FlagAlwaysSign | FlagNTLM | FlagSeal | FlagSign |
		FlagRequestTarget | FlagUnicode
)

// AV pair IDs ([MS-NLMP] 2.2.2.1).
const (
	avEOL       = 0x0000
	avFlags     = 0x0006
	avTimestamp = 0x0007
)

const avFlagMICPresent = 0x00000002

var signature = []byte("NTLMSSP\x00")

// version is the 8-byte VERSION structure sent in our messages.
var version = []byte{10, 0, 0x61, 0x4a, 0, 0, 0, 0x0f}

// Client is one NTLM client security context.
type Client struct {
	User        string
	Domain      string
	Password    string
	Workstation string

	// Rand and Now may be overridden for testing.
	Rand io.Reader
	Now  func() time.Time

	negotiateMsg []byte
	challengeMsg []byte

	sessionKey  []byte
	clientSign  []byte
	serverSign  []byte
	clientSeal  *rc4.Cipher
	serverSeal  *rc4.Cipher
	sendSeq     uint32
	recvSeq     uint32
	established bool
}

func (c *Client) rand() io.Reader {
	if c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Negotiate returns the NEGOTIATE_MESSAGE.
func (c *Client) Negotiate() []byte {
	m := make([]byte, 0, 40)
	m = append(m, signature...)
	m = binary.LittleEndian.AppendUint32(m, 1)
	m = binary.LittleEndian.AppendUint32(m, defaultFlags)
	m = append(m, make([]byte, 16)...) // domain and workstation fields: empty
	m = append(m, version...)
	c.negotiateMsg = m
	return m
}

type avPair struct {
	id    uint16
	value []byte
}

func parseAVPairs(b []byte) ([]avPair, error) {
	var out []avPair
	for {
		if len(b) < 4 {
			return nil, errors.New("ntlm: truncated target info")
		}
		id := binary.LittleEndian.Uint16(b)
		n := int(binary.LittleEndian.Uint16(b[2:]))
		b = b[4:]
		if id == avEOL {
			return out, nil
		}
		if len(b) < n {
			return nil, errors.New("ntlm: truncated AV pair")
		}
		out = append(out, avPair{id, b[:n]})
		b = b[n:]
	}
}

func encodeAVPairs(pairs []avPair) []byte {
	var out []byte
	for _, p := range pairs {
		out = binary.LittleEndian.AppendUint16(out, p.id)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(p.value)))
		out = append(out, p.value...)
	}
	return append(out, 0, 0, 0, 0)
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func hmacMD5(key []byte, data ...[]byte) []byte {
	h := hmac.New(md5.New, key)
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// NTOWFv2 computes the NTLMv2 one-way function of the credentials.
func NTOWFv2(password, user, domain string) []byte {
	h := md4.New()
	h.Write(utf16le(password))
	return hmacMD5(h.Sum(nil), utf16le(strings.ToUpper(user)+domain))
}

func filetime(t time.Time) []byte {
	// 100ns intervals since 1601-01-01.
	ft := uint64(t.UnixNano()/100) + 116444736000000000
	return binary.LittleEndian.AppendUint64(nil, ft)
}

// v2Response holds the computed NTLMv2 responses and keys.
type v2Response struct {
	nt, lm, sessionBaseKey []byte
}

// computeV2 implements ComputeResponse for NTLMv2 ([MS-NLMP] 3.3.2).
// serverName is the (possibly modified) target info sent back to the server.
func computeV2(ntowf, serverChallenge, clientChallenge, timestamp, serverName []byte, zeroLM bool) v2Response {
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, serverName...)
	temp = append(temp, 0, 0, 0, 0)

	ntProof := hmacMD5(ntowf, serverChallenge, temp)
	r := v2Response{
		nt:             append(append([]byte{}, ntProof...), temp...),
		sessionBaseKey: hmacMD5(ntowf, ntProof),
	}
	if zeroLM {
		r.lm = make([]byte, 24)
	} else {
		r.lm = append(hmacMD5(ntowf, serverChallenge, clientChallenge), clientChallenge...)
	}
	return r
}

// Authenticate processes the server's CHALLENGE_MESSAGE and returns the
// AUTHENTICATE_MESSAGE. After it succeeds, Seal and Unseal may be used.
func (c *Client) Authenticate(challenge []byte) ([]byte, error) {
	if c.negotiateMsg == nil {
		return nil, errors.New("ntlm: Negotiate not called")
	}
	if len(challenge) < 48 || !bytes.Equal(challenge[:8], signature) ||
		binary.LittleEndian.Uint32(challenge[8:]) != 2 {
		return nil, errors.New("ntlm: not a CHALLENGE_MESSAGE")
	}
	c.challengeMsg = append([]byte{}, challenge...)

	flags := binary.LittleEndian.Uint32(challenge[20:])
	if flags&FlagExtendedSessionSecurity == 0 {
		return nil, errors.New("ntlm: server does not support extended session security")
	}
	serverChallenge := challenge[24:32]
	tiLen := int(binary.LittleEndian.Uint16(challenge[40:]))
	tiOff := int(binary.LittleEndian.Uint32(challenge[44:]))
	if tiOff+tiLen > len(challenge) {
		return nil, errors.New("ntlm: target info out of range")
	}
	pairs, err := parseAVPairs(challenge[tiOff : tiOff+tiLen])
	if err != nil {
		return nil, err
	}

	// Build the target info we echo back: the server's pairs, with the
	// MIC-present flag set when the server supplied a timestamp.
	var timestamp []byte
	var avFlagsValue uint32
	var echo []avPair
	for _, p := range pairs {
		switch p.id {
		case avTimestamp:
			timestamp = p.value
			echo = append(echo, p)
		case avFlags:
			if len(p.value) >= 4 {
				avFlagsValue = binary.LittleEndian.Uint32(p.value)
			}
		default:
			echo = append(echo, p)
		}
	}
	useMIC := timestamp != nil
	if useMIC {
		avFlagsValue |= avFlagMICPresent
	}
	if avFlagsValue != 0 {
		echo = append(echo, avPair{avFlags, binary.LittleEndian.AppendUint32(nil, avFlagsValue)})
	}
	if timestamp == nil {
		timestamp = filetime(c.now())
	}

	clientChallenge := make([]byte, 8)
	if _, err := io.ReadFull(c.rand(), clientChallenge); err != nil {
		return nil, err
	}
	resp := computeV2(NTOWFv2(c.Password, c.User, c.Domain), serverChallenge, clientChallenge,
		timestamp, encodeAVPairs(echo), useMIC)

	// With NTLMv2, KeyExchangeKey is the session base key.
	exported := resp.sessionBaseKey
	var encryptedKey []byte
	if flags&FlagKeyExch != 0 {
		exported = make([]byte, 16)
		if _, err := io.ReadFull(c.rand(), exported); err != nil {
			return nil, err
		}
		ciph, _ := rc4.NewCipher(resp.sessionBaseKey)
		encryptedKey = make([]byte, 16)
		ciph.XORKeyStream(encryptedKey, exported)
	}

	msg := c.buildAuthenticate(flags, resp, encryptedKey)
	if useMIC {
		mic := hmacMD5(exported, c.negotiateMsg, c.challengeMsg, msg)
		copy(msg[72:88], mic)
	}
	c.deriveKeys(exported)
	return msg, nil
}

func (c *Client) buildAuthenticate(flags uint32, resp v2Response, encryptedKey []byte) []byte {
	const headerLen = 88
	fields := [][]byte{
		resp.lm,
		resp.nt,
		utf16le(c.Domain),
		utf16le(c.User),
		utf16le(c.Workstation),
		encryptedKey,
	}
	// Payload order: domain, user, workstation, lm, nt, session key.
	order := []int{2, 3, 4, 0, 1, 5}
	offsets := make([]int, len(fields))
	off := headerLen
	for _, i := range order {
		offsets[i] = off
		off += len(fields[i])
	}

	m := make([]byte, 0, off)
	m = append(m, signature...)
	m = binary.LittleEndian.AppendUint32(m, 3)
	for i, f := range fields {
		m = binary.LittleEndian.AppendUint16(m, uint16(len(f)))
		m = binary.LittleEndian.AppendUint16(m, uint16(len(f)))
		m = binary.LittleEndian.AppendUint32(m, uint32(offsets[i]))
	}
	m = binary.LittleEndian.AppendUint32(m, flags)
	m = append(m, version...)
	m = append(m, make([]byte, 16)...) // MIC, filled in later
	for _, i := range order {
		m = append(m, fields[i]...)
	}
	return m
}

func (c *Client) deriveKeys(exported []byte) {
	md := func(magic string) []byte {
		h := md5.Sum(append(append([]byte{}, exported...), magic...))
		return h[:]
	}
	c.sessionKey = exported
	c.clientSign = md("session key to client-to-server signing key magic constant\x00")
	c.serverSign = md("session key to server-to-client signing key magic constant\x00")
	c.clientSeal, _ = rc4.NewCipher(md("session key to client-to-server sealing key magic constant\x00"))
	c.serverSeal, _ = rc4.NewCipher(md("session key to server-to-client sealing key magic constant\x00"))
	c.sendSeq, c.recvSeq = 0, 0
	c.established = true
}

// Seal encrypts msg and returns signature (16 bytes) || ciphertext, the form
// CredSSP uses for pubKeyAuth and authInfo.
func (c *Client) Seal(msg []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("ntlm: context not established")
	}
	seq := binary.LittleEndian.AppendUint32(nil, c.sendSeq)
	c.sendSeq++
	out := make([]byte, 16+len(msg))
	c.clientSeal.XORKeyStream(out[16:], msg)
	checksum := hmacMD5(c.clientSign, seq, msg)[:8]
	binary.LittleEndian.PutUint32(out, 1)
	c.clientSeal.XORKeyStream(out[4:12], checksum)
	copy(out[12:16], seq)
	return out, nil
}

// Unseal decrypts and verifies a sealed message from the server.
func (c *Client) Unseal(data []byte) ([]byte, error) {
	if !c.established {
		return nil, errors.New("ntlm: context not established")
	}
	if len(data) < 16 {
		return nil, errors.New("ntlm: sealed message too short")
	}
	seq := binary.LittleEndian.AppendUint32(nil, c.recvSeq)
	c.recvSeq++
	msg := make([]byte, len(data)-16)
	c.serverSeal.XORKeyStream(msg, data[16:])
	checksum := make([]byte, 8)
	c.serverSeal.XORKeyStream(checksum, data[4:12])
	want := hmacMD5(c.serverSign, seq, msg)[:8]
	if binary.LittleEndian.Uint32(data) != 1 ||
		subtle.ConstantTimeCompare(checksum, want) != 1 ||
		!bytes.Equal(data[12:16], seq) {
		return nil, fmt.Errorf("ntlm: message signature check failed")
	}
	return msg, nil
}
