// Package credssp implements the client side of the Credential Security
// Support Provider protocol ([MS-CSSP]) over an established TLS connection,
// using NTLM as the authentication package. This is the "NLA" step of an RDP
// connection.
package credssp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"

	"github.com/wrouesnel/rdpcli/internal/ntlm"
)

// clientVersion is the TSRequest version this client speaks.
const clientVersion = 6

const (
	clientServerHashMagic = "CredSSP Client-To-Server Binding Hash\x00"
	serverClientHashMagic = "CredSSP Server-To-Client Binding Hash\x00"
)

// Credentials are the password credentials delegated to the server.
type Credentials struct {
	Domain   string
	User     string
	Password string
}

type negoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

// tsRequestOut is the TSRequest as this client sends it. It has no
// errorCode field so that one is never sent.
type tsRequestOut struct {
	Version     int         `asn1:"explicit,tag:0"`
	NegoTokens  []negoToken `asn1:"explicit,optional,omitempty,tag:1"`
	AuthInfo    []byte      `asn1:"explicit,optional,omitempty,tag:2"`
	PubKeyAuth  []byte      `asn1:"explicit,optional,omitempty,tag:3"`
	ClientNonce []byte      `asn1:"explicit,optional,omitempty,tag:5"`
}

// tsRequestIn is the TSRequest as received from the server.
type tsRequestIn struct {
	Version     int         `asn1:"explicit,tag:0"`
	NegoTokens  []negoToken `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte      `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte      `asn1:"explicit,optional,tag:3"`
	ErrorCode   int64       `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte      `asn1:"explicit,optional,tag:5"`
}

type tsCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

type tsPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

// Error is a failure reported by the server in a TSRequest errorCode.
type Error struct {
	Status uint32 // NTSTATUS
}

func (e *Error) Error() string {
	name := ntstatusNames[e.Status]
	if name == "" {
		name = "unknown status"
	}
	return fmt.Sprintf("credssp: server rejected authentication: %s (0x%08X)", name, e.Status)
}

var ntstatusNames = map[uint32]string{
	0xC000006D: "STATUS_LOGON_FAILURE",
	0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
	0xC000006F: "STATUS_INVALID_LOGON_HOURS",
	0xC0000070: "STATUS_INVALID_WORKSTATION",
	0xC0000071: "STATUS_PASSWORD_EXPIRED",
	0xC0000072: "STATUS_ACCOUNT_DISABLED",
	0xC0000193: "STATUS_ACCOUNT_EXPIRED",
	0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
	0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
	0xC0000413: "STATUS_AUTHENTICATION_FIREWALL_FAILED",
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

// SubjectPublicKey returns the subjectPublicKey bytes of a certificate,
// which is what CredSSP binds the authentication to.
func SubjectPublicKey(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("credssp: parsing server public key: %w", err)
	}
	return spki.PublicKey.Bytes, nil
}

// readDER reads one complete DER element from r.
func readDER(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, fmt.Errorf("credssp: expected SEQUENCE, got tag 0x%02x", hdr[0])
	}
	n := int(hdr[1])
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 {
			return nil, errors.New("credssp: bad DER length")
		}
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		hdr = append(hdr, lb...)
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func send(w io.Writer, req tsRequestOut) error {
	b, err := asn1.Marshal(req)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func recv(r io.Reader) (*tsRequestIn, error) {
	b, err := readDER(r)
	if err != nil {
		return nil, fmt.Errorf("credssp: reading TSRequest: %w", err)
	}
	var req tsRequestIn
	if _, err := asn1.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("credssp: parsing TSRequest: %w", err)
	}
	if req.ErrorCode != 0 {
		return nil, &Error{Status: uint32(req.ErrorCode)}
	}
	return &req, nil
}

// Authenticate runs CredSSP over conn (the TLS connection to the server).
// serverPublicKey is the subjectPublicKey of the server's TLS certificate.
func Authenticate(conn io.ReadWriter, serverPublicKey []byte, creds Credentials) error {
	nt := &ntlm.Client{User: creds.User, Domain: creds.Domain, Password: creds.Password}

	// 1. NEGOTIATE
	if err := send(conn, tsRequestOut{Version: clientVersion,
		NegoTokens: []negoToken{{nt.Negotiate()}}}); err != nil {
		return err
	}

	// 2. CHALLENGE
	resp, err := recv(conn)
	if err != nil {
		return err
	}
	if len(resp.NegoTokens) == 0 {
		return errors.New("credssp: server sent no NTLM challenge")
	}
	version := min(resp.Version, clientVersion)
	authMsg, err := nt.Authenticate(resp.NegoTokens[0].Token)
	if err != nil {
		return err
	}

	// 3. AUTHENTICATE + pubKeyAuth binding the TLS key to this exchange.
	var nonce, clientBinding []byte
	if version >= 5 {
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		h := sha256.Sum256(bytes.Join([][]byte{[]byte(clientServerHashMagic), nonce, serverPublicKey}, nil))
		clientBinding = h[:]
	} else {
		clientBinding = serverPublicKey
	}
	pubKeyAuth, err := nt.Seal(clientBinding)
	if err != nil {
		return err
	}
	if err := send(conn, tsRequestOut{Version: clientVersion,
		NegoTokens: []negoToken{{authMsg}}, PubKeyAuth: pubKeyAuth, ClientNonce: nonce}); err != nil {
		return err
	}

	// 4. Server proves it holds the same key and session.
	resp, err = recv(conn)
	if err != nil {
		return err
	}
	got, err := nt.Unseal(resp.PubKeyAuth)
	if err != nil {
		return fmt.Errorf("credssp: verifying server pubKeyAuth: %w", err)
	}
	var want []byte
	if version >= 5 {
		h := sha256.Sum256(bytes.Join([][]byte{[]byte(serverClientHashMagic), nonce, serverPublicKey}, nil))
		want = h[:]
	} else {
		want = append([]byte{}, serverPublicKey...)
		want[0]++
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("credssp: server public key binding mismatch (possible TLS interception)")
	}

	// 5. Delegate the password credentials.
	pw, err := asn1.Marshal(tsPasswordCreds{
		DomainName: utf16le(creds.Domain),
		UserName:   utf16le(creds.User),
		Password:   utf16le(creds.Password),
	})
	if err != nil {
		return err
	}
	tc, err := asn1.Marshal(tsCredentials{CredType: 1, Credentials: pw})
	if err != nil {
		return err
	}
	authInfo, err := nt.Seal(tc)
	if err != nil {
		return err
	}
	return send(conn, tsRequestOut{Version: clientVersion, AuthInfo: authInfo})
}
