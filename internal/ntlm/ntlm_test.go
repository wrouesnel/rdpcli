package ntlm

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from [MS-NLMP] section 4.2.4 (NTLMv2 authentication).
var (
	tvUser            = "User"
	tvDomain          = "Domain"
	tvPassword        = "Password"
	tvServerChallenge = mustHex("0123456789abcdef")
	tvClientChallenge = mustHex("aaaaaaaaaaaaaaaa")
	tvTime            = make([]byte, 8)
	// MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", MsvAvEOL.
	tvTargetInfo = mustHex("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestNTOWFv2(t *testing.T) {
	got := NTOWFv2(tvPassword, tvUser, tvDomain)
	want := mustHex("0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got, want) {
		t.Fatalf("NTOWFv2 = %x, want %x", got, want)
	}
}

func TestComputeV2(t *testing.T) {
	ntowf := NTOWFv2(tvPassword, tvUser, tvDomain)
	r := computeV2(ntowf, tvServerChallenge, tvClientChallenge, tvTime, tvTargetInfo, false)

	if want := mustHex("68cd0ab851e51c96aabc927bebef6a1c"); !bytes.Equal(r.nt[:16], want) {
		t.Errorf("NTProofStr = %x, want %x", r.nt[:16], want)
	}
	if want := mustHex("8de40ccadbc14a82f15cb0ad0de95ca3"); !bytes.Equal(r.sessionBaseKey, want) {
		t.Errorf("SessionBaseKey = %x, want %x", r.sessionBaseKey, want)
	}
	if want := mustHex("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"); !bytes.Equal(r.lm, want) {
		t.Errorf("LMv2 response = %x, want %x", r.lm, want)
	}
}

func TestAVPairsRoundTrip(t *testing.T) {
	pairs, err := parseAVPairs(tvTargetInfo)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 {
		t.Fatalf("got %d pairs, want 2", len(pairs))
	}
	if got := encodeAVPairs(pairs); !bytes.Equal(got, tvTargetInfo) {
		t.Fatalf("re-encoded target info = %x", got)
	}
}

// TestSealRoundTrip checks that a client and a mirrored "server" context
// agree on sealing, using the same exported session key.
func TestSealRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 16)
	client := &Client{}
	client.deriveKeys(key)

	// A server context is the client context with directions swapped.
	server := &Client{}
	server.deriveKeys(key)
	server.clientSign, server.serverSign = server.serverSign, server.clientSign
	server.clientSeal, server.serverSeal = server.serverSeal, server.clientSeal

	for i, msg := range []string{"Plaintext", "second message", ""} {
		sealed, err := client.Seal([]byte(msg))
		if err != nil {
			t.Fatal(err)
		}
		got, err := server.Unseal(sealed)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(got) != msg {
			t.Fatalf("message %d: got %q, want %q", i, got, msg)
		}
	}

	sealed, _ := client.Seal([]byte("tamper"))
	sealed[len(sealed)-1] ^= 1
	if _, err := server.Unseal(sealed); err == nil {
		t.Fatal("tampered message was accepted")
	}
}
