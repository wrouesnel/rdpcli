package credssp

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestTSRequestOmitsEmptyFields(t *testing.T) {
	b, err := asn1.Marshal(tsRequestOut{Version: 6, NegoTokens: []negoToken{{[]byte{1, 2}}}})
	if err != nil {
		t.Fatal(err)
	}
	// SEQUENCE { [0] INTEGER 6, [1] SEQUENCE OF SEQUENCE { [0] OCTET STRING 0102 } }
	want := []byte{0x30, 0x11,
		0xa0, 0x03, 0x02, 0x01, 0x06,
		0xa1, 0x0a, 0x30, 0x08, 0x30, 0x06, 0xa0, 0x04, 0x04, 0x02, 0x01, 0x02}
	if !bytes.Equal(b, want) {
		t.Fatalf("got  %x\nwant %x", b, want)
	}
}

func TestReadDERAndErrorCode(t *testing.T) {
	type withErr struct {
		Version   int   `asn1:"explicit,tag:0"`
		ErrorCode int64 `asn1:"explicit,optional,tag:4"`
	}
	b, err := asn1.Marshal(withErr{Version: 6, ErrorCode: 0xC000006D})
	if err != nil {
		t.Fatal(err)
	}
	_, err = recv(bytes.NewReader(b))
	cerr, ok := err.(*Error)
	if !ok || cerr.Status != 0xC000006D {
		t.Fatalf("got %v, want STATUS_LOGON_FAILURE", err)
	}
}
