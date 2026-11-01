package rdp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestX224ConnectionRequest(t *testing.T) {
	got := x224ConnectionRequest("someuser1234", protocolSSL|protocolHybrid)
	cookie := "Cookie: mstshash=someuser1\r\n" // truncated to 9 characters
	want := []byte{byte(6 + len(cookie) + 8), 0xE0, 0, 0, 0, 0, 0}
	want = append(want, cookie...)
	want = append(want, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)
	if !bytes.Equal(got, want) {
		t.Fatalf("got  %x\nwant %x", got, want)
	}
}

func TestParseConnectionConfirm(t *testing.T) {
	ok := []byte{0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x02, 0x1f, 0x08, 0x00, 0x02, 0, 0, 0}
	if p, err := parseConnectionConfirm(ok); err != nil || p != protocolHybrid {
		t.Fatalf("got %d, %v; want HYBRID", p, err)
	}
	fail := []byte{0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 0x03, 0x00, 0x08, 0x00, 0x05, 0, 0, 0}
	if _, err := parseConnectionConfirm(fail); err == nil ||
		!bytes.Contains([]byte(err.Error()), []byte("HYBRID_REQUIRED_BY_SERVER")) {
		t.Fatalf("got %v, want HYBRID_REQUIRED_BY_SERVER", err)
	}
}

func TestBERAndPER(t *testing.T) {
	for _, tc := range []struct {
		got, want []byte
	}{
		{berInt(0), []byte{0x02, 0x01, 0x00}},
		{berInt(34), []byte{0x02, 0x01, 0x22}},
		{berInt(0xffff), []byte{0x02, 0x03, 0x00, 0xff, 0xff}},
		{berLen(0x7f), []byte{0x7f}},
		{berLen(0x80), []byte{0x81, 0x80}},
		{berLen(0x1234), []byte{0x82, 0x12, 0x34}},
		{perLen(0x7f), []byte{0x7f}},
		{perLen(0x12a), []byte{0x81, 0x2a}},
	} {
		if !bytes.Equal(tc.got, tc.want) {
			t.Errorf("got %x, want %x", tc.got, tc.want)
		}
	}

	r := newR([]byte{0x81, 0x2a, 0x05})
	if n := perReadLen(r); n != 0x12a {
		t.Errorf("perReadLen = %#x, want 0x12a", n)
	}
	if n := perReadLen(r); n != 5 {
		t.Errorf("perReadLen = %d, want 5", n)
	}
}

func TestMCSConnectRoundTrip(t *testing.T) {
	// Build a Connect-Response the way a server would and check we can
	// recover its user data; also check Connect-Initial is well formed.
	ci := mcsConnectInitial([]byte("gcc"))
	tag, body := berRead(newR(ci))
	if !bytes.Equal(tag, []byte{0x7f, 0x65}) || !bytes.HasSuffix(body, []byte{0x04, 0x03, 'g', 'c', 'c'}) {
		t.Fatalf("bad Connect-Initial %x", ci)
	}
	resp := berTLV([]byte{0x7f, 0x66},
		berTLV([]byte{0x0a}, []byte{0}),
		berInt(0),
		berDomainParameters(34, 3, 0, 1, 0, 1, 0xfff8, 2),
		berTLV([]byte{0x04}, []byte("server-gcc")),
	)
	ud, err := parseMCSConnectResponse(resp)
	if err != nil || string(ud) != "server-gcc" {
		t.Fatalf("got %q, %v", ud, err)
	}
}

func TestGCCRoundTrip(t *testing.T) {
	blocks := append(clientCoreData(1024, 768, "rdpcli", protocolHybrid), clientSecurityData()...)
	ccr := gccConferenceCreateRequest(blocks)
	// The client blocks follow the "Duca" key and a PER length.
	i := bytes.Index(ccr, []byte("Duca"))
	r := newR(ccr[i+4:])
	if n := perReadLen(r); n != len(blocks) || !bytes.Equal(r.rest(), blocks) {
		t.Fatalf("client blocks not recoverable from %x", ccr)
	}
	// A server response carries its blocks after "McDn".
	var sblocks wbuf
	sblocks.bytes(dataBlock(scCore, []byte{4, 0, 8, 0})...)
	sblocks.bytes(dataBlock(scNet, []byte{0xeb, 0x03, 0, 0})...)
	resp := append([]byte("....McDn"), perLen(len(sblocks.b))...)
	resp = append(resp, sblocks.b...)
	got, err := gccServerBlocks(resp)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := parseServerData(got)
	if err != nil || sd.ioChannel != 1003 || sd.version != 0x00080004 {
		t.Fatalf("got %+v, %v", sd, err)
	}
}

func TestClientCoreDataLength(t *testing.T) {
	if n := len(clientCoreData(1024, 768, "rdpcli", protocolHybrid)); n != 216 {
		t.Fatalf("client core data is %d bytes, want 216", n)
	}
}

// TestCapabilityLengths checks each capability set against the fixed sizes
// in [MS-RDPBCGR] 2.2.7, and that the length fields match.
func TestCapabilityLengths(t *testing.T) {
	want := map[uint16]int{
		capGeneral: 24, capBitmap: 28, capOrder: 88, capBitmapCache: 40,
		capPointer: 10, capInput: 88, capBrush: 8, capGlyphCache: 52,
		capOffscreenCache: 12, capVirtualChannel: 12, capSound: 8,
		capShare: 8, capFont: 8, capControl: 12, capActivation: 12,
	}
	for _, c := range clientCapabilities(1024, 768, 16) {
		typ := binary.LittleEndian.Uint16(c)
		l := int(binary.LittleEndian.Uint16(c[2:]))
		if l != len(c) {
			t.Errorf("%s: length field %d, actual %d", capNames[typ], l, len(c))
		}
		if w, ok := want[typ]; ok && w != len(c) {
			t.Errorf("%s: %d bytes, want %d", capNames[typ], len(c), w)
		}
	}
}

func TestReadFrame(t *testing.T) {
	var in bytes.Buffer
	in.Write(tpkt(x224Data([]byte{1, 2, 3})))
	in.Write([]byte{0x00, 0x05, 0xaa, 0xbb, 0xcc})                    // short fast-path
	in.Write(append([]byte{0x00, 0x80, 0x83}, make([]byte, 0x80)...)) // long fast-path length
	r := bufio.NewReader(&in)

	f, err := readFrame(r)
	if err != nil || f.fastPath || !bytes.Equal(f.body, []byte{2, 0xF0, 0x80, 1, 2, 3}) {
		t.Fatalf("TPKT frame: %+v, %v", f, err)
	}
	f, err = readFrame(r)
	if err != nil || !f.fastPath || !bytes.Equal(f.body, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("fast-path frame: %+v, %v", f, err)
	}
	f, err = readFrame(r)
	if err != nil || !f.fastPath || len(f.body) != 0x80 {
		t.Fatalf("long fast-path frame: len %d, %v", len(f.body), err)
	}
}
