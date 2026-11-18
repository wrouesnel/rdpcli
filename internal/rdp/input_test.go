package rdp

import (
	"encoding/hex"
	"testing"
)

func TestInputEventEncoding(t *testing.T) {
	tests := []struct {
		name string
		ev   InputEvent
		want string // after the 4-byte eventTime
	}{
		{"key A down", Key(0x1E, true), "0400" + "0040" + "1e00" + "0000"},
		{"key A up", Key(0x1E, false), "0400" + "0080" + "1e00" + "0000"},
		{"extended delete down", Key(ScanDelete, true), "0400" + "0041" + "5300" + "0000"},
		{"unicode é down", KeyUnicode(0xE9, true), "0500" + "0000" + "e900" + "0000"},
		{"unicode é up", KeyUnicode(0xE9, false), "0500" + "0080" + "e900" + "0000"},
		{"move", Mouse(100, 200, ButtonNone, false), "0180" + "0008" + "6400" + "c800"},
		{"left down", Mouse(1, 2, ButtonLeft, true), "0180" + "0090" + "0100" + "0200"},
		{"right up", Mouse(1, 2, ButtonRight, false), "0180" + "0020" + "0100" + "0200"},
		{"x2 down", Mouse(1, 2, ButtonX2, true), "0280" + "0280" + "0100" + "0200"},
		{"wheel up", Wheel(0, 0, 120, false), "0180" + "7802" + "0000" + "0000"},
		// -120 as a 9-bit two's complement value is 0x188.
		{"wheel down", Wheel(0, 0, -120, false), "0180" + "8803" + "0000" + "0000"},
		{"sync caps", Sync(ToggleCapsLock), "0000" + "0000" + "04000000"},
	}
	for _, tt := range tests {
		var w wbuf
		tt.ev.encode(&w)
		if got := hex.EncodeToString(w.b[4:]); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
		if len(w.b) != 12 {
			t.Errorf("%s: event is %d bytes, want 12", tt.name, len(w.b))
		}
	}
}

func TestTextEvents(t *testing.T) {
	evs := TextEvents("a\r\n\U0001F600")
	// a down/up, Enter down/up, surrogate pair down/up each.
	if len(evs) != 8 {
		t.Fatalf("got %d events, want 8", len(evs))
	}
	if evs[2] != Key(ScanEnter, true) || evs[3] != Key(ScanEnter, false) {
		t.Errorf("newline not sent as Enter: %+v", evs[2:4])
	}
	if evs[4] != KeyUnicode(0xD83D, true) || evs[6] != KeyUnicode(0xDE00, true) {
		t.Errorf("astral rune not sent as a surrogate pair: %+v", evs[4:])
	}
}
