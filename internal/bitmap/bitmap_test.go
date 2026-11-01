package bitmap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// pels16 encodes 16 bpp pixel values little-endian.
func pels16(v ...uint16) []byte {
	b := make([]byte, 2*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint16(b[2*i:], x)
	}
	return b
}

func decodeRaw(t *testing.T, src []byte, width, height int) []byte {
	t.Helper()
	dst := make([]byte, width*height*2)
	if err := rleDecompress(src, dst, width*2, 2); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestColorRunAndImage(t *testing.T) {
	// REGULAR_COLOR_RUN of 3 × 0x1234, then REGULAR_COLOR_IMAGE of 1 pixel.
	src := append([]byte{0x60 | 3}, pels16(0x1234)...)
	src = append(src, 0x80|1)
	src = append(src, pels16(0xabcd)...)
	got := decodeRaw(t, src, 4, 1)
	if want := pels16(0x1234, 0x1234, 0x1234, 0xabcd); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestBackgroundAndForegroundRuns(t *testing.T) {
	// First line: BG run of 4 → black. Second line: SET_FG_FG run of 4 with
	// fg 0x00ff → each pixel is above ^ fg = 0x00ff.
	src := []byte{0x00 | 4, 0xC0 | 4, 0xff, 0x00}
	got := decodeRaw(t, src, 4, 2)
	want := pels16(0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestConsecutiveBackgroundRunsInsertForeground(t *testing.T) {
	// Two BG runs in a row on the first line: the second starts with the
	// foreground pel (initially white).
	src := []byte{0x00 | 2, 0x00 | 2}
	got := decodeRaw(t, src, 4, 1)
	if want := pels16(0, 0, 0xffff, 0); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestFgBgImage(t *testing.T) {
	// LITE_SET_FG_FGBG_IMAGE, 1×8 pixels, fg 0x0f0f, mask 0b10100101.
	src := []byte{0xD0 | 1, 0x0f, 0x0f, 0xa5}
	got := decodeRaw(t, src, 8, 1)
	f := uint16(0x0f0f)
	if want := pels16(f, 0, f, 0, 0, f, 0, f); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestMegaMegaAndDithered(t *testing.T) {
	// MEGA_MEGA_DITHERED_RUN length 2 → ABAB, then WHITE, then BLACK.
	src := []byte{0xF8, 2, 0}
	src = append(src, pels16(0x1111, 0x2222)...)
	src = append(src, 0xFD, 0xFE)
	got := decodeRaw(t, src, 6, 1)
	if want := pels16(0x1111, 0x2222, 0x1111, 0x2222, 0xffff, 0); !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestOverflowIsAnError(t *testing.T) {
	src := append([]byte{0x60 | 5}, pels16(1)...)
	if err := rleDecompress(src, make([]byte, 4*2), 4*2, 2); err != ErrOverflow {
		t.Fatalf("got %v, want ErrOverflow", err)
	}
}

func TestDecodeFlipsAndConverts(t *testing.T) {
	// 2×2 uncompressed 16 bpp, bottom row first: bottom = red, top = blue.
	red, blue := uint16(0xf800), uint16(0x001f)
	img, err := Decode(pels16(red, red, blue, blue), 2, 2, 16, false)
	if err != nil {
		t.Fatal(err)
	}
	if c := img.RGBAAt(0, 0); c.B != 0xff || c.R != 0 {
		t.Errorf("top-left = %v, want blue", c)
	}
	if c := img.RGBAAt(1, 1); c.R != 0xff || c.B != 0 {
		t.Errorf("bottom-right = %v, want red", c)
	}
}
