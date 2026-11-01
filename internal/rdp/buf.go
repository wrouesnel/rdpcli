package rdp

import (
	"encoding/binary"
	"io"
	"unicode/utf16"
)

// wbuf is a little append-only encoder. RDP structures are little-endian;
// the T.125/X.224 layers use big-endian (the *be methods).
type wbuf struct{ b []byte }

func (w *wbuf) u8(v uint8)      { w.b = append(w.b, v) }
func (w *wbuf) u16(v uint16)    { w.b = binary.LittleEndian.AppendUint16(w.b, v) }
func (w *wbuf) u32(v uint32)    { w.b = binary.LittleEndian.AppendUint32(w.b, v) }
func (w *wbuf) u16be(v uint16)  { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *wbuf) bytes(p ...byte) { w.b = append(w.b, p...) }
func (w *wbuf) zero(n int)      { w.b = append(w.b, make([]byte, n)...) }
func (w *wbuf) fixed(p []byte, n int) {
	// p truncated or zero-padded to exactly n bytes.
	if len(p) > n {
		p = p[:n]
	}
	w.b = append(w.b, p...)
	w.zero(n - len(p))
}

// rbuf is a bounds-checked decoder. The first out-of-range read sets err and
// all later reads return zero values, so callers check err once at the end.
type rbuf struct {
	b   []byte
	off int
	err error
}

func newR(b []byte) *rbuf { return &rbuf{b: b} }

func (r *rbuf) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return false
	}
	return true
}

func (r *rbuf) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *rbuf) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *rbuf) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *rbuf) u16be() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *rbuf) take(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *rbuf) skip(n int) { r.take(n) }

func (r *rbuf) remaining() int {
	if r.err != nil {
		return 0
	}
	return len(r.b) - r.off
}

func (r *rbuf) rest() []byte { return r.take(r.remaining()) }

// utf16le encodes s as UTF-16LE, optionally with a NUL terminator.
func utf16le(s string, nul bool) []byte {
	u := utf16.Encode([]rune(s))
	if nul {
		u = append(u, 0)
	}
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

// fromUTF16 decodes UTF-16LE bytes, stopping at the first NUL.
func fromUTF16(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}
