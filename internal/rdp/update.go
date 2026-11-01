package rdp

import (
	"fmt"
	"image"

	"github.com/wrouesnel/rdpcli/internal/bitmap"
)

// Slow-path update types ([MS-RDPBCGR] 2.2.9.1.1.3.1).
const (
	updateTypeOrders      = 0
	updateTypeBitmap      = 1
	updateTypePalette     = 2
	updateTypeSynchronize = 3
)

// Bitmap data flags ([MS-RDPBCGR] 2.2.9.1.1.3.1.2.2).
const (
	bitmapCompression      = 0x0001
	noBitmapCompressionHdr = 0x0400
)

// Bitmap is a decoded screen update to draw at (X, Y).
type Bitmap struct {
	X, Y  int
	Image *image.RGBA
}

// parseUpdate decodes a slow-path Update PDU. Only bitmap updates carry
// anything this client draws; others are ignored.
func (c *Conn) parseUpdate(body []byte) ([]Bitmap, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("rdp: truncated update PDU")
	}
	switch updateType := uint16(body[0]) | uint16(body[1])<<8; updateType {
	case updateTypeBitmap:
		return c.parseBitmapData(body)
	case updateTypeSynchronize:
	default:
		c.logf("update: ignoring slow-path update type %d", updateType)
	}
	return nil, nil
}

// parseBitmapData decodes TS_UPDATE_BITMAP_DATA, which is the same in
// slow-path and fast-path updates.
func (c *Conn) parseBitmapData(data []byte) ([]Bitmap, error) {
	r := newR(data)
	if t := r.u16(); t != updateTypeBitmap {
		return nil, fmt.Errorf("rdp: bitmap update has type %d", t)
	}
	n := int(r.u16())
	out := make([]Bitmap, 0, n)
	for i := 0; i < n; i++ {
		left := int(r.u16())
		top := int(r.u16())
		right := int(r.u16())
		bottom := int(r.u16())
		width := int(r.u16())
		height := int(r.u16())
		bpp := int(r.u16())
		flags := r.u16()
		length := int(r.u16())
		data := r.take(length)
		if r.err != nil {
			return nil, fmt.Errorf("rdp: truncated bitmap update")
		}
		compressed := flags&bitmapCompression != 0
		if compressed && flags&noBitmapCompressionHdr == 0 {
			if len(data) < 8 {
				return nil, fmt.Errorf("rdp: short compressed bitmap header")
			}
			data = data[8:] // TS_CD_HEADER
		}
		img, err := bitmap.Decode(data, width, height, bpp, compressed)
		if err != nil {
			// One bad rectangle should not end the session.
			c.logf("update: %dx%d at (%d,%d): %v", width, height, left, top, err)
			continue
		}
		// The transmitted bitmap may be padded; crop to the destination.
		w := min(right-left+1, width)
		h := min(bottom-top+1, height)
		if w <= 0 || h <= 0 {
			continue
		}
		out = append(out, Bitmap{X: left, Y: top, Image: img.SubImage(image.Rect(0, 0, w, h)).(*image.RGBA)})
	}
	return out, nil
}

// Fast-path output ([MS-RDPBCGR] 2.2.9.1.2).
const (
	fpUpdateOrders      = 0x0
	fpUpdateBitmap      = 0x1
	fpUpdatePalette     = 0x2
	fpUpdateSynchronize = 0x3
	fpUpdateSurfCmds    = 0x4

	fpFragSingle = 0
	fpFragLast   = 1
	fpFragFirst  = 2
	fpFragNext   = 3

	fpCompressionUsed = 0x2

	// Pointer updates (0x5–0xC) are not rendered yet.
	fpUpdatePointerFirst = 0x5
	fpUpdatePointerLast  = 0xC
)

// maxFastPathReassembly bounds fragment reassembly. Without the
// Multifragment Update capability the server's limit is far lower.
const maxFastPathReassembly = 16 << 20

// handleFastPath processes one fast-path output PDU, queueing decoded
// bitmaps on c.pending.
func (c *Conn) handleFastPath(f frame) error {
	if f.header&0xC0 != 0 {
		return fmt.Errorf("rdp: encrypted fast-path output is not supported (header 0x%02x)", f.header)
	}
	r := newR(f.body)
	for r.remaining() > 0 {
		hdr := r.u8()
		code := hdr & 0x0F
		frag := (hdr >> 4) & 0x03
		if (hdr>>6)&0x03 == fpCompressionUsed {
			r.u8() // compressionFlags
			return fmt.Errorf("rdp: compressed fast-path output is not supported")
		}
		size := int(r.u16())
		data := r.take(size)
		if r.err != nil {
			return fmt.Errorf("rdp: truncated fast-path update")
		}

		switch frag {
		case fpFragFirst:
			c.fpFrag = append(c.fpFrag[:0], data...)
			continue
		case fpFragNext:
			c.fpFrag = append(c.fpFrag, data...)
			if len(c.fpFrag) > maxFastPathReassembly {
				return fmt.Errorf("rdp: fast-path update too large")
			}
			continue
		case fpFragLast:
			data = append(c.fpFrag, data...)
			c.fpFrag = nil
		}

		switch {
		case code == fpUpdateBitmap:
			bitmaps, err := c.parseBitmapData(data)
			if err != nil {
				return err
			}
			c.pending = append(c.pending, bitmaps...)
		case code == fpUpdateSynchronize:
		case code >= fpUpdatePointerFirst && code <= fpUpdatePointerLast:
		default:
			c.logf("fastpath: ignoring update code %d (%d bytes)", code, len(data))
		}
	}
	return nil
}
