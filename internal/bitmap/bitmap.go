// Package bitmap decodes RDP bitmap update data: uncompressed bitmaps and
// the interleaved RLE compression of [MS-RDPBCGR] 2.2.9.1.1.3.1.2.4, at
// 15, 16 and 24 bits per pixel.
package bitmap

import (
	"errors"
	"fmt"
	"image"
)

// ErrOverflow is returned when compressed data would write past the bitmap.
var ErrOverflow = errors.New("bitmap: RLE data overruns bitmap")

// Decode decodes one bitmap of width×height pixels (width as transmitted,
// i.e. padded) into a top-down RGBA image. RDP bitmaps are stored bottom-up.
func Decode(data []byte, width, height, bpp int, compressed bool) (*image.RGBA, error) {
	ps, err := pixelSize(bpp)
	if err != nil {
		return nil, err
	}
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("bitmap: bad size %dx%d", width, height)
	}

	var raw []byte
	var rowDelta int
	if compressed {
		rowDelta = width * ps
		raw = make([]byte, rowDelta*height)
		if err := rleDecompress(data, raw, rowDelta, ps); err != nil {
			return nil, err
		}
	} else {
		rowDelta = (width*ps + 3) &^ 3
		if len(data) < rowDelta*height {
			return nil, fmt.Errorf("bitmap: uncompressed data is %d bytes, need %d", len(data), rowDelta*height)
		}
		raw = data
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for row := 0; row < height; row++ {
		src := raw[row*rowDelta:]
		dst := img.Pix[(height-1-row)*img.Stride:]
		for x := 0; x < width; x++ {
			r, g, b := toRGB(readPixel(src, x*ps, ps), bpp)
			o := x * 4
			dst[o], dst[o+1], dst[o+2], dst[o+3] = r, g, b, 0xff
		}
	}
	return img, nil
}

func pixelSize(bpp int) (int, error) {
	switch bpp {
	case 15, 16:
		return 2, nil
	case 24:
		return 3, nil
	}
	return 0, fmt.Errorf("bitmap: unsupported depth %d bpp", bpp)
}

func readPixel(b []byte, off, ps int) uint32 {
	v := uint32(b[off]) | uint32(b[off+1])<<8
	if ps == 3 {
		v |= uint32(b[off+2]) << 16
	}
	return v
}

func writePixel(b []byte, off, ps int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	if ps == 3 {
		b[off+2] = byte(v >> 16)
	}
}

func toRGB(v uint32, bpp int) (r, g, b uint8) {
	switch bpp {
	case 15:
		r5, g5, b5 := uint8(v>>10&0x1f), uint8(v>>5&0x1f), uint8(v&0x1f)
		return r5<<3 | r5>>2, g5<<3 | g5>>2, b5<<3 | b5>>2
	case 16:
		r5, g6, b5 := uint8(v>>11&0x1f), uint8(v>>5&0x3f), uint8(v&0x1f)
		return r5<<3 | r5>>2, g6<<2 | g6>>4, b5<<3 | b5>>2
	default: // 24: bytes are B, G, R
		return uint8(v >> 16), uint8(v >> 8), uint8(v)
	}
}

// RLE order codes.
const (
	regularBgRun        = 0x0
	regularFgRun        = 0x1
	regularFgBgImage    = 0x2
	regularColorRun     = 0x3
	regularColorImage   = 0x4
	liteSetFgFgRun      = 0xC
	liteSetFgFgBgImage  = 0xD
	liteDitheredRun     = 0xE
	megaMegaBgRun       = 0xF0
	megaMegaFgRun       = 0xF1
	megaMegaFgBgImage   = 0xF2
	megaMegaColorRun    = 0xF3
	megaMegaColorImage  = 0xF4
	megaMegaSetFgRun    = 0xF6
	megaMegaSetFgBgImg  = 0xF7
	megaMegaDitheredRun = 0xF8
	specialFgBg1        = 0xF9
	specialFgBg2        = 0xFA
	white               = 0xFD
	black               = 0xFE
)

func codeID(hdr byte) int {
	switch {
	case hdr&0xC0 != 0xC0:
		return int(hdr >> 5) // regular orders
	case hdr&0xF0 == 0xF0:
		return int(hdr) // mega-mega and special orders
	default:
		return int(hdr >> 4) // lite orders
	}
}

// runLength decodes the run length of the order at src[0], returning the
// length and the number of header bytes consumed.
func runLength(code int, src []byte) (n, adv int, err error) {
	need := func(k int) bool { return len(src) >= k }
	switch code {
	case regularFgBgImage:
		if n = int(src[0] & 0x1F); n != 0 {
			return n * 8, 1, nil
		}
		if !need(2) {
			return 0, 0, ErrOverflow
		}
		return int(src[1]) + 1, 2, nil
	case liteSetFgFgBgImage:
		if n = int(src[0] & 0x0F); n != 0 {
			return n * 8, 1, nil
		}
		if !need(2) {
			return 0, 0, ErrOverflow
		}
		return int(src[1]) + 1, 2, nil
	case regularBgRun, regularFgRun, regularColorRun, regularColorImage:
		if n = int(src[0] & 0x1F); n != 0 {
			return n, 1, nil
		}
		if !need(2) {
			return 0, 0, ErrOverflow
		}
		return int(src[1]) + 32, 2, nil
	case liteSetFgFgRun, liteDitheredRun:
		if n = int(src[0] & 0x0F); n != 0 {
			return n, 1, nil
		}
		if !need(2) {
			return 0, 0, ErrOverflow
		}
		return int(src[1]) + 16, 2, nil
	case megaMegaBgRun, megaMegaFgRun, megaMegaSetFgRun, megaMegaDitheredRun,
		megaMegaColorRun, megaMegaFgBgImage, megaMegaSetFgBgImg, megaMegaColorImage:
		if !need(3) {
			return 0, 0, ErrOverflow
		}
		return int(src[1]) | int(src[2])<<8, 3, nil
	}
	return 0, 0, fmt.Errorf("bitmap: no run length for order 0x%x", code)
}

// rleDecompress implements RleDecompress from [MS-RDPBCGR]. dst is written
// in transmission order (bottom scanline first); rowDelta is the scanline
// size in bytes.
func rleDecompress(src, dst []byte, rowDelta, ps int) error {
	whitePel := uint32(1)<<(8*ps) - 1
	fgPel := whitePel
	insertFgPel := false
	firstLine := true
	s, d := 0, 0

	put := func(v uint32) error {
		if d+ps > len(dst) {
			return ErrOverflow
		}
		writePixel(dst, d, ps, v)
		d += ps
		return nil
	}
	above := func() uint32 { return readPixel(dst, d-rowDelta, ps) }
	pel := func() (uint32, error) {
		if s+ps > len(src) {
			return 0, ErrOverflow
		}
		v := readPixel(src, s, ps)
		s += ps
		return v, nil
	}
	fgBgImage := func(mask byte, bits int) error {
		for i := 0; i < bits; i++ {
			var v uint32
			set := mask&(1<<i) != 0
			switch {
			case firstLine && set:
				v = fgPel
			case firstLine:
				v = 0
			case set:
				v = above() ^ fgPel
			default:
				v = above()
			}
			if err := put(v); err != nil {
				return err
			}
		}
		return nil
	}

	for s < len(src) {
		if firstLine && d >= rowDelta {
			firstLine = false
			insertFgPel = false
		}
		code := codeID(src[s])

		if code == regularBgRun || code == megaMegaBgRun {
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			if insertFgPel && n > 0 {
				v := fgPel
				if !firstLine {
					v = above() ^ fgPel
				}
				if err := put(v); err != nil {
					return err
				}
				n--
			}
			for ; n > 0; n-- {
				var v uint32
				if !firstLine {
					v = above()
				}
				if err := put(v); err != nil {
					return err
				}
			}
			// A following background run needs a foreground pel inserted.
			insertFgPel = true
			continue
		}
		insertFgPel = false

		switch code {
		case regularFgRun, megaMegaFgRun, liteSetFgFgRun, megaMegaSetFgRun:
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			if code == liteSetFgFgRun || code == megaMegaSetFgRun {
				if fgPel, err = pel(); err != nil {
					return err
				}
			}
			for ; n > 0; n-- {
				v := fgPel
				if !firstLine {
					v = above() ^ fgPel
				}
				if err := put(v); err != nil {
					return err
				}
			}

		case liteDitheredRun, megaMegaDitheredRun:
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			a, err := pel()
			if err != nil {
				return err
			}
			b, err := pel()
			if err != nil {
				return err
			}
			for ; n > 0; n-- {
				if err := put(a); err != nil {
					return err
				}
				if err := put(b); err != nil {
					return err
				}
			}

		case regularColorRun, megaMegaColorRun:
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			a, err := pel()
			if err != nil {
				return err
			}
			for ; n > 0; n-- {
				if err := put(a); err != nil {
					return err
				}
			}

		case regularFgBgImage, megaMegaFgBgImage, liteSetFgFgBgImage, megaMegaSetFgBgImg:
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			if code == liteSetFgFgBgImage || code == megaMegaSetFgBgImg {
				if fgPel, err = pel(); err != nil {
					return err
				}
			}
			for n > 0 {
				if s >= len(src) {
					return ErrOverflow
				}
				mask := src[s]
				s++
				bits := min(n, 8)
				if err := fgBgImage(mask, bits); err != nil {
					return err
				}
				n -= bits
			}

		case regularColorImage, megaMegaColorImage:
			n, adv, err := runLength(code, src[s:])
			if err != nil {
				return err
			}
			s += adv
			k := n * ps
			if s+k > len(src) || d+k > len(dst) {
				return ErrOverflow
			}
			copy(dst[d:], src[s:s+k])
			s += k
			d += k

		case specialFgBg1, specialFgBg2:
			s++
			mask := byte(0x03)
			if code == specialFgBg2 {
				mask = 0x05
			}
			if err := fgBgImage(mask, 8); err != nil {
				return err
			}

		case white, black:
			s++
			v := uint32(0)
			if code == white {
				v = whitePel
			}
			if err := put(v); err != nil {
				return err
			}

		default:
			return fmt.Errorf("bitmap: unknown RLE order 0x%02x", src[s])
		}
	}
	return nil
}
