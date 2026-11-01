package rdp

import "fmt"

// Client capability sets for the Confirm Active PDU ([MS-RDPBCGR] 2.2.7).
// This is a deliberately minimal client: it does not render, so it
// advertises no drawing orders and asks the server to suppress output.

const (
	capGeneral        = 1
	capBitmap         = 2
	capOrder          = 3
	capBitmapCache    = 4
	capControl        = 5
	capActivation     = 7
	capPointer        = 8
	capShare          = 9
	capSound          = 12
	capInput          = 13
	capFont           = 14
	capBrush          = 15
	capGlyphCache     = 16
	capOffscreenCache = 17
	capVirtualChannel = 20
)

func capSet(typ uint16, body []byte) []byte {
	var w wbuf
	w.u16(typ)
	w.u16(uint16(4 + len(body)))
	w.bytes(body...)
	return w.b
}

func clientCapabilities(width, height, bpp uint16) [][]byte {
	var caps [][]byte
	add := func(typ uint16, f func(w *wbuf)) {
		var w wbuf
		f(&w)
		caps = append(caps, capSet(typ, w.b))
	}

	add(capGeneral, func(w *wbuf) {
		w.u16(1)      // osMajorType: Windows
		w.u16(3)      // osMinorType: Windows NT
		w.u16(0x0200) // protocolVersion
		w.u16(0)      // pad
		w.u16(0)      // generalCompressionTypes
		w.u16(0x0405) // extraFlags: FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR
		w.u16(0)      // updateCapabilityFlag
		w.u16(0)      // remoteUnshareFlag
		w.u16(0)      // generalCompressionLevel
		w.u8(0)       // refreshRectSupport
		w.u8(1)       // suppressOutputSupport
	})
	add(capBitmap, func(w *wbuf) {
		w.u16(bpp) // preferredBitsPerPixel: echo the server's session depth
		w.u16(1)   // receive1BitPerPixel
		w.u16(1)   // receive4BitsPerPixel
		w.u16(1)   // receive8BitsPerPixel
		w.u16(width)
		w.u16(height)
		w.u16(0) // pad
		w.u16(1) // desktopResizeFlag
		w.u16(1) // bitmapCompressionFlag
		w.u8(0)  // highColorFlags
		w.u8(0)  // drawingFlags
		w.u16(1) // multipleRectangleSupport
		w.u16(0) // pad
	})
	add(capOrder, func(w *wbuf) {
		w.zero(16)    // terminalDescriptor
		w.u32(0)      // pad
		w.u16(1)      // desktopSaveXGranularity
		w.u16(20)     // desktopSaveYGranularity
		w.u16(0)      // pad
		w.u16(1)      // maximumOrderLevel
		w.u16(0)      // numberFonts
		w.u16(0x002A) // orderFlags: NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT
		w.zero(32)    // orderSupport: no drawing orders
		w.u16(0)      // textFlags
		w.u16(0)      // orderSupportExFlags
		w.u32(0)      // pad
		w.u32(230400) // desktopSaveSize
		w.u16(0)      // pad
		w.u16(0)      // pad
		w.u16(0)      // textANSICodePage
		w.u16(0)      // pad
	})
	add(capBitmapCache, func(w *wbuf) {
		w.zero(24)
		w.u16(200)
		w.u16(256)
		w.u16(600)
		w.u16(1024)
		w.u16(1000)
		w.u16(4096)
	})
	add(capPointer, func(w *wbuf) {
		w.u16(1)  // colorPointerFlag
		w.u16(20) // colorPointerCacheSize
		w.u16(21) // pointerCacheSize
	})
	add(capInput, func(w *wbuf) {
		w.u16(0x0011) // INPUT_FLAG_SCANCODES | INPUT_FLAG_UNICODE
		w.u16(0)      // pad
		w.u32(0x0409) // keyboardLayout
		w.u32(4)      // keyboardType
		w.u32(0)      // keyboardSubType
		w.u32(12)     // keyboardFunctionKey
		w.zero(64)    // imeFileName
	})
	add(capBrush, func(w *wbuf) { w.u32(0) })
	add(capGlyphCache, func(w *wbuf) {
		w.zero(40) // glyphCache: 10 empty definitions
		w.u32(0)   // fragCache
		w.u16(0)   // glyphSupportLevel: GLYPH_SUPPORT_NONE
		w.u16(0)   // pad
	})
	add(capOffscreenCache, func(w *wbuf) {
		w.u32(0) // offscreenSupportLevel: off
		w.u16(0)
		w.u16(0)
	})
	add(capVirtualChannel, func(w *wbuf) {
		w.u32(0)    // flags: no compression
		w.u32(1600) // VCChunkSize
	})
	add(capSound, func(w *wbuf) { w.u16(0); w.u16(0) })
	add(capShare, func(w *wbuf) { w.u16(0); w.u16(0) })
	add(capFont, func(w *wbuf) { w.u16(1); w.u16(0) })
	add(capControl, func(w *wbuf) {
		w.u16(0) // controlFlags
		w.u16(0) // remoteDetachFlag
		w.u16(2) // controlInterest: CONTROLPRIORITY_NEVER
		w.u16(2) // detachInterest
	})
	add(capActivation, func(w *wbuf) { w.zero(8) })
	return caps
}

// confirmActivePDU builds the Client Confirm Active PDU body.
func confirmActivePDU(shareID uint32, userID uint16, width, height, bpp uint16) []byte {
	caps := clientCapabilities(width, height, bpp)
	source := []byte("MSTSC\x00")
	var combined wbuf
	combined.u16(uint16(len(caps)))
	combined.u16(0) // pad
	for _, c := range caps {
		combined.bytes(c...)
	}

	var w wbuf
	w.u32(shareID)
	w.u16(1002) // originatorId: server channel
	w.u16(uint16(len(source)))
	w.u16(uint16(len(combined.b)))
	w.bytes(source...)
	w.bytes(combined.b...)
	return shareControl(pduTypeConfirmActive, userID, w.b)
}

var capNames = map[uint16]string{
	capGeneral: "General", capBitmap: "Bitmap", capOrder: "Order", capBitmapCache: "BitmapCache",
	capControl: "Control", capActivation: "Activation", capPointer: "Pointer", capShare: "Share",
	capSound: "Sound", capInput: "Input", capFont: "Font", capBrush: "Brush",
	capGlyphCache: "GlyphCache", capOffscreenCache: "OffscreenCache", capVirtualChannel: "VirtualChannel",
	10: "ColorCache", 18: "BitmapCacheHostSupport", 19: "BitmapCacheRev2", 22: "DrawGdiPlus",
	23: "Rail", 24: "Window", 25: "CompDesk", 26: "MultifragmentUpdate", 27: "LargePointer",
	28: "SurfaceCommands", 29: "BitmapCodecs", 30: "FrameAcknowledge",
}

// serverCaps holds the server capability values the client must follow.
type serverCaps struct {
	bpp, width, height uint16
	names              []string
}

func parseServerCaps(r *rbuf, n uint16) serverCaps {
	var sc serverCaps
	for i := 0; i < int(n) && r.err == nil; i++ {
		typ := r.u16()
		l := int(r.u16())
		body := newR(r.take(l - 4))
		name := capNames[typ]
		if name == "" {
			name = fmt.Sprintf("type%d", typ)
		}
		sc.names = append(sc.names, fmt.Sprintf("%s(%d)", name, l))
		if typ == capGeneral {
			body.skip(10)
			extra := body.u16()
			body.skip(6)
			refresh, suppress := body.u8(), body.u8()
			sc.names[len(sc.names)-1] += fmt.Sprintf("[extraFlags=0x%04x refreshRect=%d suppressOutput=%d]", extra, refresh, suppress)
		}
		if typ == capBitmap {
			sc.bpp = body.u16()
			body.skip(6)
			sc.width = body.u16()
			sc.height = body.u16()
		}
	}
	return sc
}
