package rdp

import (
	"errors"
	"unicode/utf16"
)

// Client input events ([MS-RDPBCGR] 2.2.8.1.1.3), sent as slow-path Input
// Event PDUs. Slow path needs no extra capability negotiation, and batching
// many events in one PDU keeps typed text cheap.

// InputEvent is one keyboard, mouse or synchronize event. Build them with
// the Key, KeyUnicode, Mouse, Wheel and Sync helpers.
type InputEvent struct {
	msgType uint16
	a, b, c uint16
	toggles uint32
}

const (
	inputEventSync     = 0x0000
	inputEventScancode = 0x0004
	inputEventUnicode  = 0x0005
	inputEventMouse    = 0x8001
	inputEventMouseX   = 0x8002

	kbdFlagsExtended  = 0x0100
	kbdFlagsExtended1 = 0x0200
	kbdFlagsDown      = 0x4000
	kbdFlagsRelease   = 0x8000
)

// Scancode is a PC/AT set 1 make code. Codes with the 0xE000 bit set are
// extended keys (sent with the E0 prefix on a real keyboard), e.g.
// 0xE04B is the Left arrow on the navigation block.
type Scancode uint16

// Some scancodes rdpcli sends itself.
const (
	ScanEsc        Scancode = 0x01
	ScanBackspace  Scancode = 0x0E
	ScanTab        Scancode = 0x0F
	ScanEnter      Scancode = 0x1C
	ScanLeftCtrl   Scancode = 0x1D
	ScanLeftShift  Scancode = 0x2A
	ScanLeftAlt    Scancode = 0x38
	ScanDelete     Scancode = 0xE053
	ScanLeftWin    Scancode = 0xE05B
	ScanR          Scancode = 0x13
	ScanRightCtrl  Scancode = 0xE01D
	ScanRightAlt   Scancode = 0xE038
	ScanRightShift Scancode = 0x36
)

// Key is a key press (down) or release (!down) by scancode.
func Key(code Scancode, down bool) InputEvent {
	flags := uint16(0)
	if code&0xE000 == 0xE000 {
		flags |= kbdFlagsExtended
	}
	if down {
		flags |= kbdFlagsDown
	} else {
		flags |= kbdFlagsRelease
	}
	return InputEvent{msgType: inputEventScancode, a: flags, b: uint16(code & 0xFF)}
}

// KeyUnicode is a press or release of a key that produces one UTF-16 code
// unit, independent of the server's keyboard layout.
func KeyUnicode(unit uint16, down bool) InputEvent {
	flags := uint16(0)
	if !down {
		flags = kbdFlagsRelease
	}
	return InputEvent{msgType: inputEventUnicode, a: flags, b: unit}
}

// Mouse buttons.
const (
	ButtonNone   = 0
	ButtonLeft   = 1
	ButtonRight  = 2
	ButtonMiddle = 3
	ButtonX1     = 4
	ButtonX2     = 5
)

const (
	ptrFlagsHWheel   = 0x0400
	ptrFlagsWheel    = 0x0200
	ptrFlagsWheelNeg = 0x0100
	ptrFlagsMove     = 0x0800
	ptrFlagsDown     = 0x8000
	ptrFlagsButton1  = 0x1000
	ptrFlagsButton2  = 0x2000
	ptrFlagsButton3  = 0x4000
	ptrXFlagsDown    = 0x8000
	ptrXFlagsButton1 = 0x0001
	ptrXFlagsButton2 = 0x0002
)

// Mouse moves the pointer to (x, y) and, if button is not ButtonNone,
// presses (down) or releases it there.
func Mouse(x, y int, button int, down bool) InputEvent {
	ev := InputEvent{msgType: inputEventMouse, b: clampCoord(x), c: clampCoord(y)}
	switch button {
	case ButtonNone:
		ev.a = ptrFlagsMove
		return ev
	case ButtonLeft:
		ev.a = ptrFlagsButton1
	case ButtonRight:
		ev.a = ptrFlagsButton2
	case ButtonMiddle:
		ev.a = ptrFlagsButton3
	case ButtonX1, ButtonX2:
		ev.msgType = inputEventMouseX
		ev.a = ptrXFlagsButton1
		if button == ButtonX2 {
			ev.a = ptrXFlagsButton2
		}
		if down {
			ev.a |= ptrXFlagsDown
		}
		return ev
	default:
		ev.a = ptrFlagsMove
		return ev
	}
	if down {
		ev.a |= ptrFlagsDown
	}
	return ev
}

// Wheel scrolls at (x, y). delta is in wheel units (120 per notch);
// positive scrolls up (vertical) or right (horizontal). It is clamped to
// what one event can carry (±255).
func Wheel(x, y int, delta int, horizontal bool) InputEvent {
	ev := InputEvent{msgType: inputEventMouse, b: clampCoord(x), c: clampCoord(y)}
	ev.a = ptrFlagsWheel
	if horizontal {
		ev.a = ptrFlagsHWheel
	}
	delta = max(-255, min(255, delta))
	if delta < 0 {
		// The rotation is a 9-bit two's complement value.
		ev.a |= ptrFlagsWheelNeg | uint16(delta)&0x00FF
	} else {
		ev.a |= uint16(delta)
	}
	return ev
}

// Toggle key states for Sync.
const (
	ToggleScrollLock = 0x1
	ToggleNumLock    = 0x2
	ToggleCapsLock   = 0x4
	ToggleKanaLock   = 0x8
)

// Sync sets the server's toggle key states (Scroll/Num/Caps/Kana Lock) and
// tells it no other keys are down.
func Sync(toggles uint32) InputEvent {
	return InputEvent{msgType: inputEventSync, toggles: toggles}
}

func clampCoord(v int) uint16 { return uint16(max(0, min(0xFFFF, v))) }

func (ev InputEvent) encode(w *wbuf) {
	w.u32(0) // eventTime: ignored by servers
	w.u16(ev.msgType)
	if ev.msgType == inputEventSync {
		w.u16(0) // pad
		w.u32(ev.toggles)
		return
	}
	w.u16(ev.a)
	w.u16(ev.b)
	w.u16(ev.c)
}

// maxEventsPerPDU keeps an Input PDU well inside one TPKT frame.
const maxEventsPerPDU = 500

func inputBody(events []InputEvent) []byte {
	var w wbuf
	w.u16(uint16(len(events)))
	w.u16(0) // pad
	for _, ev := range events {
		ev.encode(&w)
	}
	return w.b
}

// ErrNotActive is returned when input is sent while the session is not
// active (before activation, or during a server reactivation).
var ErrNotActive = errors.New("rdp: session not active")

// SendInput sends input events to the session. It is safe to call
// concurrently with Next.
func (c *Conn) SendInput(events ...InputEvent) error {
	if !c.active.Load() {
		return ErrNotActive
	}
	for len(events) > 0 {
		n := min(len(events), maxEventsPerPDU)
		if err := c.sendData(pduType2Input, inputBody(events[:n])); err != nil {
			return err
		}
		events = events[n:]
	}
	return nil
}

// TextEvents returns the key presses that type s, using Unicode key events
// so the result does not depend on the server's keyboard layout. Newlines
// and tabs are sent as the Enter and Tab keys; carriage returns are dropped
// (so CRLF types one Enter).
func TextEvents(s string) []InputEvent {
	var evs []InputEvent
	for _, r := range s {
		switch r {
		case '\r':
			continue
		case '\n':
			evs = append(evs, Key(ScanEnter, true), Key(ScanEnter, false))
			continue
		case '\t':
			evs = append(evs, Key(ScanTab, true), Key(ScanTab, false))
			continue
		}
		var units []uint16
		if r > 0xFFFF {
			hi, lo := utf16.EncodeRune(r)
			units = []uint16{uint16(hi), uint16(lo)}
		} else {
			units = []uint16{uint16(r)}
		}
		for _, u := range units {
			evs = append(evs, KeyUnicode(u, true), KeyUnicode(u, false))
		}
	}
	return evs
}
