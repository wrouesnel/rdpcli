package rdp

import (
	"fmt"
)

// --- GCC client data blocks ([MS-RDPBCGR] 2.2.1.3) ---------------------------

const (
	csCore     = 0xC001
	csSecurity = 0xC002
	csNet      = 0xC003
	csCluster  = 0xC004

	scCore     = 0x0C01
	scSecurity = 0x0C02
	scNet      = 0x0C03
)

func dataBlock(typ uint16, body []byte) []byte {
	var w wbuf
	w.u16(typ)
	w.u16(uint16(4 + len(body)))
	w.bytes(body...)
	return w.b
}

func clientCoreData(width, height uint16, clientName string, selectedProtocol uint32) []byte {
	var w wbuf
	w.u32(0x00080004) // RDP 5.0+ protocol version
	w.u16(width)
	w.u16(height)
	w.u16(0xCA01) // colorDepth: RNS_UD_COLOR_8BPP (superseded below)
	w.u16(0xAA03) // SASSequence
	w.u32(0x0409) // keyboardLayout: en-US
	w.u32(2600)   // clientBuild
	w.fixed(utf16le(clientName, false), 32)
	w.u32(4)  // keyboardType: IBM enhanced
	w.u32(0)  // keyboardSubType
	w.u32(12) // keyboardFunctionKey
	w.zero(64)
	w.u16(0xCA01) // postBeta2ColorDepth
	w.u16(1)      // clientProductId
	w.u32(0)      // serialNumber
	w.u16(16)     // highColorDepth
	w.u16(0x000F) // supportedColorDepths: 24/16/15/32 bpp
	w.u16(0x0001) // earlyCapabilityFlags: RNS_UD_CS_SUPPORT_ERRINFO_PDU
	w.zero(64)    // clientDigProductId
	w.u8(0)       // connectionType
	w.u8(0)       // pad1octet
	w.u32(selectedProtocol)
	return dataBlock(csCore, w.b)
}

func clientSecurityData() []byte {
	var w wbuf
	w.u32(0) // encryptionMethods: none (TLS provides security)
	w.u32(0) // extEncryptionMethods
	return dataBlock(csSecurity, w.b)
}

func clientNetworkData() []byte {
	var w wbuf
	w.u32(0) // no static virtual channels yet
	return dataBlock(csNet, w.b)
}

func clientClusterData(console bool) []byte {
	flags := uint32(0x01 | 0x03<<2) // REDIRECTION_SUPPORTED, version 4
	if console {
		flags |= 0x02 // REDIRECTED_SESSIONID_FIELD_VALID, session 0 (console)
	}
	var w wbuf
	w.u32(flags)
	w.u32(0) // redirectedSessionId
	return dataBlock(csCluster, w.b)
}

// serverData holds what we need from the server's GCC data blocks.
type serverData struct {
	version         uint32
	ioChannel       uint16
	encryptionLevel uint32
}

func parseServerData(blocks []byte) (serverData, error) {
	var sd serverData
	r := newR(blocks)
	for r.remaining() >= 4 {
		typ := r.u16()
		n := int(r.u16())
		if n < 4 {
			return sd, fmt.Errorf("rdp: bad server data block length %d", n)
		}
		b := newR(r.take(n - 4))
		switch typ {
		case scCore:
			sd.version = b.u32()
		case scSecurity:
			b.u32() // encryptionMethod
			sd.encryptionLevel = b.u32()
		case scNet:
			sd.ioChannel = b.u16()
		}
	}
	if r.err != nil {
		return sd, fmt.Errorf("rdp: truncated server data: %w", r.err)
	}
	if sd.ioChannel == 0 {
		return sd, fmt.Errorf("rdp: server did not assign an I/O channel")
	}
	return sd, nil
}

// --- Security header and Client Info PDU -------------------------------------

const (
	secInfoPkt    = 0x0040
	secLicensePkt = 0x0080
)

// Client Info flags ([MS-RDPBCGR] 2.2.1.11.1.1).
const (
	infoMouse             = 0x00000001
	infoDisableCtrlAltDel = 0x00000002
	infoAutoLogon         = 0x00000008
	infoUnicode           = 0x00000010
	infoMaximizeShell     = 0x00000020
	infoLogonNotify       = 0x00000040
	infoEnableWindowsKey  = 0x00000100
	infoLogonErrors       = 0x00010000
	infoNoAudioPlayback   = 0x00080000
)

func clientInfoPDU(domain, user, password, clientAddr string) []byte {
	flags := uint32(infoMouse | infoDisableCtrlAltDel | infoUnicode | infoMaximizeShell |
		infoLogonNotify | infoEnableWindowsKey | infoLogonErrors | infoNoAudioPlayback)
	if password != "" {
		flags |= infoAutoLogon
	}
	strs := [][]byte{
		utf16le(domain, false), utf16le(user, false), utf16le(password, false),
		nil, nil, // alternate shell, working directory
	}

	var w wbuf
	w.u16(secInfoPkt) // basic security header
	w.u16(0)
	w.u32(0) // CodePage
	w.u32(flags)
	for _, s := range strs {
		w.u16(uint16(len(s)))
	}
	for _, s := range strs {
		w.bytes(s...)
		w.bytes(0, 0)
	}

	// Extended info packet.
	addr := utf16le(clientAddr, true)
	dir := utf16le(`C:\rdpcli`, true)
	w.u16(0x0002) // AF_INET
	w.u16(uint16(len(addr)))
	w.bytes(addr...)
	w.u16(uint16(len(dir)))
	w.bytes(dir...)
	w.zero(172)       // clientTimeZone: UTC
	w.u32(0)          // clientSessionId
	w.u32(0x0000006F) // performanceFlags: disable wallpaper, animations, theming, etc.
	w.u16(0)          // cbAutoReconnectCookie
	return w.b
}

// --- Share control / share data headers ([MS-RDPBCGR] 2.2.8.1.1.1) -----------

const (
	pduTypeDemandActive  = 0x1
	pduTypeConfirmActive = 0x3
	pduTypeDeactivateAll = 0x6
	pduTypeData          = 0x7
	pduTypeServerRedir   = 0xA
)

// Data PDU types (pduType2).
const (
	pduType2Update          = 2
	pduType2Control         = 20
	pduType2Pointer         = 27
	pduType2Synchronize     = 31
	pduType2Input           = 28
	pduType2RefreshRect     = 33
	pduType2SuppressOutput  = 35
	pduType2ShutdownDenied  = 37
	pduType2SaveSessionInfo = 38
	pduType2FontList        = 39
	pduType2FontMap         = 40
	pduType2SetErrorInfo    = 47
	pduType2MonitorLayout   = 55
)

var pduType2Names = map[uint8]string{
	pduType2Update:          "Update",
	pduType2Control:         "Control",
	pduType2Pointer:         "Pointer",
	pduType2Synchronize:     "Synchronize",
	pduType2SuppressOutput:  "SuppressOutput",
	pduType2ShutdownDenied:  "ShutdownDenied",
	pduType2SaveSessionInfo: "SaveSessionInfo",
	pduType2FontList:        "FontList",
	pduType2FontMap:         "FontMap",
	pduType2SetErrorInfo:    "SetErrorInfo",
	pduType2MonitorLayout:   "MonitorLayout",
}

func shareControl(pduType uint16, source uint16, body []byte) []byte {
	var w wbuf
	w.u16(uint16(6 + len(body)))
	w.u16(pduType | 0x10) // TS_PROTOCOL_VERSION
	w.u16(source)
	w.bytes(body...)
	return w.b
}

func shareData(shareID uint32, source uint16, pduType2 uint8, body []byte) []byte {
	var w wbuf
	w.u32(shareID)
	w.u8(0)                      // pad
	w.u8(1)                      // streamId: STREAM_LOW
	w.u16(uint16(4 + len(body))) // uncompressedLength: from pduType2 onward
	w.u8(pduType2)
	w.u8(0)  // compressedType
	w.u16(0) // compressedLength
	w.bytes(body...)
	return shareControl(pduTypeData, source, w.b)
}

func synchronizeBody() []byte {
	var w wbuf
	w.u16(1)    // SYNCMSGTYPE_SYNC
	w.u16(1002) // targetUser: server channel
	return w.b
}

const (
	ctrlActionRequestControl = 1
	ctrlActionGrantedControl = 2
	ctrlActionCooperate      = 4
)

func controlBody(action uint16) []byte {
	var w wbuf
	w.u16(action)
	w.u16(0) // grantId
	w.u32(0) // controlId
	return w.b
}

func fontListBody() []byte {
	var w wbuf
	w.u16(0)      // numberFonts
	w.u16(0)      // totalNumFonts
	w.u16(0x0003) // FONTLIST_FIRST | FONTLIST_LAST
	w.u16(0x0032) // entrySize
	return w.b
}

func suppressOutputBody() []byte {
	// allowDisplayUpdates = SUPPRESS_DISPLAY_UPDATES; we draw nothing.
	return []byte{0, 0, 0, 0}
}

// allowOutputBody re-enables display updates for the whole desktop.
func allowOutputBody(width, height int) []byte {
	var w wbuf
	w.u8(1) // ALLOW_DISPLAY_UPDATES
	w.zero(3)
	w.u16(0)
	w.u16(0)
	w.u16(uint16(width - 1))
	w.u16(uint16(height - 1))
	return w.b
}

// refreshRectBody asks the server to repaint the whole desktop.
func refreshRectBody(width, height int) []byte {
	var w wbuf
	w.u8(1) // numberOfAreas
	w.zero(3)
	w.u16(0)
	w.u16(0)
	w.u16(uint16(width - 1))
	w.u16(uint16(height - 1))
	return w.b
}

// --- Licensing ([MS-RDPELE] / [MS-RDPBCGR] 2.2.1.12) --------------------------

const (
	licenseErrorAlert  = 0xFF
	statusValidClient  = 0x00000007
	licenseRequestType = 0x01
)

// parseLicensing handles the server licensing PDU. Servers that do not
// require a client license (e.g. administrative sessions) send an error
// alert with STATUS_VALID_CLIENT.
func parseLicensing(body []byte) error {
	r := newR(body)
	msgType := r.u8()
	r.u8()  // flags
	r.u16() // wMsgSize
	switch msgType {
	case licenseErrorAlert:
		code := r.u32()
		if r.err != nil {
			return fmt.Errorf("rdp: truncated license error alert")
		}
		if code != statusValidClient {
			return fmt.Errorf("rdp: licensing failed, error code 0x%x", code)
		}
		return nil
	case licenseRequestType:
		return fmt.Errorf("rdp: server requires RDS client licensing, which is not implemented yet")
	default:
		return fmt.Errorf("rdp: unexpected licensing message type 0x%02x", msgType)
	}
}

// --- Save Session Info ([MS-RDPBCGR] 2.2.10.1) ------------------------------

const (
	infoTypeLogon         = 0
	infoTypeLogonLong     = 1
	infoTypePlainNotify   = 2
	infoTypeLogonExtended = 3
)

// LogonInfo describes the session the server logged us on to.
type LogonInfo struct {
	SessionID uint32
	Domain    string
	User      string
}

// parseSaveSessionInfo returns logon info (when present) and whether this
// PDU signals that the logon completed.
func parseSaveSessionInfo(body []byte) (info LogonInfo, loggedOn bool, logonError *LogonError) {
	r := newR(body)
	switch r.u32() {
	case infoTypeLogon:
		cbDomain := r.u32()
		domain := r.take(52)
		cbUser := r.u32()
		user := r.take(512)
		info.SessionID = r.u32()
		info.Domain = fromUTF16(domain[:min(int(cbDomain), len(domain))])
		info.User = fromUTF16(user[:min(int(cbUser), len(user))])
		return info, true, nil
	case infoTypeLogonLong:
		r.u16() // version
		r.u32() // size
		info.SessionID = r.u32()
		cbDomain := int(r.u32())
		cbUser := int(r.u32())
		r.skip(558)
		info.Domain = fromUTF16(r.take(cbDomain))
		info.User = fromUTF16(r.take(cbUser))
		return info, true, nil
	case infoTypePlainNotify:
		return info, true, nil
	case infoTypeLogonExtended:
		r.u16() // length
		present := r.u32()
		if present&0x01 != 0 { // LOGON_EX_AUTORECONNECTCOOKIE
			n := int(r.u32())
			r.skip(n)
		}
		if present&0x02 != 0 { // LOGON_EX_LOGONERRORS
			r.u32() // cbFieldData
			typ := r.u32()
			data := r.u32()
			if r.err == nil {
				logonError = &LogonError{Type: typ, Data: data}
			}
		}
		return info, false, logonError
	}
	return info, false, nil
}

// LogonError is a logon error/warning reported by the server.
type LogonError struct {
	Type uint32
	Data uint32
}

func (e *LogonError) String() string {
	return fmt.Sprintf("logon notification type 0x%08x data 0x%08x", e.Type, e.Data)
}

// inputSyncBody is an Input PDU with one Synchronize event: no toggle keys
// (Scroll/Num/Caps Lock) active. Clients send this after activation.
func inputSyncBody() []byte {
	var w wbuf
	w.u16(1) // numEvents
	w.u16(0) // pad
	w.u32(0) // eventTime
	w.u16(0) // INPUT_EVENT_SYNC
	w.u16(0) // pad
	w.u32(0) // toggleFlags
	return w.b
}
