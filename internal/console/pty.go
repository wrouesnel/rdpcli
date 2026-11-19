package console

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image"
	"io"
	"strconv"
	"strings"
)

// The interactive link runs a program in a pseudo console (ConPTY) on the
// remote side and carries its terminal both ways over the console window:
// output as pages on the screen, input as keys typed into the window. A C#
// helper (pty.cs) owns the pseudo console; it shows the program's output
// one page at a time and reads rdpcli's keys.
//
// Output page: a header row, then base64 text in rows of Cols-1 cells.
//
//	RDPCLI2 <id> <seq> <enc> <chars> <inseq> <status> <hash>
//
// enc is "b" for the raw bytes or "z" for raw deflate; chars is the length
// of the base64 text; inseq counts the input frames applied so far; status
// is "r" while the program runs, else its exit code; hash is the first 4
// bytes of the SHA-256 of the header up to status, a newline and the base64
// text, in hex. A page with data stays on screen, unchanged, until rdpcli
// acknowledges it by typing the last digit of seq+1. Then the helper shows
// page seq+1, empty until there is more output; it fills an empty page at
// most once. The program has ended and its output has all been sent when
// an empty page has a status other than "r"; rdpcli then types "q".
//
// Input frame, typed: <type><digit><payload>:<check>. with type "i" for
// bytes for the program (payload base64) or "w" for a resize (payload
// "cols,rows"), digit the frame's number mod 10, and check the first 2
// bytes of the SHA-256 of what precedes the colon, in hex. The helper
// applies a frame once, when its digit is the next one expected, and shows
// the count in inseq. One frame is in flight at a time. A "." on its own
// is ignored by the helper; rdpcli starts retries with one, which ends a
// frame left unfinished by a lost key. "q" ends the program; any other key
// redraws the page. rdpcli types "." when it has typed nothing else for
// 15 seconds; after 60 seconds without a key the helper ends the session,
// and closes its console, so a lost rdpcli does not leave it waiting
// forever.

//go:embed pty.cs
var ptyFile string

// ptySource is the helper's source with LF line endings, so its hash (and
// the class name) is the same whatever line endings the checkout used.
var ptySource = strings.ReplaceAll(ptyFile, "\r\n", "\n")

// PtyClass is the helper's class name: it carries a hash of the source, so
// a console kept open from another build never runs a different helper.
var PtyClass = func() string {
	sum := sha256.Sum256([]byte(ptySource))
	return "RdpcliPty" + hex.EncodeToString(sum[:4])
}()

// ptyLineMax is the longest line typed when installing the helper.
const ptyLineMax = 2000

// PtyInstallLines returns the PowerShell lines that compile the helper,
// gzipped and base64-encoded so it types quickly and needs no quoting. The
// last line clears the console when the helper is ready, and shows the
// error otherwise.
func PtyInstallLines() []string {
	src := strings.ReplaceAll(ptySource, "RdpcliPty", PtyClass)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.Write([]byte(src))
	zw.Close()
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	var lines []string
	op := "="
	for len(b64) > 0 {
		n := min(len(b64), ptyLineMax)
		lines = append(lines, "$rp"+op+"'"+b64[:n]+"'")
		op = "+="
		b64 = b64[n:]
	}
	lines = append(lines, "if(-not ('"+PtyClass+"' -as [type])){try{"+
		"$rz=[IO.Compression.GZipStream]::new([IO.MemoryStream]::new([Convert]::FromBase64String($rp)),[IO.Compression.CompressionMode]::Decompress);"+
		"Add-Type -TypeDefinition ([IO.StreamReader]::new($rz).ReadToEnd());cls}catch{$_}}else{cls}")
	return lines
}

// PtyRunLine returns the line that runs cmdline in a pseudo console of
// cols x rows cells.
func PtyRunLine(cmdline string, id uint32, cols, rows int) string {
	return fmt.Sprintf("[%s]::Run('%s',%d,%d,%d)", PtyClass, base64.StdEncoding.EncodeToString([]byte(cmdline)), id, cols, rows)
}

// StreamPage is one page of an interactive session's output.
type StreamPage struct {
	ID, Seq uint32
	InSeq   uint32 // input frames applied
	Data    []byte // output bytes, empty while waiting for more
	Running bool   // false once the program has exited and all output is sent
	Status  int    // the program's exit code, once it has exited
}

// ReadStream reads the page on screen, reading only the rows it needs.
// header reports that a header row was seen at all, ok that the whole page
// checked out.
func (r *Reader) ReadStream(img *image.RGBA) (p StreamPage, header, ok bool) {
	first := r.readRow(img, 0, nil)
	f := strings.Fields(first)
	if len(f) != 8 || f[0] != "RDPCLI2" {
		return p, false, false
	}
	lines := []string{first}
	if chars, err := strconv.Atoi(f[4]); err == nil && chars > 0 {
		w := r.Grid.Cols - 1
		n := min((chars+w-1)/w, r.Grid.Rows-1)
		for row := 1; row <= n; row++ {
			lines = append(lines, r.readRow(img, row, nil))
		}
	}
	p, ok = r.ReadStreamPage(Screen{Lines: lines})
	return p, true, ok
}

// ReadStreamPage reads a page from screen text.
func (r *Reader) ReadStreamPage(s Screen) (p StreamPage, ok bool) {
	if len(s.Lines) < 1 {
		return p, false
	}
	f := strings.Fields(s.Lines[0])
	if len(f) != 8 || f[0] != "RDPCLI2" {
		return p, false
	}
	var nums [4]uint64
	for i, v := range []string{f[1], f[2], f[4], f[5]} {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return p, false
		}
		nums[i] = n
	}
	p = StreamPage{ID: uint32(nums[0]), Seq: uint32(nums[1]), InSeq: uint32(nums[3]), Running: f[6] == "r"}
	if !p.Running {
		st, err := strconv.ParseUint(f[6], 10, 32)
		if err != nil {
			return p, false
		}
		p.Status = int(int32(uint32(st)))
	}
	chars := int(nums[2])

	width := r.Grid.Cols - 1
	var b strings.Builder
	for row := 1; row < len(s.Lines) && b.Len() < chars; row++ {
		line := s.Lines[row]
		if len(line) > width {
			line = line[:width]
		}
		b.WriteString(line)
	}
	data := b.String()
	if len(data) != chars {
		return p, false
	}
	sum := sha256.Sum256([]byte(strings.Join(f[:7], " ") + "\n" + data))
	if hex.EncodeToString(sum[:4]) != f[7] {
		return p, false
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return p, false
	}
	switch f[3] {
	case "b":
	case "z":
		if raw, err = io.ReadAll(flate.NewReader(bytes.NewReader(raw))); err != nil {
			return p, false
		}
	default:
		return p, false
	}
	p.Data = raw
	return p, true
}

// InputFrame returns the keys that send frame number seq: input bytes
// (kind 'i') or a resize to "cols,rows" (kind 'w').
func InputFrame(kind byte, seq uint32, payload []byte) string {
	body := string(kind) + strconv.Itoa(int(seq%10))
	if kind == 'i' {
		body += base64.StdEncoding.EncodeToString(payload)
	} else {
		body += string(payload)
	}
	sum := sha256.Sum256([]byte(body))
	return body + ":" + hex.EncodeToString(sum[:2]) + "."
}
