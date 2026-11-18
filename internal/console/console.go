// Package console reads the text of a Windows console window off the
// screen.
//
// A calibration command prints three things at the top of a cleared
// console: a strip of 16 cells with alternating background colours, the
// printable ASCII characters, and the window size in cells. The strip
// gives the cell size and the grid's origin; the ASCII row gives the
// font's glyphs, so no font data is shipped and any console font or size
// works; the size line gives the grid's extent. Text is then read cell by
// cell by matching each cell's ink against the learned glyphs.
//
// This relies on the screen arriving exactly, without antialiasing: true
// over RDP, where Windows does not smooth fonts unless the client asks.
package console

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"strconv"
	"strings"
)

// CalibrationCommand returns the PowerShell command line that prints the
// calibration rows. It starts with cls, so the strip is the console's top
// row. The nonce is printed on the size line, so a console left over from
// an earlier run cannot be mistaken for this one. It uses no double quotes,
// so it can be passed on a powershell.exe command line unescaped. VT colour
// sequences need Windows 10 or later.
func CalibrationCommand(nonce uint32) string {
	return fmt.Sprintf(`cls;$e=[char]27;-join(0..15|%%{$e+'['+(45+$_%%2)+'m '})+$e+'[0m';-join[char[]](33..126);$s=$Host.UI.RawUI.WindowSize;''+$s.Width+' '+$s.Height+' %d'`, nonce)
}

const (
	stripCells = 16
	firstGlyph = '!'
	lastGlyph  = '~'
)

// Unknown is returned for a cell whose ink matches no learned glyph.
const Unknown = '�'

// Grid is where the console's character cells are on the screen.
type Grid struct {
	X, Y         int // top-left pixel of cell (0, 0)
	CellW, CellH int
	Cols, Rows   int
}

func (g Grid) cell(col, row int) image.Rectangle {
	x, y := g.X+col*g.CellW, g.Y+row*g.CellH
	return image.Rect(x, y, x+g.CellW, y+g.CellH)
}

// Reader reads console text using a calibrated grid and font.
type Reader struct {
	Grid   Grid
	Nonce  uint32          // from the size line
	glyphs map[string]rune // ink bitmap -> character
	cursor string          // ink bitmap of the cursor on a blank cell, if known
}

// Screen is the text read from the console window.
type Screen struct {
	Lines []string // one per row, trailing spaces removed
	// CursorRow and CursorCol give the cursor position, or -1 when the
	// cursor was not seen.
	CursorRow, CursorCol int
}

// ErrNoCalibration means the calibration rows were not found on screen.
var ErrNoCalibration = errors.New("console: calibration rows not found on screen")

// Calibrate finds the calibration rows printed by CalibrationCommand in img
// and learns the grid and font from them. Check the Reader's Nonce, and
// HasCursor to know the prompt after the rows has been drawn.
func Calibrate(img *image.RGBA) (*Reader, error) {
	g, ok := findStrip(img)
	if !ok {
		return nil, ErrNoCalibration
	}
	n := int(lastGlyph - firstGlyph + 1)
	if g.X+n*g.CellW > img.Rect.Max.X || g.Y+3*g.CellH > img.Rect.Max.Y {
		return nil, fmt.Errorf("console: calibration rows run off the screen")
	}
	r := &Reader{Grid: g, glyphs: make(map[string]rune)}
	for i := 0; i < n; i++ {
		ink, blank := cellInk(img, g.cell(i, 1))
		if blank {
			return nil, fmt.Errorf("console: calibration glyph %q is blank (console narrower than %d columns?)", rune(firstGlyph+i), n)
		}
		key := string(ink)
		if prev, dup := r.glyphs[key]; dup {
			return nil, fmt.Errorf("console: glyphs %q and %q look identical", prev, rune(firstGlyph+i))
		}
		r.glyphs[key] = rune(firstGlyph + i)
	}

	// The size line: "COLS ROWS". Read only its first cells: past the
	// window's right edge is the scroll bar, which is not text.
	r.Grid.Cols = 24
	line := strings.TrimSpace(r.readRow(img, 2, nil))
	cols, rows, nonce, ok := parseSize(line)
	if !ok {
		return nil, fmt.Errorf("console: could not read the window size line (read %q)", line)
	}
	if g.X+cols*g.CellW > img.Rect.Max.X || g.Y+rows*g.CellH > img.Rect.Max.Y {
		return nil, fmt.Errorf("console: window of %dx%d cells does not fit on the screen", cols, rows)
	}
	r.Grid.Cols, r.Grid.Rows = cols, rows
	r.Nonce = nonce

	// The prompt follows the calibration rows, with the cursor after it:
	// learn the cursor's shape as the first cell on that row that is not
	// blank and not a glyph.
	for row := 3; row < rows && r.cursor == ""; row++ {
		for col := 0; col < cols; col++ {
			ink, blank := cellInk(img, r.Grid.cell(col, row))
			if blank {
				continue
			}
			if _, ok := r.glyphs[string(ink)]; !ok {
				r.cursor = string(ink)
				break
			}
		}
	}
	return r, nil
}

func parseSize(s string) (cols, rows int, nonce uint32, ok bool) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return 0, 0, 0, false
	}
	c, err1 := strconv.Atoi(f[0])
	r, err2 := strconv.Atoi(f[1])
	n, err3 := strconv.ParseUint(f[2], 10, 32)
	if err1 != nil || err2 != nil || err3 != nil || c < 1 || r < 1 {
		return 0, 0, 0, false
	}
	return c, r, uint32(n), true
}

// HasCursor reports whether the cursor's shape was learned, which happens
// once the prompt after the calibration rows has been drawn.
func (r *Reader) HasCursor() bool { return r.cursor != "" }

// Read reads the whole console window.
func (r *Reader) Read(img *image.RGBA) Screen {
	s := Screen{CursorRow: -1, CursorCol: -1}
	for row := 0; row < r.Grid.Rows; row++ {
		var cur int = -1
		s.Lines = append(s.Lines, r.readRow(img, row, &cur))
		if cur >= 0 {
			s.CursorRow, s.CursorCol = row, cur
		}
	}
	return s
}

// readRow reads one row; if cursorCol is not nil it receives the cursor's
// column when the cursor is on this row.
func (r *Reader) readRow(img *image.RGBA, row int, cursorCol *int) string {
	var b strings.Builder
	for col := 0; col < r.Grid.Cols; col++ {
		ink, blank := cellInk(img, r.Grid.cell(col, row))
		if blank {
			b.WriteByte(' ')
			continue
		}
		ch, isCursor := r.match(ink)
		if isCursor && cursorCol != nil {
			*cursorCol = col
		}
		b.WriteRune(ch)
	}
	return strings.TrimRight(b.String(), " ")
}

// match identifies one cell's ink.
func (r *Reader) match(ink []byte) (ch rune, cursor bool) {
	if ch, ok := r.glyphs[string(ink)]; ok {
		return ch, false
	}
	if r.cursor != "" {
		if string(ink) == r.cursor {
			return ' ', true
		}
		// The cursor drawn over a character inverts the pixels it covers.
		x := []byte(string(ink))
		for i := range x {
			x[i] ^= r.cursor[i]
		}
		if ch, ok := r.glyphs[string(x)]; ok {
			return ch, true
		}
	}
	return Unknown, false
}

// cellInk binarises one cell: the most common colour in the cell is the
// background and every other pixel is ink. That reads any foreground and
// background colours alike. The result has one byte per pixel (0 or 1).
func cellInk(img *image.RGBA, rect image.Rectangle) (ink []byte, blank bool) {
	counts := make(map[color.RGBA]int)
	var bg color.RGBA
	best := 0
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			c := img.RGBAAt(x, y)
			counts[c]++
			if counts[c] > best {
				best, bg = counts[c], c
			}
		}
	}
	ink = make([]byte, 0, rect.Dx()*rect.Dy())
	blank = true
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		for x := rect.Min.X; x < rect.Max.X; x++ {
			if img.RGBAAt(x, y) != bg {
				ink = append(ink, 1)
				blank = false
			} else {
				ink = append(ink, 0)
			}
		}
	}
	return ink, blank
}

// findStrip locates the calibration strip: 16 runs of equal width
// alternating between two colours on each of CellH consecutive rows.
func findStrip(img *image.RGBA) (Grid, bool) {
	b := img.Rect
	for y := b.Min.Y; y < b.Max.Y; y++ {
		x, w, ok := stripInRow(img, y)
		if !ok {
			continue
		}
		h := 1
		for y+h < b.Max.Y {
			x2, w2, ok := stripInRow(img, y+h)
			if !ok || x2 != x || w2 != w {
				break
			}
			h++
		}
		if h >= 4 {
			return Grid{X: x, Y: y, CellW: w, CellH: h}, true
		}
		y += h - 1
	}
	return Grid{}, false
}

func stripInRow(img *image.RGBA, y int) (x0, w int, ok bool) {
	b := img.Rect
	// Split the row into runs of one colour.
	type run struct {
		x, n int
		c    color.RGBA
	}
	var runs []run
	for x := b.Min.X; x < b.Max.X; x++ {
		c := img.RGBAAt(x, y)
		if len(runs) > 0 && runs[len(runs)-1].c == c {
			runs[len(runs)-1].n++
			continue
		}
		runs = append(runs, run{x: x, n: 1, c: c})
	}
	for i := 0; i+stripCells <= len(runs); i++ {
		a, c := runs[i].c, runs[i+1].c
		w := runs[i].n
		if a == c || w < 3 {
			continue
		}
		match := true
		for j := 0; j < stripCells && match; j++ {
			r := runs[i+j]
			want := a
			if j%2 == 1 {
				want = c
			}
			match = r.n == w && r.c == want
		}
		if match {
			return runs[i].x, w, true
		}
	}
	return 0, 0, false
}
