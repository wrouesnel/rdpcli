package console

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
	"os"
	"strings"
	"testing"
)

func loadPNG(t *testing.T, path string) *image.RGBA {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	src, err := png.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewRGBA(src.Bounds())
	draw.Draw(img, img.Rect, src, src.Bounds().Min, draw.Src)
	return img
}

// A conhost window on Windows Server 2025 over RDP, after
// CalibrationCommand.
func TestCalibrateRealScreen(t *testing.T) {
	img := loadPNG(t, "testdata/calibrated.png")
	r, err := Calibrate(img)
	if err != nil {
		t.Fatal(err)
	}
	g := r.Grid
	if g.CellW != 8 || g.CellH != 16 || g.Cols != 125 || g.Rows != 43 {
		t.Errorf("grid %+v, want 8x16 cells, 125x43", g)
	}
	s := r.Read(img)
	want := []string{
		"",
		`!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` + "`abcdefghijklmnopqrstuvwxyz{|}~",
		fmt.Sprintf("125 43 %d", r.Nonce),
		`PS C:\Users\rdpadmin>`,
	}
	for i, w := range want {
		if s.Lines[i] != w {
			t.Errorf("line %d: got %q, want %q", i, s.Lines[i], w)
		}
	}
	if s.CursorRow != 3 || s.CursorCol != len(`PS C:\Users\rdpadmin> `) {
		t.Errorf("cursor at %d,%d", s.CursorRow, s.CursorCol)
	}
	for i := 4; i < len(s.Lines); i++ {
		if s.Lines[i] != "" {
			t.Errorf("line %d: got %q, want blank", i, s.Lines[i])
		}
	}
}

// A synthetic screen: random glyph bitmaps, coloured text and an offset
// grid, to check the reader does not depend on one font or palette.
func TestSyntheticScreen(t *testing.T) {
	const cw, ch, cols, rows = 7, 13, 100, 8
	rng := rand.New(rand.NewSource(1))
	font := map[rune][]bool{}
	for c := rune(firstGlyph); c <= lastGlyph; c++ {
		bits := make([]bool, cw*ch)
		for i := range bits {
			bits[i] = rng.Intn(3) == 0
		}
		bits[0] = true // never blank
		font[c] = bits
	}
	img := image.NewRGBA(image.Rect(0, 0, 800, 200))
	bg := color.RGBA{12, 12, 12, 255}
	draw.Draw(img, img.Rect, &image.Uniform{bg}, image.Point{}, draw.Src)
	ox, oy := 5, 9
	put := func(col, row int, c rune, fg, back color.RGBA) {
		for y := 0; y < ch; y++ {
			for x := 0; x < cw; x++ {
				p := back
				if c != ' ' && font[c][y*cw+x] {
					p = fg
				}
				img.SetRGBA(ox+col*cw+x, oy+row*ch+y, p)
			}
		}
	}
	text := func(row int, s string, fg, back color.RGBA) {
		for i, c := range s {
			put(i, row, c, fg, back)
		}
	}
	white := color.RGBA{200, 200, 200, 255}
	for i := 0; i < stripCells; i++ {
		c := color.RGBA{140, 20, 156, 255}
		if i%2 == 1 {
			c = color.RGBA{57, 150, 222, 255}
		}
		put(i, 0, ' ', white, c)
	}
	var alphabet strings.Builder
	for c := rune(firstGlyph); c <= lastGlyph; c++ {
		alphabet.WriteRune(c)
	}
	text(1, alphabet.String(), white, bg)
	text(2, "100 8 42", white, bg)
	text(4, "Error: in red on yellow", color.RGBA{255, 0, 0, 255}, color.RGBA{255, 255, 0, 255})

	r, err := Calibrate(img)
	if err != nil {
		t.Fatal(err)
	}
	if r.Grid != (Grid{X: ox, Y: oy, CellW: cw, CellH: ch, Cols: cols, Rows: rows}) || r.Nonce != 42 {
		t.Fatalf("grid %+v, nonce %d", r.Grid, r.Nonce)
	}
	s := r.Read(img)
	if s.Lines[4] != "Error: in red on yellow" {
		t.Errorf("coloured line read as %q", s.Lines[4])
	}
}

func TestNoCalibration(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	if _, err := Calibrate(img); err != ErrNoCalibration {
		t.Errorf("got %v, want ErrNoCalibration", err)
	}
}
