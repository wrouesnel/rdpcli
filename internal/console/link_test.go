package console

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// screenFor lays a page out the way the helper does: a header row, then
// the base64 text in rows of cols-1 characters.
func screenFor(id, seq, pages uint32, status int, data string, cols, rows int) Screen {
	sum := sha256.Sum256([]byte(data))
	s := Screen{Lines: []string{fmt.Sprintf("RDPCLI1 %d %d %d %d %s %d", id, seq, pages, len(data), hex.EncodeToString(sum[:4]), status)}}
	w := cols - 1
	for i := 0; i < len(data); i += w {
		s.Lines = append(s.Lines, data[i:min(i+w, len(data))])
	}
	for len(s.Lines) < rows {
		s.Lines = append(s.Lines, "")
	}
	return s
}

func TestReadPageAndDecode(t *testing.T) {
	want := "héllo\r\nwörld\r\n" + strings.Repeat("x", 3000)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(want))
	zw.Close()
	data := base64.StdEncoding.EncodeToString(buf.Bytes())

	r := &Reader{Grid: Grid{Cols: 40, Rows: 30}}
	p, ok := r.ReadPage(screenFor(7, 0, 1, 3, data, 40, 30))
	if !ok {
		t.Fatal("page not accepted")
	}
	if p.ID != 7 || p.Seq != 0 || p.Pages != 1 || p.Status != 3 {
		t.Errorf("header read as %+v", p)
	}
	got, err := DecodeOutput(p.Data)
	if err != nil || got != want {
		t.Errorf("decoded %q, %v", got, err)
	}
}

func TestReadPageRejectsDamage(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("abc", 200)))
	r := &Reader{Grid: Grid{Cols: 40, Rows: 30}}
	good := screenFor(1, 2, 5, 0, data, 40, 30)

	misread := screenFor(1, 2, 5, 0, data, 40, 30)
	misread.Lines[3] = strings.Replace(misread.Lines[3], misread.Lines[3][:1], "�", 1)
	short := screenFor(1, 2, 5, 0, data, 40, 30)
	short.Lines[2] = ""
	for name, s := range map[string]Screen{"misread cell": misread, "row not drawn yet": short, "no header": {Lines: good.Lines[1:]}} {
		if _, ok := r.ReadPage(s); ok {
			t.Errorf("%s: damaged page accepted", name)
		}
	}
	if _, ok := r.ReadPage(good); !ok {
		t.Error("good page rejected")
	}
}

func TestAckKey(t *testing.T) {
	for seq, want := range map[uint32]string{0: "1", 8: "9", 9: "0", 19: "0"} {
		if got := AckKey(seq); got != want {
			t.Errorf("AckKey(%d) = %q, want %q", seq, got, want)
		}
	}
}

func TestHelperFitsOneLine(t *testing.T) {
	if strings.ContainsAny(HelperFunction, "\r\n") {
		t.Error("helper must be a single line")
	}
	if strings.Contains(HelperFunction, `"`) {
		t.Error("helper should not need double quotes")
	}
}
