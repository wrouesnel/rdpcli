package console

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// streamScreen lays out a page the way pty.cs does.
func streamScreen(id, seq uint32, enc string, data string, inseq uint32, st string, cols int) Screen {
	head := fmt.Sprintf("RDPCLI2 %d %d %s %d %d %s", id, seq, enc, len(data), inseq, st)
	sum := sha256.Sum256([]byte(head + "\n" + data))
	s := Screen{Lines: []string{head + " " + hex.EncodeToString(sum[:4])}}
	w := cols - 1
	for i := 0; i < len(data); i += w {
		s.Lines = append(s.Lines, data[i:min(i+w, len(data))])
	}
	return s
}

func TestReadStreamPage(t *testing.T) {
	r := &Reader{Grid: Grid{Cols: 40, Rows: 30}}
	want := []byte("\x1b[2J\x1b[HPS C:\\> héllo\r\n" + strings.Repeat("x", 500))

	raw := base64.StdEncoding.EncodeToString(want)
	p, ok := r.ReadStreamPage(streamScreen(5, 3, "b", raw, 7, "r", 40))
	if !ok || !bytes.Equal(p.Data, want) || p.ID != 5 || p.Seq != 3 || p.InSeq != 7 || !p.Running {
		t.Errorf("raw page read as %+v, %v", p, ok)
	}

	var zb bytes.Buffer
	zw, _ := flate.NewWriter(&zb, flate.BestCompression)
	zw.Write(want)
	zw.Close()
	z := base64.StdEncoding.EncodeToString(zb.Bytes())
	p, ok = r.ReadStreamPage(streamScreen(5, 4, "z", z, 7, "r", 40))
	if !ok || !bytes.Equal(p.Data, want) {
		t.Errorf("deflated page read as %q, %v", p.Data, ok)
	}

	p, ok = r.ReadStreamPage(streamScreen(5, 9, "b", "", 8, "3221225786", 40))
	if !ok || len(p.Data) != 0 || p.Running || p.Status != -1073741510 {
		t.Errorf("final page read as %+v, %v", p, ok)
	}

	// The hash covers the header: a torn header is rejected.
	torn := streamScreen(5, 3, "b", raw, 7, "r", 40)
	torn.Lines[0] = strings.Replace(torn.Lines[0], " 7 r ", " 8 r ", 1)
	short := streamScreen(5, 3, "b", raw, 7, "r", 40)
	short.Lines = short.Lines[:len(short.Lines)-1]
	for name, s := range map[string]Screen{"torn header": torn, "missing row": short} {
		if _, ok := r.ReadStreamPage(s); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestInputFrame(t *testing.T) {
	f := InputFrame('i', 12, []byte("dir\r"))
	body := "i2" + base64.StdEncoding.EncodeToString([]byte("dir\r"))
	sum := sha256.Sum256([]byte(body))
	if want := body + ":" + hex.EncodeToString(sum[:2]) + "."; f != want {
		t.Errorf("frame %q, want %q", f, want)
	}
	if f := InputFrame('w', 0, []byte("80,24")); !strings.HasPrefix(f, "w080,24:") || strings.Count(f, ".") != 1 {
		t.Errorf("resize frame %q", f)
	}
}

func TestPtyInstallLines(t *testing.T) {
	lines := PtyInstallLines()
	var b64 strings.Builder
	for _, l := range lines {
		if len(l) > ptyLineMax+16 || strings.ContainsAny(l, "\"\r\n") {
			t.Errorf("unsuitable line: %.60q", l)
		}
		if strings.HasPrefix(l, "$rp") {
			b64.WriteString(l[strings.Index(l, "'")+1 : len(l)-1])
		}
	}
	gz, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	src, _ := io.ReadAll(zr)
	if !strings.Contains(string(src), "public class "+PtyClass+"\n") || strings.Contains(string(src), "RdpcliPty\n") {
		t.Error("helper source not renamed")
	}
	if !strings.Contains(lines[len(lines)-1], PtyClass) {
		t.Error("last line does not load the helper")
	}
}
