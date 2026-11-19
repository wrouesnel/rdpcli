package console

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The link moves a command's output across the screen without losing any
// of it to scrolling. A PowerShell helper (HelperFunction) runs the
// command, gzips its output and shows it base64-encoded, one page at a
// time: a header row, then data rows. rdpcli reads each page off the
// screen, checks it against the header and acknowledges it by typing the
// last digit of the next page's number, so a repeated acknowledgement is
// harmless; any other key makes the helper redraw the page and "q" stops
// the transfer. Nothing moves on until rdpcli has the page, so nothing can
// scroll away unread.
//
// Header row: RDPCLI1 <id> <seq> <pages> <chars> <sha256-prefix> <status>
//
// chars is the page's base64 length; the hash is the first 4 bytes of the
// SHA-256 of the page's base64 text, in hex; status is the command's
// result (0 for success, $LASTEXITCODE for a failing native program, 1
// for PowerShell errors).

// HelperFunction defines the PowerShell function RdpcliRun that runs a command
// (UTF-8, base64-encoded) and pages its output. The command runs as a
// script block in a child scope, so it cannot overwrite the helper's
// variables; Invoke-Expression is not used because its non-terminating
// errors escape *>&1 redirection. All output streams are captured, with
// PowerShell's usual WARNING:/VERBOSE:/DEBUG: prefixes. It is one line, to be
// typed at the prompt. Its rows leave out the window's last column and
// row, so writing them never scrolls the console. PowerShell variable
// names are case-insensitive, so every variable here has a distinct name.
const HelperFunction = `function RdpcliRun($c,$id,$ow){$cw=$Host.UI.RawUI.WindowSize.Width-1;$rh=$Host.UI.RawUI.WindowSize.Height-2;` +
	`$global:LASTEXITCODE=0;$o=@();try{$o=@(& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($c)))) *>&1)}catch{$o+=$_};` +
	`$st=if($LASTEXITCODE){$LASTEXITCODE}elseif($o|?{$_ -is [Management.Automation.ErrorRecord]}){1}else{0};` +
	`$o=$o|%{if($_ -is [Management.Automation.WarningRecord]){'WARNING: '+$_.Message}elseif($_ -is [Management.Automation.VerboseRecord]){'VERBOSE: '+$_.Message}` +
	`elseif($_ -is [Management.Automation.DebugRecord]){'DEBUG: '+$_.Message}else{$_}};` +
	`$b=[Text.Encoding]::UTF8.GetBytes(($o|Out-String -Width $ow));$m=New-Object IO.MemoryStream;` +
	`$z=New-Object IO.Compression.GZipStream($m,[IO.Compression.CompressionMode]::Compress);$z.Write($b,0,$b.Length);$z.Close();` +
	`$d=[Convert]::ToBase64String($m.ToArray());$cap=$cw*$rh;$nt=[Math]::Max(1,[Math]::Ceiling($d.Length/$cap));` +
	`[Console]::CursorVisible=$false;cls;$sq=0;while($sq -lt $nt){$pg=$d.Substring($sq*$cap,[Math]::Min($cap,$d.Length-$sq*$cap));` +
	`$hs=-join([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($pg))[0..3]|%{$_.ToString('x2')});` +
	`[Console]::SetCursorPosition(0,0);[Console]::Write(('RDPCLI1 '+$id+' '+$sq+' '+$nt+' '+$pg.Length+' '+$hs+' '+$st).PadRight($cw));` +
	`for($ri=0;$ri -lt $rh;$ri++){$q=$ri*$cw;$l=if($q -lt $pg.Length){$pg.Substring($q,[Math]::Min($cw,$pg.Length-$q))}else{''};` +
	`[Console]::SetCursorPosition(0,$ri+1);[Console]::Write($l.PadRight($cw))};` +
	`$k=[Console]::ReadKey($true).KeyChar;if([string]$k -eq [string](($sq+1)%10)){$sq++}elseif($k -eq 'q'){break}};cls;[Console]::CursorVisible=$true}`

// AckKey is the key that acknowledges page seq.
func AckKey(seq uint32) string { return strconv.Itoa(int((seq + 1) % 10)) }

// RunLine returns the line that runs command through the helper, with
// output formatted for width columns.
func RunLine(command string, id uint32, width int) string {
	return fmt.Sprintf("RdpcliRun '%s' %d %d", base64.StdEncoding.EncodeToString([]byte(command)), id, width)
}

// Page is one page of a transfer, read off the screen.
type Page struct {
	ID, Seq, Pages uint32
	Status         int
	Data           string // the page's base64 text
}

// ReadPage reads the page on screen. ok is false when there is no page, or
// it is incomplete or does not match its header (still being drawn).
func (r *Reader) ReadPage(s Screen) (p Page, ok bool) {
	if len(s.Lines) < 2 {
		return p, false
	}
	f := strings.Fields(s.Lines[0])
	if len(f) != 7 || f[0] != "RDPCLI1" {
		return p, false
	}
	var nums [4]uint64
	for i, v := range []string{f[1], f[2], f[3], f[4]} {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return p, false
		}
		nums[i] = n
	}
	status, err := strconv.Atoi(f[6])
	if err != nil {
		return p, false
	}
	p = Page{ID: uint32(nums[0]), Seq: uint32(nums[1]), Pages: uint32(nums[2]), Status: status}
	chars := int(nums[3])

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
	sum := sha256.Sum256([]byte(data))
	if hex.EncodeToString(sum[:4]) != f[5] {
		return p, false
	}
	p.Data = data
	return p, true
}

// DecodeOutput turns the concatenated pages back into the command's text.
func DecodeOutput(data string) (string, error) {
	gz, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("console: transfer is not valid base64: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", fmt.Errorf("console: transfer is not gzip: %w", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		return "", fmt.Errorf("console: transfer: %w", err)
	}
	return string(out), nil
}
