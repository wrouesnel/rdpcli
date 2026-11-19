# rdpcli

A statically linked Go command-line client for Windows Remote Desktop (RDP).
The goal is to give command-line access to Windows hosts that only have RDP
enabled (no WinRM/SSH), using a normal authenticated RDP session and its
standard virtual channels. It is also a vehicle for exploring the protocol.

Status: early. rdpcli can log on to an RDP session, save a screenshot of the
desktop, show and control the desktop from a local browser page (keyboard and
mouse), and run PowerShell in a console it opens on the remote desktop:
either a single command, its output read back off the screen, or an
interactive terminal session connected to the local terminal.

## Install

Release archives for Linux, macOS, Windows and FreeBSD are on the GitHub
releases page, each with a single statically linked binary; `SHA256SUMS`
lists their checksums. Or build from source:

```sh
CGO_ENABLED=0 go build -o bin/rdpcli ./cmd/rdpcli
go install github.com/wrouesnel/rdpcli/cmd/rdpcli@latest
```

`rdpcli version` prints the version.

## Releases

CI (`.github/workflows/ci.yml`) checks formatting, vets and tests on Linux,
macOS and Windows, and builds every release archive. Pushing a `v*` tag runs
`.github/workflows/release.yml`, which tests the tagged commit, builds the
archives with `scripts/build-release.sh` and publishes a GitHub release with
generated notes; a tag with a hyphen (`v1.0.0-rc.1`) makes a pre-release.
The script runs locally too (`scripts/build-release.sh v1.2.3` writes
`dist/`), and its builds are reproducible.

## Usage

```sh
# Password from the RDPCLI_PASSWORD environment variable, stdin
# (--password-stdin) or a terminal prompt; never from the command line.
rdpcli connect rdp.example.com -u 'EXAMPLE\alice' --tls-sha256 <fingerprint>
rdpcli connect 127.0.0.1 -u rdpadmin --password-stdin --tls-insecure --hold 30s -v

# Save the desktop as a PNG once it has finished drawing
rdpcli screenshot rdp.example.com -u alice -o desktop.png --tls-sha256 <fingerprint>

# Live desktop in a browser: prints a http://127.0.0.1:PORT/<token>/ URL to open
rdpcli view rdp.example.com -u alice --tls-sha256 <fingerprint>
rdpcli view rdp.example.com -u alice --view-only --tls-sha256 <fingerprint>
```

## Console: PowerShell over the screen and keyboard

```sh
rdpcli console rdp.example.com -u alice -c 'Get-Service | Where Status -eq Running' --tls-sha256 <fingerprint>
rdpcli console rdp.example.com -u alice --no-interactive -c 'hostname' ...   # in scripts
rdpcli console rdp.example.com -u alice -t ...                # interactive PowerShell in this terminal
```

`console` needs nothing on the server beyond an RDP logon: no WinRM, no
virtual channels (which policy often disables), no agent. It works like a
person at the keyboard:

1. It opens the Run box (Win+R) and starts
   `conhost.exe powershell.exe -NoProfile` with a calibration command on its
   command line. conhost is named so the console is a classic console window
   even where Windows Terminal is the default; PSReadLine is removed because
   it ignores the Unicode key events rdpcli types with.
2. The calibration command prints a strip of 16 cells in alternating
   colours, the printable ASCII characters, and the window size. From these
   rdpcli learns where the character cells are and what each character looks
   like in the console's font, so no font data is built in and any font or
   size works. RDP does not antialias text unless the client asks, so cells
   arrive exactly and are matched exactly.
3. Once that console is seen, rdpcli maximises it, calibrates again and
   types in a small helper function.
4. The command goes to the helper base64-encoded (so no quoting can break
   it). The helper runs it, captures every output stream, gzips the text and
   shows it as pages of base64: a header row (transfer id, page number, page
   count, length, SHA-256 prefix, status) and data rows. rdpcli reads each
   page, checks it, and types the page's acknowledgement key; only then does
   the helper show the next page. Output never scrolls past unread, and a
   page that doesn't check out (still being drawn) is waited for or redrawn.
   The output is printed exactly, in any language.

The exit code is the command's: `$LASTEXITCODE` of a failing native program,
1 if PowerShell reported an error, otherwise 0. Output is formatted for the
local terminal's width (`--output-width` to change).

Nothing is typed until the console has been seen on screen (the calibration
rows carry a random nonce, so an old console can't be mistaken for the new
one). If the console never appears, or the session is not logged on (a legal
notice, a password change), `console` starts the browser viewer, prints its
URL and asks you to sort out the desktop there, then press Continue.
`--no-interactive` makes it fail instead, for scripts.

Throughput is roughly 20–40 KB of text a second (12 pages of incompressible
text, 96 KB, in 2.7 s); a run takes about 12 s more, mostly waiting for
windows to appear. Current limits: output arrives once the command has
finished, not while it runs; the command cannot read input; and if rdpcli
gives up (`--command-timeout`), the command keeps running on the server until
it ends, after which the console closes.

### Interactive terminal (`-t`)

With `-t`, rdpcli runs `powershell.exe` (or, with `-c`, PowerShell running
that command) in a Windows pseudo console (ConPTY) on the remote side and
connects it to the local terminal, like `ssh -t`: full-screen programs,
colour, PSReadLine editing and tab completion, Ctrl+C, and terminal resizes
all work. Ctrl+] detaches. The exit code is the program's.

Instead of the paging function, rdpcli types in a small C# helper (gzipped,
compiled by Windows PowerShell's `Add-Type`, about 3 s) that owns the pseudo
console. Both directions go over the console window:

- **Output:** the helper shows the program's raw terminal output a page at a
  time, base64 (deflated when that carries more), with a header that holds
  the page number, the count of input frames applied, the program's state
  and a SHA-256 prefix over all of it. A page stays put until rdpcli types
  its acknowledgement, so nothing is skipped however fast the program
  writes.
- **Input:** keys typed locally go as checksummed, numbered frames
  (base64 bytes, or a new window size) typed into the console window; the
  helper applies each frame once and reports the count in the next header,
  and rdpcli sends a frame again if it does not see it counted.

rdpcli types a keepalive every 15 s while idle; if the helper hears nothing
for 60 s (rdpcli was killed, the network went), it ends the program and
closes its console rather than leave it on the desktop. Typed characters
echo in about 0.1–0.5 s; 3000 lines of output arrive in under 2 s. ConPTY
needs Windows 10 1809 / Server 2019 or later. `--command-timeout` does not
apply to `-t`.

## Viewer

The viewer listens on 127.0.0.1 only (change with `--listen`), and its URL
contains a random token so other local users cannot guess it. It is a plain
stdlib web page fed by Server-Sent Events, which keeps the binary static; a
native GUI toolkit would need cgo.

In the viewer, click the screen to give it the keyboard. Printable
characters are sent as Unicode key events, so they type the same whatever
the server's keyboard layout; shortcuts (with Ctrl, Alt or Win held) and
non-printing keys go as scancodes. "raw keys" sends everything as
scancodes, for programs that read physical keys. "Type clipboard" types the
local clipboard's text into the session as keystrokes, which works even
where clipboard redirection is disabled. Keys the browser keeps for itself
(such as Ctrl+W) cannot be sent; Ctrl+Alt+Del has a button.

If the session is active but Windows has not reported a logon within a few
seconds (a legal notice, a password change, a logon screen), `view` keeps
the session open so the logon can be completed in the browser.

Server certificates are verified against the system roots by default. Most RDP
hosts use self-signed certificates, so pin one with `--tls-sha256` (the
fingerprint is printed on connect) or skip verification with `--tls-insecure`.

## Implemented so far

| Layer | Spec | Notes |
|---|---|---|
| TPKT / X.224, security negotiation | MS-RDPBCGR 2.2.1.1–2 | requests TLS + CredSSP |
| TLS | | capped at TLS 1.2, see below |
| CredSSP (NLA) with NTLMv2 | MS-CSSP, MS-NLMP | TSRequest v6 with nonce binding; NTLM tested against MS-NLMP 4.2.4 vectors |
| MCS / GCC connect, attach, channel join | T.125, T.124, MS-RDPBCGR 2.2.1.3–8 | no virtual channels yet |
| Client Info, licensing | MS-RDPBCGR 2.2.1.11–12 | only "valid client" licensing (no RDS CAL flow) |
| Capability exchange, finalization | MS-RDPBCGR 2.2.1.13–22 | bitmap updates only (no drawing orders); `connect` asks the server to suppress output |
| Save Session Info (logon notification) | MS-RDPBCGR 2.2.10.1 | |
| Fast-path output, bitmap updates | MS-RDPBCGR 2.2.9.1.2 | with fragment reassembly; no bulk compression, no pointer shapes yet |
| Interleaved RLE bitmap codec | MS-RDPBCGR 2.2.9.1.1.3.1.2.4 | 15/16/24 bpp; the session runs at 16 bpp |
| Keyboard and mouse input | MS-RDPBCGR 2.2.8.1.1.3 | slow-path Input PDUs: scancode, Unicode, mouse, extended buttons, wheel, sync |
| Console text reading | | calibrated glyph matching on conhost; see "Console" above |
| Interactive terminal | | ConPTY behind a C# helper, paged over the console window; see "Interactive terminal" |

## Protocol notes

- **TLS 1.3:** Windows Server 2025 aborts CredSSP with a TLS `internal_error`
  alert as soon as the first TSRequest arrives over TLS 1.3. Over TLS 1.2 it
  works, so the client caps TLS at 1.2 unless the caller sets `MaxVersion`.
- **Reconnect race:** connecting again within a few seconds of a previous
  connection to the same session occasionally (~10%) gets the new connection
  dropped right after activation, with no Set Error Info. A graceful
  disconnect (MCS Disconnect Provider Ultimatum + TLS close_notify, then
  waiting for the server to close) does not prevent it, so `connect` retries
  that case.
- **Screen updates need fast-path:** Windows Server 2025 sends no legacy
  bitmap updates at all unless the client advertises
  `FASTPATH_OUTPUT_SUPPORTED`; it does not fall back to slow-path Update PDUs,
  and Refresh Rect / Suppress Output do not change that.
- **Input right after connecting:** Windows ignores keystrokes for a moment
  after a client connects, while it switches the session over to the new
  connection. `console` waits for the screen to stop changing before it types.
- **Input bursts:** a single Input PDU carrying a long string (120
  characters, 240 Unicode key events) reached conhost with characters lost
  and reordered; 24 characters per PDU, 10 ms apart, arrive intact.
- **Unicode keys and PSReadLine:** PSReadLine (loaded by default in
  PowerShell 5.1) ignores Unicode key events (VK_PACKET), so text typed that
  way never reaches the prompt. Without PSReadLine, conhost takes them.
- **ConPTY terminal modes:** the pseudo console turns on focus reporting
  and win32-input-mode (`?1004h`, `?9001h`) on the terminal when it starts
  and turns them off only when the program exits normally; on a detach
  rdpcli turns them off itself.
- **Open question:** one early run was rejected after Confirm Active with
  `ERRINFO_BAD_CAPABILITIES` (0x10EA) and has not reproduced since, with the
  same capability sets.

## Test environment

`testenv/winvm.sh` runs a local Windows Server 2025 Evaluation VM in QEMU/KVM
via the [dockur/windows](https://github.com/dockur/windows) container image,
with RDP published on `127.0.0.1:3389`.

```sh
export RDPCLI_VM_PASSWORD=...   # local admin password for the VM
testenv/winvm.sh up             # first start downloads and installs Windows
testenv/winvm.sh logs           # follow install progress (or http://127.0.0.1:8006)
testenv/winvm.sh down
```

The default admin user is `rdpadmin`. Check the VM with a reference client
(FreeRDP 3; the password is read from stdin so it stays off the command line):

```sh
# NLA authentication only (exit 0 on success)
printf '%s\n' "$RDPCLI_VM_PASSWORD" | \
  xfreerdp3 /v:127.0.0.1 /u:rdpadmin /cert:ignore /auth-only /from-stdin:force

# Full console session on a virtual display
printf '%s\n' "$RDPCLI_VM_PASSWORD" | \
  xvfb-run -a xfreerdp3 /v:127.0.0.1 /u:rdpadmin /admin /cert:ignore /from-stdin:force
```
