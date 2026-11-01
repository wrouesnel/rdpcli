# rdpcli

A statically linked Go command-line client for Windows Remote Desktop (RDP).
The goal is to give command-line access to Windows hosts that only have RDP
enabled (no WinRM/SSH), using a normal authenticated RDP session and its
standard virtual channels. It is also a vehicle for exploring the protocol.

Status: early. rdpcli can log on to an RDP session, save a screenshot of the
desktop, and show the desktop live in a local browser page (view only: no
keyboard or mouse input yet).

## Build

```sh
CGO_ENABLED=0 go build -o bin/rdpcli ./cmd/rdpcli
```

## Usage

```sh
# Password from the RDPCLI_PASSWORD environment variable, stdin
# (--password-stdin) or a terminal prompt; never from the command line.
rdpcli connect rdp.example.com -u 'EXAMPLE\alice' --tls-sha256 <fingerprint>
rdpcli connect 127.0.0.1 -u rdpadmin --password-stdin --tls-insecure --hold 30s -v

# Save the desktop as a PNG once it has finished drawing
rdpcli screenshot rdp.example.com -u alice -o desktop.png --tls-sha256 <fingerprint>

# Live view in a browser: prints a http://127.0.0.1:PORT/<token>/ URL to open
rdpcli view rdp.example.com -u alice --tls-sha256 <fingerprint>
```

The viewer listens on 127.0.0.1 only (change with `--listen`), and its URL
contains a random token so other local users cannot guess it. It is a plain
stdlib web page fed by Server-Sent Events, which keeps the binary static; a
native GUI toolkit would need cgo.

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
