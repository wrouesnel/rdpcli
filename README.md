# rdpcli

A statically linked Go command-line client for Windows Remote Desktop (RDP).
The goal is to give command-line access to Windows hosts that only have RDP
enabled (no WinRM/SSH), using a normal authenticated RDP session and its
standard virtual channels. It is also a vehicle for exploring the protocol.

Status: early. Nothing usable yet.

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
