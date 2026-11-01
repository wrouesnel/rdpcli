#!/usr/bin/env bash
# Local Windows test VM for rdpcli development.
#
# Runs Windows Server 2025 Evaluation inside QEMU/KVM using the dockurr/windows
# container image (rootless podman). The image downloads the evaluation ISO from
# Microsoft and performs an unattended install on first start.
#
# RDP is published on 127.0.0.1 only. The web console (noVNC) on 127.0.0.1:8006
# shows install progress.
#
# Configuration (environment):
#   RDPCLI_VM_NAME      container name            (default: rdpcli-winvm)
#   RDPCLI_VM_STORAGE   VM disk directory         (default: ~/.local/share/rdpcli/winvm)
#   RDPCLI_VM_VERSION   dockurr VERSION value     (default: 2025)
#   RDPCLI_VM_RDP_PORT  host port for RDP         (default: 3389)
#   RDPCLI_VM_WEB_PORT  host port for web console (default: 8006)
#   RDPCLI_VM_USER      local admin user          (default: rdpadmin)
#   RDPCLI_VM_PASSWORD  local admin password      (required for "up")
set -euo pipefail

NAME="${RDPCLI_VM_NAME:-rdpcli-winvm}"
STORAGE="${RDPCLI_VM_STORAGE:-$HOME/.local/share/rdpcli/winvm}"
VERSION="${RDPCLI_VM_VERSION:-2025}"
RDP_PORT="${RDPCLI_VM_RDP_PORT:-3389}"
WEB_PORT="${RDPCLI_VM_WEB_PORT:-8006}"
VM_USER="${RDPCLI_VM_USER:-rdpadmin}"
IMAGE="docker.io/dockurr/windows:latest"

usage() {
    echo "usage: $0 up|down|status|logs" >&2
    exit 2
}

cmd_up() {
    if [[ -z "${RDPCLI_VM_PASSWORD:-}" ]]; then
        echo "RDPCLI_VM_PASSWORD must be set" >&2
        exit 1
    fi
    mkdir -p "$STORAGE"
    if podman container exists "$NAME"; then
        podman start "$NAME"
        return
    fi
    # Pass the password through the environment rather than the command line.
    USERNAME="$VM_USER" PASSWORD="$RDPCLI_VM_PASSWORD" \
    podman run -d --name "$NAME" \
        --device /dev/kvm --device /dev/net/tun \
        --cap-add NET_ADMIN \
        --group-add keep-groups \
        --stop-timeout 120 \
        -p "127.0.0.1:${WEB_PORT}:8006" \
        -p "127.0.0.1:${RDP_PORT}:3389/tcp" \
        -p "127.0.0.1:${RDP_PORT}:3389/udp" \
        -v "${STORAGE}:/storage" \
        -e VERSION="$VERSION" \
        -e RAM_SIZE=8G -e CPU_CORES=4 -e DISK_SIZE=64G \
        -e USERNAME -e PASSWORD \
        "$IMAGE"
}

case "${1:-}" in
    up) cmd_up ;;
    down) podman stop "$NAME" ;;
    status) podman ps -a --filter "name=^${NAME}$" ;;
    logs) podman logs -f "$NAME" ;;
    *) usage ;;
esac
