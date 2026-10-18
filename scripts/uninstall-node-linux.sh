#!/usr/bin/env bash
# Stop the node/master services and retain the protected state for identity
# reuse. Default keeps root-only snapshots of /var/lib/lattice and
# /etc/lattice; --purge removes those snapshots and their identities. Never
# touches the separately installed bootstrapper control service.
set -euo pipefail
umask 077
PURGE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE=1; shift;;
        *) echo "Unknown uninstall option" >&2; exit 1;;
    esac
done
[[ "$(id -u)" == 0 ]] || { echo "Uninstall requires sudo/root" >&2; exit 1; }
ROOT=""
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then
    ROOT="${LATTICE_INSTALL_TEST_ROOT:?}"
    [[ -d "$ROOT" && "$ROOT" != / ]] || exit 1
fi

BIN="$ROOT/usr/local/lib/lattice"
STATE="$ROOT/var/lib/lattice"
ETC="$ROOT/etc/lattice"
UNITS="$ROOT/etc/systemd/system"
SOCKET_DIR="$ROOT/run/lattice"
SOCKET="$SOCKET_DIR/node.sock"

PRESENT=0
for service in lattice-node lattice-master; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then PRESENT=1; fi
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then PRESENT=1; fi
done
for service in lattice-node lattice-master; do
    systemctl disable --now "$service" 2>/dev/null || true
done
for unit in lattice-node.service lattice-master.service; do
    rm -f "$UNITS/$unit"
done
rm -f "$SOCKET"
rmdir "$SOCKET_DIR" 2>/dev/null || true
rm -rf "$BIN"

RETAIN=()
if [[ -d "$STATE" ]]; then RETAIN+=("$STATE"); fi
if [[ -d "$ETC" ]]; then RETAIN+=("$ETC"); fi
if [[ ${#RETAIN[@]} == 0 ]]; then
    if [[ "$PRESENT" == 1 ]]; then
        echo "Lattice services stopped; no state directories found."
    else
        echo "Lattice is not installed; nothing to do."
    fi
    exit 0
fi

if [[ "$PURGE" == 1 ]]; then
    for directory in "${RETAIN[@]}"; do
        [[ -z "$(find "$directory" -type l -print -quit)" ]] || { echo "$directory contains symbolic links; purge stopped" >&2; exit 1; }
    done
    rm -rf "${RETAIN[@]}"
    echo "All Lattice system state removed, including identities and keys."
    exit 0
fi

STAMP="$(date +%Y%m%d-%H%M%S)$RANDOM"
for directory in "${RETAIN[@]}"; do
    mv "$directory" "$directory.pre-uninstall-$STAMP"
done
echo "Lattice services stopped; binaries removed and state preserved as *.pre-uninstall-$STAMP"
echo "Reinstall with the public installer; identity and the assigned overlay IP survive inside the snapshots."
