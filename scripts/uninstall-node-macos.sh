#!/usr/bin/env bash
# Stop both role daemons and retain the protected state for identity reuse.
# The default keeps one root-only state snapshot next to the install
# location; --purge removes that snapshot and its identities. Never touches
# third-party tools or the separately installed bootstrapper service.
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

STATE="$ROOT/Library/Application Support/Lattice"
BIN="$STATE/bin"
PLISTS="$ROOT/Library/LaunchDaemons"
SOCKET_DIR="$ROOT/var/run/lattice"
SOCKET="$SOCKET_DIR/node.sock"

PRESENT=0
for role in node master; do
    if launchctl print "system/com.lattice.$role" >/dev/null 2>&1; then PRESENT=1; fi
done
for role in node master; do
    launchctl bootout "system/com.lattice.$role" 2>/dev/null || true
done
for role in node master; do
    rm -f "$PLISTS/com.lattice.$role.plist"
done
rm -f "$SOCKET"
rmdir "$SOCKET_DIR" 2>/dev/null || true

if [[ ! -d "$STATE" ]]; then
    if [[ "$PRESENT" == 1 ]]; then
        echo "Lattice daemons stopped; no system install directory found."
    else
        echo "Lattice is not installed; nothing to do."
    fi
    exit 0
fi

if [[ "$PURGE" == 1 ]]; then
    [[ -z "$(find "$STATE" -type l -print -quit)" ]] || { echo "State contains symbolic links; purge stopped" >&2; exit 1; }
    rm -rf "$STATE"
    echo "All Lattice system state removed, including identities and keys."
    exit 0
fi

STAMP="$(date +%Y%m%d-%H%M%S)$RANDOM"
BACKUP="$STATE.pre-uninstall-$STAMP"
mv "$STATE" "$BACKUP"
echo "Lattice daemons stopped; binaries and state preserved in:"
echo "  $BACKUP"
echo "Reinstall with the public installer; identity and the assigned overlay IP survive inside the snapshot."
