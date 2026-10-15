#!/usr/bin/env bash
# Install one participating node and optional master. Never initialize owner workload policy.
set -euo pipefail
umask 077
ARTIFACTS=""; ROLE=node; BOOTSTRAP=https://lattice.sentialab.org
while [[ $# -gt 0 ]]; do case "$1" in --artifact-dir) ARTIFACTS="$2"; shift 2;; --role) ROLE="$2"; shift 2;; --bootstrap-url) BOOTSTRAP="$2"; shift 2;; *) echo "Unknown installer option" >&2; exit 1;; esac; done
[[ "$ROLE" == node || "$ROLE" == master ]] || exit 1
[[ -d "$ARTIFACTS" && -x "$ARTIFACTS/lattice-node" ]] || { echo "A complete verified artifact directory is required" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo "System installation requires sudo/root" >&2; exit 1; }
ROOT=""
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then ROOT="${LATTICE_INSTALL_TEST_ROOT:?}"; [[ -d "$ROOT" && "$ROOT" != / ]] || exit 1; fi
"$ARTIFACTS/lattice-node" verify-bundle --artifact-dir "$ARTIFACTS" --role "$ROLE"
if ! command -v wg >/dev/null || ! command -v ip >/dev/null || ! command -v ping >/dev/null; then
    command -v apt-get >/dev/null || { echo "Debian/Ubuntu with apt is required" >&2; exit 1; }
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iproute2 iputils-ping ca-certificates
fi
BIN="$ROOT/usr/local/lib/lattice"; STATE="$ROOT/var/lib/lattice"; ETC="$ROOT/etc/lattice"; UNITS="$ROOT/etc/systemd/system"; SOCKET="$ROOT/run/lattice/node.sock"
mkdir -p "$BIN" "$STATE" "$ETC" "$UNITS" "$(dirname "$SOCKET")"
chmod 700 "$STATE" "$ETC"
chmod 755 "$(dirname "$SOCKET")"
STAGE="$(mktemp -d "$BIN/.install.XXXXXXXX")"
BACKUP="$(mktemp -d "$BIN/.rollback.XXXXXXXX")"
for f in lattice-node.service lattice-master.service; do [[ ! -f "$UNITS/$f" ]] || cp "$UNITS/$f" "$BACKUP/$f"; done
for f in node.env master.env; do [[ ! -f "$ETC/$f" ]] || cp "$ETC/$f" "$BACKUP/$f"; done
cp -R "$ARTIFACTS/." "$STAGE/"
rollback() {
    local code=$?
    if [[ $code -ne 0 ]]; then
        set +e
        systemctl stop lattice-master lattice-node
        [[ ! -d "$BIN/current" ]] || mv "$BIN/current" "$BACKUP/failed"
        [[ ! -d "$BACKUP/current" ]] || mv "$BACKUP/current" "$BIN/current"
        for f in lattice-node.service lattice-master.service; do if [[ -f "$BACKUP/$f" ]]; then cp "$BACKUP/$f" "$UNITS/$f"; else rm -f "$UNITS/$f"; fi; done
        for f in node.env master.env; do if [[ -f "$BACKUP/$f" ]]; then cp "$BACKUP/$f" "$ETC/$f"; else rm -f "$ETC/$f"; fi; done
        systemctl daemon-reload
        [[ ! -f "$BACKUP/lattice-node.service" ]] || systemctl start lattice-node
        [[ ! -f "$BACKUP/lattice-master.service" ]] || systemctl start lattice-master
        echo "Installation failed; previous service files and binaries restored. Identity and diagnostic state retained." >&2
    fi
    [[ ! -d "$STAGE" ]] || rm -rf "$STAGE"
    exit "$code"
}
trap rollback EXIT
systemctl stop lattice-node || true
if [[ "$ROLE" == master ]]; then systemctl stop lattice-master || true; fi
[[ ! -d "$BIN/current" ]] || mv "$BIN/current" "$BACKUP/current"
mv "$STAGE" "$BIN/current"
chmod 755 "$BIN/current/"lattice-*
cat > "$ETC/node.env" <<ENV
LATTICE_CONFIG="$STATE/node.json"
LATTICE_SOCKET="$SOCKET"
LATTICE_MASTER_DATA="$STATE/master"
LATTICE_IPC_GID="$(id -g "${SUDO_USER:-root}")"
ENV
cat > "$UNITS/lattice-node.service" <<UNIT
[Unit]
Description=Lattice participating node
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=root
EnvironmentFile=$ETC/node.env
ExecStart="$BIN/current/lattice-node"
Restart=always
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable lattice-node
systemctl start lattice-node
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 ]]; then
    for ((i=0;i<60;i++)); do [[ ! -S "$SOCKET" ]] || break; sleep 1; done
    [[ -S "$SOCKET" ]] || { echo "Node IPC did not start" >&2; exit 1; }
fi
export LATTICE_CONFIG="$STATE/node.json" LATTICE_SOCKET="$SOCKET" LATTICE_MASTER_DATA="$STATE/master"
set +e
"$BIN/current/lattice-node" setup --role "$ROLE" --bootstrap-url "$BOOTSTRAP" --timeout-secs 120 --json
RESULT=$?
set -e
[[ $RESULT == 0 || $RESULT == 2 ]] || exit 1
if [[ "$ROLE" == master ]]; then
    cat > "$ETC/master.env" <<ENV
LATTICE_CONTROL_DATA="$STATE/master"
ENV
    cat > "$UNITS/lattice-master.service" <<UNIT
[Unit]
Description=Lattice authorized workload master
Requires=lattice-node.service
After=lattice-node.service network-online.target
[Service]
Type=simple
User=root
EnvironmentFile=$ETC/master.env
ExecStart="$BIN/current/lattice-master"
Restart=always
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable lattice-master
    systemctl start lattice-master
    set +e
    "$BIN/current/lattice-node" setup --wait --timeout-secs 30 --json
    RESULT=$?
    set -e
    [[ $RESULT == 0 || $RESULT == 2 ]] || exit 1
fi
trap - EXIT
[[ $RESULT != 2 ]] || echo "Network ready; workload attachment is pending and the node will retry."
echo "System services installed. Recovery snapshot: $BACKUP"
