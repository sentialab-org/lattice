#!/usr/bin/env bash
# Install one participating node and optional master. Never initialize owner workload policy.
set -euo pipefail
umask 077
SUPERVISOR_DIR=""; PUBLIC_URL=""; ADOPT_GATEWAY=0
ARTIFACTS=""; ACCEPT_TERMS=0; ROLE=node; BOOTSTRAP=https://lattice.sentialab.org
while [[ $# -gt 0 ]]; do case "$1" in --supervisor-dir) SUPERVISOR_DIR="$2"; shift 2;; --public-url) PUBLIC_URL="$2"; shift 2;; --adopt-gateway) ADOPT_GATEWAY=1; shift;; --accept-terms) ACCEPT_TERMS=1; shift;; --artifact-dir) ARTIFACTS="$2"; shift 2;; --role) ROLE="$2"; shift 2;; --bootstrap-url) BOOTSTRAP="$2"; shift 2;; *) echo "Unknown installer option" >&2; exit 1;; esac; done
[[ "$ROLE" == node || "$ROLE" == master ]] || exit 1
if [[ -n "$SUPERVISOR_DIR" ]]; then
    [[ "$ROLE" == node && "$SUPERVISOR_DIR" == /* && -f "$SUPERVISOR_DIR/network.json" && -n "$PUBLIC_URL" && "$ADOPT_GATEWAY" == 1 ]] || { echo "Supervisor requires a provisioned absolute authority directory, public URL and explicit --adopt-gateway" >&2; exit 1; }
elif [[ "$ADOPT_GATEWAY" == 1 || -n "$PUBLIC_URL" ]]; then
    echo "Authority options require --supervisor-dir" >&2; exit 1
fi
[[ -d "$ARTIFACTS" && -x "$ARTIFACTS/lattice-node" ]] || { echo "A complete verified artifact directory is required" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo "System installation requires sudo/root" >&2; exit 1; }
ROOT=""
if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" == 1 ]]; then ROOT="${LATTICE_INSTALL_TEST_ROOT:?}"; [[ -d "$ROOT" && "$ROOT" != / ]] || exit 1; fi
"$ARTIFACTS/lattice-node" verify-bundle --artifact-dir "$ARTIFACTS" --role "$ROLE"
if ! command -v wg >/dev/null || ! command -v ip >/dev/null || ! command -v ping >/dev/null || ! command -v nft >/dev/null || ! command -v python3 >/dev/null; then
    command -v apt-get >/dev/null || { echo "Debian/Ubuntu with apt is required" >&2; exit 1; }
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iproute2 iputils-ping nftables python3 ca-certificates
fi
INTERFACE=""
if [[ -n "$SUPERVISOR_DIR" ]]; then
    INTERFACE="$(python3 - "$SUPERVISOR_DIR/network.json" <<'PY_INTERFACE'
import json,re,sys
with open(sys.argv[1]) as source: interface=json.load(source)['interface_name']
if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface): raise SystemExit('Invalid preserved interface name')
print(interface)
PY_INTERFACE
)"
fi
BIN="$ROOT/usr/local/lib/lattice"; STATE="$ROOT/var/lib/lattice"; ETC="$ROOT/etc/lattice"; UNITS="$ROOT/etc/systemd/system"; SOCKET="$ROOT/run/lattice/node.sock"
mkdir -p "$BIN" "$STATE" "$ETC" "$UNITS" "$(dirname "$SOCKET")"
chmod 700 "$STATE" "$ETC"
chmod 755 "$BIN"
chmod 755 "$(dirname "$SOCKET")"
STAGE="$(mktemp -d "$BIN/.install.XXXXXXXX")"
BACKUP="$(mktemp -d "$BIN/.rollback.XXXXXXXX")"
for f in lattice-node.service lattice-master.service; do [[ ! -f "$UNITS/$f" ]] || cp "$UNITS/$f" "$BACKUP/$f"; done
for f in node.env master.env; do [[ ! -f "$ETC/$f" ]] || cp "$ETC/$f" "$BACKUP/$f"; done
OLD_NODE_ACTIVE=0; OLD_MASTER_ACTIVE=0; OLD_NODE_ENABLED=0; OLD_MASTER_ENABLED=0
if systemctl is-active --quiet lattice-node; then OLD_NODE_ACTIVE=1; fi
if systemctl is-active --quiet lattice-master; then OLD_MASTER_ACTIVE=1; fi
if systemctl is-enabled --quiet lattice-node; then OLD_NODE_ENABLED=1; fi
if systemctl is-enabled --quiet lattice-master; then OLD_MASTER_ENABLED=1; fi
printf 'node_active=%s\nmaster_active=%s\nnode_enabled=%s\nmaster_enabled=%s\n' "$OLD_NODE_ACTIVE" "$OLD_MASTER_ACTIVE" "$OLD_NODE_ENABLED" "$OLD_MASTER_ENABLED" > "$BACKUP/service-state"
cp -R "$ARTIFACTS/." "$STAGE/"
chmod 755 "$STAGE"
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
        if [[ "$OLD_NODE_ENABLED" == 1 ]]; then systemctl enable lattice-node; else systemctl disable lattice-node; fi
        if [[ "$OLD_MASTER_ENABLED" == 1 ]]; then systemctl enable lattice-master; else systemctl disable lattice-master; fi
        [[ "$OLD_NODE_ACTIVE" != 1 ]] || systemctl start lattice-node
        [[ "$OLD_MASTER_ACTIVE" != 1 ]] || systemctl start lattice-master
        echo "Installation failed; previous service files and binaries restored. Identity and diagnostic state retained." >&2
    fi
    [[ ! -d "$STAGE" ]] || rm -rf "$STAGE"
    exit "$code"
}
trap rollback EXIT
systemctl stop lattice-node || true
systemctl stop lattice-master || true
systemctl disable lattice-master || true
[[ ! -f "$UNITS/lattice-master.service" ]] || mv "$UNITS/lattice-master.service" "$BACKUP/retired-lattice-master.service"
# A stopped daemon can leave its socket behind; only a newly bound socket is ready.
[[ ! -S "$SOCKET" ]] || rm -f "$SOCKET"
[[ ! -d "$BIN/current" ]] || mv "$BIN/current" "$BACKUP/current"
mv "$STAGE" "$BIN/current"
chmod 755 "$BIN/current/"lattice-* "$BIN/current/lattice"
cat > "$ETC/node.env" <<ENV
LATTICE_CONFIG="$STATE/node.json"
LATTICE_SOCKET="$SOCKET"
LATTICE_MASTER_DATA="$STATE/master"
LATTICE_IPC_GID="$(id -g "${SUDO_USER:-root}")"
LATTICE_OWNER_UID="$(id -u "${SUDO_USER:-root}")"
ENV
if [[ -n "$INTERFACE" ]]; then printf 'LATTICE_NETWORK_INTERFACE="%s"\n' "$INTERFACE" >> "$ETC/node.env"; fi
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
RESULT=0
if [[ -n "$SUPERVISOR_DIR" ]]; then
    TERMS_ARGS=(); [[ "$ACCEPT_TERMS" != 1 ]] || TERMS_ARGS+=(--accept-terms)
    "$BIN/current/lattice-node" accept-terms "${TERMS_ARGS[@]}"
    "$BIN/current/lattice-node" module enable --kind supervisor --authority-data-dir "$SUPERVISOR_DIR" --public-url "$PUBLIC_URL" --adopt-gateway --enable-network
    if [[ "${LATTICE_INSTALL_TEST_MODE:-0}" != 1 ]]; then
        for ((i=0;i<120;i++)); do
            "$BIN/current/lattice-node" modules > "$BACKUP/module-status.json"
            "$BIN/current/lattice-node" network-manager > "$BACKUP/network-manager-status.json"
            if python3 - "$BACKUP/module-status.json" "$BACKUP/network-manager-status.json" <<'PY_READY'
import json,sys
with open(sys.argv[1]) as source: modules=json.load(source)['data']
with open(sys.argv[2]) as source: network=json.load(source)['data']
active={m['kind'] for m in modules if m['state']=='active'}
raise SystemExit(0 if {'supervisor','relay'} <= active and network['applied_revision'] is not None else 1)
PY_READY
            then break; fi
            if [[ "$i" == 119 ]]; then echo "Supervisor handoff is pending; protected diagnostics and authority state retained in $BACKUP" >&2; exit 1; fi
            sleep 1
        done
    fi
else
    set +e
    SETUP_ARGS=(--role "$ROLE" --bootstrap-url "$BOOTSTRAP" --timeout-secs 120 --json)
    [[ "$ACCEPT_TERMS" != 1 ]] || SETUP_ARGS+=(--accept-terms)
    "$BIN/current/lattice-node" setup "${SETUP_ARGS[@]}"
    RESULT=$?
    set -e
    [[ $RESULT == 0 || $RESULT == 2 ]] || exit 1
fi

trap - EXIT
[[ $RESULT != 2 ]] || echo "Network ready; workload attachment is pending and the node will retry."
echo "Base Node service installed; optional modules are supervised by the node. Recovery snapshot: $BACKUP"
