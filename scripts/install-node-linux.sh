#!/usr/bin/env bash
# Install lattice-node and lattice-worker on Linux (x86_64 or aarch64).
# Usage (as root):
#   ARTIFACT_DIR=./dist \
#   LATTICE_ENROLLMENT_TOKEN=secret \
#   LATTICE_MASTER_URL=http://<master>:7443 \
#   LATTICE_BOOTSTRAP_URL=http://<bootstrapper>:7443 \
#   LATTICE_ALLOW_INSECURE_HTTP=1 \
#   ./scripts/install-node-linux.sh
#
# Skips enrollment when MASTER_URL is empty. Skips bootstrap join when
# BOOTSTRAP_URL is empty. Secrets come from the environment only.
set -euo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-./dist}"
DATA_DIR="${LATTICE_DATA_DIR:-/var/lib/lattice}"
BIN_DIR="${LATTICE_BIN_DIR:-/usr/local/bin}"
MASTER_URL="${LATTICE_MASTER_URL:-}"
BOOTSTRAP_URL="${LATTICE_BOOTSTRAP_URL:-}"
ENROLLMENT_TOKEN="${LATTICE_ENROLLMENT_TOKEN:-}"
SOCKET="${LATTICE_SOCKET:-/tmp/lattice-node.sock}"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
fi

for binary in lattice-node lattice-worker; do
    if [[ ! -x "$ARTIFACT_DIR/$binary" ]]; then
        echo "Missing executable artifact: $ARTIFACT_DIR/$binary" >&2
        exit 1
    fi
done

command -v wg >/dev/null 2>&1 || {
    echo "wireguard-tools missing, installing."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools
    else
        echo "Install wireguard-tools manually, then rerun." >&2
        exit 1
    fi
}

OVERLAY_CIDR="${LATTICE_NETWORK_CIDR:-10.77.0.0/16}"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "Allowing overlay mesh $OVERLAY_CIDR through UFW."
    ufw allow from "$OVERLAY_CIDR" comment 'Lattice overlay mesh'
fi

install -m 0755 "$ARTIFACT_DIR/lattice-node" "$BIN_DIR/lattice-node"
install -m 0755 "$ARTIFACT_DIR/lattice-worker" "$BIN_DIR/lattice-worker"
mkdir -p "$DATA_DIR"
chmod 0700 "$DATA_DIR"
mkdir -p /etc/lattice

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cat > /etc/systemd/system/lattice-node.service <<EOF
[Unit]
Description=Lattice Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/lattice/node.env
ExecStart=$BIN_DIR/lattice-node
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

{
    echo "LATTICE_CONFIG=$DATA_DIR/node.json"
    echo "LATTICE_SOCKET=$SOCKET"
    if [[ -n "${LATTICE_ALLOW_INSECURE_HTTP:-}" ]]; then
        echo "LATTICE_ALLOW_INSECURE_HTTP=$LATTICE_ALLOW_INSECURE_HTTP"
    fi
} > /etc/lattice/node.env
chmod 0600 /etc/lattice/node.env

systemctl daemon-reload
systemctl enable --now lattice-node.service
sleep 3

ipc() {
    python3 "$SCRIPT_DIR/lattice-ipc.py" --socket "$SOCKET" "$@"
}

if [[ -n "$BOOTSTRAP_URL" && -n "$ENROLLMENT_TOKEN" ]]; then
    echo "Joining bootstrapper $BOOTSTRAP_URL"
    LATTICE_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" ipc enroll-bootstrap --url "$BOOTSTRAP_URL"
    ipc set-network-enabled --enabled true
fi

if [[ -n "$MASTER_URL" && -n "$ENROLLMENT_TOKEN" ]]; then
    echo "Enrolling with master $MASTER_URL"
    LATTICE_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN" ipc enroll --url "$MASTER_URL"
fi

echo "Node status:"
ipc status | head -c 600
echo
