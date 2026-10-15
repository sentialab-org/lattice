#!/usr/bin/env bash
# Install lattice-bootstrapper on Linux (x86_64 or aarch64, e.g. Raspberry Pi).
# Usage (as root):
#   ARTIFACT_DIR=./dist \
#   LATTICE_ENROLLMENT_TOKEN=secret \
#   LATTICE_OPERATOR_TOKEN=secret \
#   LATTICE_CLUSTER_ID=lattice-nbi \
#   LATTICE_NETWORK_GATEWAY_ENDPOINT=<public-ip>:51820 \
#   LATTICE_NETWORK_CIDR=10.77.0.0/16 \
#   ./scripts/install-bootstrapper-linux.sh [--apply-gateway]
#
# With --apply-gateway the script fetches the rendered gateway config from
# the local operator API and applies the WireGuard interface, overlay route
# and nftables ruleset. Without it, setup stops after the service starts.
set -euo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-./dist}"
DATA_DIR="${LATTICE_DATA_DIR:-/var/lib/lattice}"
BIN_DIR="${LATTICE_BIN_DIR:-/usr/local/bin}"
BIND="${LATTICE_CONTROL_BIND:-0.0.0.0:7443}"
CLUSTER_ID="${LATTICE_CLUSTER_ID:-lattice-main}"
ENROLLMENT_TOKEN="${LATTICE_ENROLLMENT_TOKEN:-}"
OPERATOR_TOKEN="${LATTICE_OPERATOR_TOKEN:-}"
APPLY_GATEWAY=0

if [[ "${1:-}" == "--apply-gateway" ]]; then
    APPLY_GATEWAY=1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root." >&2
    exit 1
fi

if [[ -z "$ENROLLMENT_TOKEN" || -z "$OPERATOR_TOKEN" ]]; then
    echo "LATTICE_ENROLLMENT_TOKEN and LATTICE_OPERATOR_TOKEN are required." >&2
    exit 1
fi

if [[ ! -x "$ARTIFACT_DIR/lattice-bootstrapper" ]]; then
    echo "Missing executable artifact: $ARTIFACT_DIR/lattice-bootstrapper" >&2
    exit 1
fi

command -v wg >/dev/null 2>&1 || {
    echo "wireguard-tools missing, installing."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools nftables
}

install -m 0755 "$ARTIFACT_DIR/lattice-bootstrapper" "$BIN_DIR/lattice-bootstrapper"
mkdir -p "$DATA_DIR"
chmod 0700 "$DATA_DIR"
mkdir -p /etc/lattice

cat > /etc/lattice/bootstrapper.env <<EOF
LATTICE_CONTROL_DATA=$DATA_DIR
LATTICE_GATEWAY_RECONCILE=1
LATTICE_ENROLLMENT_TOKEN=$ENROLLMENT_TOKEN
LATTICE_OPERATOR_TOKEN=$OPERATOR_TOKEN
LATTICE_CONTROL_BIND=$BIND
LATTICE_CLUSTER_ID=$CLUSTER_ID
LATTICE_CONTROL_ROLE=bootstrapper
LATTICE_NETWORK_CIDR=${LATTICE_NETWORK_CIDR:-10.77.0.0/16}
LATTICE_NETWORK_GATEWAY_IP=${LATTICE_NETWORK_GATEWAY_IP:-10.77.0.1}
LATTICE_NETWORK_GATEWAY_ENDPOINT=${LATTICE_NETWORK_GATEWAY_ENDPOINT:-127.0.0.1:51820}
LATTICE_NETWORK_INTERFACE=${LATTICE_NETWORK_INTERFACE:-lattice0}
LATTICE_NETWORK_RESERVED_IPS=${LATTICE_NETWORK_RESERVED_IPS:-10.77.0.2,10.77.0.3}
LATTICE_NETWORK_PATH_POLICY=${LATTICE_NETWORK_PATH_POLICY:-hub}
EOF
chmod 0600 /etc/lattice/bootstrapper.env

cat > /etc/systemd/system/lattice-bootstrapper.service <<EOF
[Unit]
Description=Lattice Bootstrapper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/lattice/bootstrapper.env
ExecStart=$BIN_DIR/lattice-bootstrapper
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sysctl -w net.ipv4.ip_forward=1
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

systemctl daemon-reload
systemctl enable --now lattice-bootstrapper.service
sleep 3
curl --fail --silent --show-error http://127.0.0.1:7443/health | head -c 300
echo

if [[ "$APPLY_GATEWAY" -eq 1 ]]; then
    echo "Applying gateway interface and firewall from local state."
    mkdir -p /etc/wireguard /etc/nftables
    IFACE="$(LATTICE_CONTROL_DATA="$DATA_DIR" "$BIN_DIR/lattice-bootstrapper" gateway-config | awk '/^# interface: /{print $3}')"
    ADDR="$(LATTICE_CONTROL_DATA="$DATA_DIR" "$BIN_DIR/lattice-bootstrapper" gateway-config | awk '/^# address: /{print $3}')"
    OVERLAY="$(LATTICE_CONTROL_DATA="$DATA_DIR" "$BIN_DIR/lattice-bootstrapper" gateway-config | awk '/^# overlay: /{print $3}')"
    LATTICE_CONTROL_DATA="$DATA_DIR" "$BIN_DIR/lattice-bootstrapper" gateway-config | grep -v "^#" > "/etc/wireguard/$IFACE.conf"
    chmod 0600 "/etc/wireguard/$IFACE.conf"
    ip link add dev "$IFACE" type wireguard 2>/dev/null || true
    wg syncconf "$IFACE" "/etc/wireguard/$IFACE.conf"
    ip address replace "$ADDR" dev "$IFACE"
    ip link set up dev "$IFACE"
    ip route replace "$OVERLAY" dev "$IFACE"
    LATTICE_CONTROL_DATA="$DATA_DIR" "$BIN_DIR/lattice-bootstrapper" gateway-nftables > /etc/nftables/lattice-overlay.nft
    nft -f /etc/nftables/lattice-overlay.nft
    echo "Gateway $IFACE applied with $ADDR"
fi
