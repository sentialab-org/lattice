#!/usr/bin/env bash
# Install lattice-master on macOS via launchd.
# Usage:
#   ARTIFACT_DIR=./dist \
#   LATTICE_ENROLLMENT_TOKEN=secret \
#   LATTICE_OPERATOR_TOKEN=secret \
#   LATTICE_PUBLIC_URL=http://<mac-lan-ip>:7443 \
#   ./scripts/install-master-macos.sh
#
# The master orchestrates over HTTPS or LAN HTTP only. It never joins the
# overlay, so no WireGuard setup happens here.
set -euo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-./dist}"
BIN_DIR="${LATTICE_BIN_DIR:-/usr/local/bin}"
DATA_DIR="${LATTICE_DATA_DIR:-$HOME/Library/Application Support/Lattice/master}"
BIND="${LATTICE_CONTROL_BIND:-0.0.0.0:7443}"
CLUSTER_ID="${LATTICE_CLUSTER_ID:-lattice-main}"
ENROLLMENT_TOKEN="${LATTICE_ENROLLMENT_TOKEN:-}"
OPERATOR_TOKEN="${LATTICE_OPERATOR_TOKEN:-}"
PUBLIC_URL="${LATTICE_PUBLIC_URL:-http://127.0.0.1:7443}"

if [[ -z "$ENROLLMENT_TOKEN" || -z "$OPERATOR_TOKEN" ]]; then
    echo "LATTICE_ENROLLMENT_TOKEN and LATTICE_OPERATOR_TOKEN are required." >&2
    exit 1
fi

if [[ ! -x "$ARTIFACT_DIR/lattice-master" ]]; then
    echo "Missing executable artifact: $ARTIFACT_DIR/lattice-master (aarch64-apple-darwin)" >&2
    exit 1
fi

mkdir -p "$BIN_DIR" "$DATA_DIR"
cp "$ARTIFACT_DIR/lattice-master" "$BIN_DIR/lattice-master"
chmod 0755 "$BIN_DIR/lattice-master"

PLIST="$HOME/Library/LaunchAgents/com.lattice.master.plist"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.lattice.master</string>
  <key>ProgramArguments</key>
  <array><string>$BIN_DIR/lattice-master</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LATTICE_CONTROL_DATA</key><string>$DATA_DIR</string>
    <key>LATTICE_ENROLLMENT_TOKEN</key><string>$ENROLLMENT_TOKEN</string>
    <key>LATTICE_OPERATOR_TOKEN</key><string>$OPERATOR_TOKEN</string>
    <key>LATTICE_CONTROL_BIND</key><string>$BIND</string>
    <key>LATTICE_CLUSTER_ID</key><string>$CLUSTER_ID</string>
    <key>LATTICE_CONTROL_ROLE</key><string>master</string>
    <key>LATTICE_PUBLIC_URL</key><string>$PUBLIC_URL</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA_DIR/master.log</string>
  <key>StandardErrorPath</key><string>$DATA_DIR/master.log</string>
</dict>
</plist>
EOF
chmod 0600 "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"
sleep 2
curl --fail --silent --show-error http://127.0.0.1:7443/health | head -c 300
echo
