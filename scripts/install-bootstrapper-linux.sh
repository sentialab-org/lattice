#!/usr/bin/env bash
# Explicit Supervisor provisioning and legacy gateway handoff through one Base Node.
set -euo pipefail
umask 077
ARTIFACT_DIR="${ARTIFACT_DIR:-./dist}"
AUTHORITY="${LATTICE_DATA_DIR:-/var/lib/lattice}"
PUBLIC_URL="${LATTICE_PUBLIC_URL:-}"
OWNER="${LATTICE_OWNER_USER:-}"
TERMS=(); ADOPT=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact-dir) ARTIFACT_DIR="$2"; shift 2;;
        --authority-dir) AUTHORITY="$2"; shift 2;;
        --public-url) PUBLIC_URL="$2"; shift 2;;
        --owner-user) OWNER="$2"; shift 2;;
        --accept-terms) TERMS=(--accept-terms); shift;;
        --adopt-gateway|--apply-gateway) ADOPT=1; shift;;
        *) echo "Unknown Supervisor installer option" >&2; exit 1;;
    esac
done
[[ "$(id -u)" == 0 ]] || { echo "Supervisor provisioning requires sudo/root" >&2; exit 1; }
[[ "$AUTHORITY" == /* && -n "$PUBLIC_URL" && "$ADOPT" == 1 ]] || { echo "Provide --public-url HTTPS_ORIGIN and --adopt-gateway; --authority-dir must be absolute" >&2; exit 1; }
[[ ! -L "$AUTHORITY" ]] || { echo "Authority directory must not be a symbolic link" >&2; exit 1; }
"$ARTIFACT_DIR/lattice-node" verify-bundle --artifact-dir "$ARTIFACT_DIR" --role node
mkdir -p "$AUTHORITY"; chmod 700 "$AUTHORITY"
EXISTING=0
for name in control-identity.json network.json gateway_wireguard.json; do [[ ! -e "$AUTHORITY/$name" ]] || EXISTING=$((EXISTING+1)); done
if [[ "$EXISTING" == 0 ]]; then
    if [[ ! -f "$AUTHORITY/account.json" ]]; then
        [[ -n "$OWNER" ]] || { echo "Fresh Supervisor provisioning requires --owner-user; the password is entered privately" >&2; exit 1; }
        "$ARTIFACT_DIR/lattice-admin" provision --data-dir "$AUTHORITY" --username "$OWNER"
    fi
    "$ARTIFACT_DIR/lattice-admin" initialize-supervisor --data-dir "$AUTHORITY" --public-url "$PUBLIC_URL"
elif [[ "$EXISTING" != 3 || ! -f "$AUTHORITY/account.json" ]]; then
    echo "Incomplete existing authority; recover its original files before installation. No keys have been replaced." >&2; exit 1
fi
INSTALLER="$(dirname "$0")/install-node-linux.sh"
[[ ! -f "$ARTIFACT_DIR/install.sh" ]] || INSTALLER="$ARTIFACT_DIR/install.sh"
exec bash "$INSTALLER" --artifact-dir "$ARTIFACT_DIR" --role node --supervisor-dir "$AUTHORITY" --public-url "$PUBLIC_URL" --adopt-gateway "${TERMS[@]}"
