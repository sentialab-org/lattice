#!/usr/bin/env bash
# Lattice one-line Linux installer.
#   curl https://lattice.sentialab.org/installer/linux.sh | bash
# Security note: prefer HTTPS. The installer verifies SHA-256 checksums of
# every downloaded file, but checksums alone cannot replace TLS against an
# active network attacker. Serve this host over HTTPS in production.
set -euo pipefail

BASE="${LATTICE_RELEASE_BASE:-https://lattice.sentialab.org/releases}"
VERSION="${LATTICE_VERSION:-0.1.0}"
NONINTERACTIVE="${LATTICE_NONINTERACTIVE:-0}"

ask() {
    local prompt="$1" default="$2" var_name="$3" answer=""
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        printf -v "$var_name" "%s" "$default"
        return
    fi
    read -r -p "$prompt [$default]: " answer
    if [[ -z "$answer" ]]; then
        answer="$default"
    fi
    printf -v "$var_name" "%s" "$answer"
}

ask_yn() {
    local prompt="$1" default="$2" var_name="$3" answer=""
    while true; do
        if [[ "$NONINTERACTIVE" == "1" ]]; then
            printf -v "$var_name" "%s" "$default"
            return
        fi
        read -r -p "$prompt (y/n) [$default]: " answer
        if [[ -z "$answer" ]]; then
            answer="$default"
        fi
        case "$answer" in
            y|Y|yes|YES) printf -v "$var_name" "y"; return ;;
            n|N|no|NO) printf -v "$var_name" "n"; return ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

ask_secret() {
    local prompt="$1" var_name="$2" answer=""
    if [[ -n "${!var_name:-}" ]]; then
        return
    fi
    if [[ "$NONINTERACTIVE" == "1" ]]; then
        echo "Missing required secret for $prompt in non-interactive mode." >&2
        exit 1
    fi
    read -r -s -p "$prompt: " answer
    echo
    printf -v "$var_name" "%s" "$answer"
}

fetch() {
    local url="$1" dest="$2"
    curl --fail --location --silent --show-error "$url" --output "$dest"
}

fetch_verified() {
    local url="$1" dest="$2"
    fetch "$url" "$dest"
    fetch "$url.sha256" "$dest.sha256"
    local expected actual
    expected="$(awk '{print $1}' "$dest.sha256")"
    actual="$(sha256sum "$dest" | awk '{print $1}')"
    if [[ "$expected" != "$actual" ]]; then
        echo "Checksum mismatch for $(basename "$dest"). Aborting." >&2
        exit 1
    fi
}

echo "Lattice Linux installer (release $VERSION)"
echo "Server: $BASE"
echo

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64) TARGET_DIR="linux-x86_64" ;;
    aarch64|arm64) TARGET_DIR="linux-aarch64" ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

ROLE=""
while [[ "$ROLE" != "node" && "$ROLE" != "bootstrapper" ]]; do
    ask "Install role (node/bootstrapper)" "${LATTICE_ROLE:-node}" ROLE
done

ask "Release server base URL" "$BASE" BASE
ENROLLMENT_TOKEN="${LATTICE_ENROLLMENT_TOKEN:-}"
OPERATOR_TOKEN="${LATTICE_OPERATOR_TOKEN:-}"
ask_secret "Enrollment token" ENROLLMENT_TOKEN

WORK="$(mktemp -d)"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "$ROLE" == "node" ]]; then
    MASTER_URL="${LATTICE_MASTER_URL:-}"
    BOOTSTRAP_URL="${LATTICE_BOOTSTRAP_URL:-}"
    ask "Master URL (empty to skip workload enrollment)" "$MASTER_URL" MASTER_URL
    ask "Bootstrapper URL (empty to skip overlay join)" "$BOOTSTRAP_URL" BOOTSTRAP_URL
    INSECURE=""
    ask_yn "Allow plain HTTP outside localhost (test deployments only)" "${LATTICE_ALLOW_INSECURE_HTTP:-n}" INSECURE
    if [[ "$INSECURE" == "y" ]]; then
        export LATTICE_ALLOW_INSECURE_HTTP=1
    fi

    mkdir -p "$WORK/dist"
    for binary in lattice-node lattice-worker; do
        fetch_verified "$BASE/$VERSION/$TARGET_DIR/$binary" "$WORK/dist/$binary"
    done
    fetch_verified "$BASE/scripts/install-node-linux.sh" "$WORK/install-node-linux.sh"
    fetch_verified "$BASE/scripts/lattice-ipc.py" "$WORK/lattice-ipc.py"
    cp "$WORK/lattice-ipc.py" "$WORK/dist/lattice-ipc.py"

    echo
    echo "Installing node binaries and starting service."
    export ARTIFACT_DIR="$WORK/dist"
    export LATTICE_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN"
    export LATTICE_MASTER_URL="$MASTER_URL"
    export LATTICE_BOOTSTRAP_URL="$BOOTSTRAP_URL"
    bash "$WORK/install-node-linux.sh"
else
    ask_secret "Operator token" OPERATOR_TOKEN
    GATEWAY_ENDPOINT="${LATTICE_NETWORK_GATEWAY_ENDPOINT:-}"
    ask "Public gateway endpoint host:port" "$GATEWAY_ENDPOINT" GATEWAY_ENDPOINT
    APPLY=""
    ask_yn "Apply gateway WireGuard interface and firewall now" "y" APPLY

    mkdir -p "$WORK/dist"
    fetch_verified "$BASE/$VERSION/$TARGET_DIR/lattice-bootstrapper" "$WORK/dist/lattice-bootstrapper"
    fetch_verified "$BASE/scripts/install-bootstrapper-linux.sh" "$WORK/install-bootstrapper-linux.sh"

    echo
    echo "Installing bootstrapper service."
    export ARTIFACT_DIR="$WORK/dist"
    export LATTICE_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN"
    export LATTICE_OPERATOR_TOKEN="$OPERATOR_TOKEN"
    export LATTICE_NETWORK_GATEWAY_ENDPOINT="$GATEWAY_ENDPOINT"
    if [[ "$APPLY" == "y" ]]; then
        bash "$WORK/install-bootstrapper-linux.sh" --apply-gateway
    else
        bash "$WORK/install-bootstrapper-linux.sh"
    fi
fi

echo
echo "Done. Verify with the commands printed by the installer above."
