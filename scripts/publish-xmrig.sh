#!/usr/bin/env bash
set -euo pipefail

CONTROL_URL="${1:-${LATTICE_CONTROL_URL:-}}"
OPERATOR_TOKEN="${2:-${LATTICE_OPERATOR_TOKEN:-}}"
VERSION="${XMRIG_VERSION:-6.26.0}"
ARCHIVE_SHA256="${XMRIG_ARCHIVE_SHA256:-}"

if [[ -z "$CONTROL_URL" || -z "$OPERATOR_TOKEN" ]]; then
    echo "Usage: $0 <control-url> <operator-token>" >&2
    exit 1
fi

if [[ -z "$ARCHIVE_SHA256" ]]; then
    case "$VERSION" in
        6.26.0)
            ARCHIVE_SHA256="fc6f8ae5f64e4f17481f7e3be29a1c56949f216a998414188003eae1db20c9e5"
            ;;
        *)
            echo "No pinned upstream SHA-256 is known for XMRig $VERSION. Set XMRIG_ARCHIVE_SHA256." >&2
            exit 1
            ;;
    esac
fi

ASSET="xmrig-$VERSION-linux-static-x64.tar.gz"
RELEASE_URL="https://github.com/xmrig/xmrig/releases/download/v$VERSION/$ASSET"
TEMP="$(mktemp -d)"

cleanup() {
    rm -rf "$TEMP"
}
trap cleanup EXIT

ARCHIVE="$TEMP/$ASSET"
curl --fail --location --silent --show-error "$RELEASE_URL" --output "$ARCHIVE"

ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$ARCHIVE_SHA256" ]]; then
    echo "Upstream archive SHA-256 mismatch. Expected $ARCHIVE_SHA256, got $ACTUAL_SHA256." >&2
    exit 1
fi

mkdir -p "$TEMP/extract"
tar -xzf "$ARCHIVE" -C "$TEMP/extract"

EXECUTABLE="$(find "$TEMP/extract" -type f -name xmrig -print -quit)"
if [[ -z "$EXECUTABLE" ]]; then
    echo "Could not find xmrig in the verified archive." >&2
    exit 1
fi

RUNTIME_SHA256="$(sha256sum "$EXECUTABLE" | awk '{print $1}')"
RUNTIME_SIZE="$(wc -c < "$EXECUTABLE" | tr -d ' ')"
URI="${CONTROL_URL%/}/api/v1/operator/xmrig/runtimes/$VERSION/linux/x86_64"

echo "Publishing XMRig $VERSION for linux/x86_64"
echo "Executable SHA-256: $RUNTIME_SHA256"
echo "Executable size: $RUNTIME_SIZE"

curl --fail --silent --show-error     -H "Authorization: Bearer $OPERATOR_TOKEN"     -H "Content-Type: application/octet-stream"     --data-binary "@$EXECUTABLE"     "$URI"

echo
