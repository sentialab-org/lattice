#!/usr/bin/env bash
# Assemble a Lattice release tree ready to rsync to the download host.
# Usage: ./scripts/publish-release.sh <version> [output-dir]
#
# Reads release binaries from the local Cargo target directories and the
# installer scripts from web/installer and scripts. Writes SHA-256 sidecar
# files for every artifact. Upload the output directory so that its content
# is served at $LATTICE_RELEASE_BASE (installer/ and scripts/ included).
set -euo pipefail

VERSION="${1:-}"
OUT="${2:-./dist}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [output-dir]" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$REPO_ROOT/target"

checksum() {
    (cd "$(dirname "$1")" && shasum -a 256 "$(basename "$1")" | awk '{print $1}') > "$1.sha256"
}

copy_verified() {
    local src="$1" dest="$2"
    if [[ ! -f "$src" ]]; then
        echo "Missing artifact, build it first: $src" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    checksum "$dest"
    echo "staged $(basename "$dest")"
}

rm -rf "$OUT"
mkdir -p "$OUT"

copy_verified "$REPO_ROOT/web/installer/linux.sh" "$OUT/installer/linux.sh"
copy_verified "$REPO_ROOT/web/installer/windows.ps1" "$OUT/installer/windows.ps1"
copy_verified "$REPO_ROOT/web/installer/index.html" "$OUT/index.html"
copy_verified "$REPO_ROOT/web/installer/README.md" "$OUT/README.md"
copy_verified "$REPO_ROOT/scripts/install-node-linux.sh" "$OUT/scripts/install-node-linux.sh"
copy_verified "$REPO_ROOT/scripts/install-bootstrapper-linux.sh" "$OUT/scripts/install-bootstrapper-linux.sh"
copy_verified "$REPO_ROOT/scripts/install-node-windows.ps1" "$OUT/scripts/install-node-windows.ps1"
copy_verified "$REPO_ROOT/scripts/install-master-macos.sh" "$OUT/scripts/install-master-macos.sh"
copy_verified "$REPO_ROOT/scripts/lattice-ipc.py" "$OUT/scripts/lattice-ipc.py"

copy_verified "$TARGET/x86_64-unknown-linux-gnu/release/lattice-node" "$OUT/releases/$VERSION/linux-x86_64/lattice-node"
copy_verified "$TARGET/x86_64-unknown-linux-gnu/release/lattice-worker" "$OUT/releases/$VERSION/linux-x86_64/lattice-worker"
copy_verified "$TARGET/x86_64-unknown-linux-gnu/release/lattice-bootstrapper" "$OUT/releases/$VERSION/linux-x86_64/lattice-bootstrapper"
copy_verified "$TARGET/x86_64-unknown-linux-gnu/release/lattice-master" "$OUT/releases/$VERSION/linux-x86_64/lattice-master"
copy_verified "$TARGET/aarch64-unknown-linux-gnu/release/lattice-bootstrapper" "$OUT/releases/$VERSION/linux-aarch64/lattice-bootstrapper"
copy_verified "$TARGET/aarch64-unknown-linux-gnu/release/lattice-master" "$OUT/releases/$VERSION/linux-aarch64/lattice-master"
copy_verified "$TARGET/aarch64-unknown-linux-gnu/release/lattice-control" "$OUT/releases/$VERSION/linux-aarch64/lattice-control"
copy_verified "$TARGET/x86_64-pc-windows-gnu/release/lattice-node.exe" "$OUT/releases/$VERSION/windows-x86_64/lattice-node.exe"
copy_verified "$TARGET/x86_64-pc-windows-gnu/release/lattice-worker.exe" "$OUT/releases/$VERSION/windows-x86_64/lattice-worker.exe"
copy_verified "$TARGET/release/lattice-master" "$OUT/releases/$VERSION/macos-arm64/lattice-master"
copy_verified "$TARGET/release/lattice-node" "$OUT/releases/$VERSION/macos-arm64/lattice-node"

(cd "$OUT" && find . -type f ! -name "*.sha256" -exec shasum -a 256 {} + | sort -k 2 > SHA256SUMS)

echo
echo "Release tree ready in $OUT. Rsync its content to the download host document root."
echo "Linux one-liner:   curl https://<host>/installer/linux.sh | bash"
echo "Windows one-liner: irm https://<host>/installer/windows.ps1 | iex"
