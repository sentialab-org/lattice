#!/usr/bin/env bash
# Public entry point; interaction belongs to the elevated native setup via /dev/tty.
set -euo pipefail
umask 077
SITE="${LATTICE_SITE_BASE:-https://lattice.sentialab.org}"
ROLE="${LATTICE_ROLE:-node}"
[[ "$ROLE" == node || "$ROLE" == master ]] || { echo "Role must be node or master" >&2; exit 1; }
[[ "$SITE" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || { echo "An HTTPS site origin is required" >&2; exit 1; }
VERSION="${LATTICE_VERSION:-}"
if [[ -z "$VERSION" ]]; then VERSION="$(curl --fail --silent --show-error --proto '=https' "$SITE/releases/stable")"; fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || { echo "Invalid release version" >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; *) echo "Unsupported architecture" >&2; exit 1;; esac
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/lattice-install.XXXXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
BASE="$SITE/releases/$VERSION/linux-$ARCH/$ROLE.tar.gz"
curl --fail --silent --show-error --proto '=https' "$BASE" -o "$STAGE/bundle.tar.gz"
curl --fail --silent --show-error --proto '=https' "$BASE.sha256" -o "$STAGE/expected"
EXPECTED="$(cat "$STAGE/expected")"
[[ "$EXPECTED" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid archive checksum" >&2; exit 1; }
[[ "$(sha256sum "$STAGE/bundle.tar.gz" | cut -d ' ' -f 1)" == "$EXPECTED" ]] || { echo "Archive checksum mismatch" >&2; exit 1; }
tar -tzf "$STAGE/bundle.tar.gz" | awk '/^[A-Za-z0-9][A-Za-z0-9._-]*$/ { next } { exit 1 }'
tar -tvzf "$STAGE/bundle.tar.gz" | awk 'substr($0,1,1)!="-" { exit 1 }'
mkdir "$STAGE/artifacts"
tar -xzf "$STAGE/bundle.tar.gz" -C "$STAGE/artifacts" --no-same-owner
BOOTSTRAP="${LATTICE_BOOTSTRAP_URL:-$SITE}"
if [[ "$(id -u)" != 0 ]]; then
    sudo bash "$STAGE/artifacts/install.sh" --artifact-dir "$STAGE/artifacts" --role "$ROLE" --bootstrap-url "$BOOTSTRAP"
else
    bash "$STAGE/artifacts/install.sh" --artifact-dir "$STAGE/artifacts" --role "$ROLE" --bootstrap-url "$BOOTSTRAP"
fi
