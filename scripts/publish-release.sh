#!/usr/bin/env bash
# Assemble locally; promotion and remote publication are separate reviewed operations.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -ge 2 ]] || { echo "Usage: $0 VERSION NEW-STAGING-DIRECTORY [TARGETS]" >&2; exit 1; }
exec python3 "$ROOT/scripts/release_manifest.py" assemble --version "$1" --out "$2" --targets "${3:-macos-arm64,macos-x86_64,linux-x86_64,linux-aarch64,windows-x86_64}"
