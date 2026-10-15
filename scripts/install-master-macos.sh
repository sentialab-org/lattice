#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/install-node-macos.sh" --role master "$@"
