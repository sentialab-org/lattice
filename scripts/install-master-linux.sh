#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/install-node-linux.sh" --role master "$@"
