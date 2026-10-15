#!/usr/bin/env bash
# Read-only verification; run with administrator access and a second node's TCP listener.
set -euo pipefail
case "$(uname -s)" in
    Darwin)
        export LATTICE_CONFIG="${LATTICE_CONFIG:-/Library/Application Support/Lattice/node.json}"
        export PATH="/Library/Application Support/Lattice/bin/current:$PATH"
        NODE_DEFAULT='/Library/Application Support/Lattice/bin/current/lattice-node'
        ;;
    Linux)
        export LATTICE_CONFIG="${LATTICE_CONFIG:-/var/lib/lattice/node.json}"
        NODE_DEFAULT='/usr/local/lib/lattice/current/lattice-node'
        ;;
    *) echo 'Unsupported verification platform' >&2; exit 1 ;;
esac
exec "${LATTICE_NODE_BINARY:-$NODE_DEFAULT}" verify-installation "$@"
