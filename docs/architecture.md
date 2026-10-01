# Architecture

## Overview

```text
                  Lattice Control
                        |
                 authenticated API
                        |
        +---------------+---------------+
        |               |               |
   Lattice Node    Lattice Node    Lattice Node
     Windows           Linux           Linux
        |               |               |
        +---------- Workloads -----------+
```

## Node

The node is the trusted local authority.

Subsystems:

- identity
- enrollment
- capability discovery
- policy engine
- scheduler client
- artifact manager
- runtime manager
- process supervisor
- resource controller
- telemetry
- local IPC

## Desktop Control

Lattice Desktop is a Tauri application that talks to the node over local IPC.

Windows uses a local-only Named Pipe. Linux uses a Unix domain socket. The desktop process does not own workload lifecycle, so closing the UI does not stop the node.

Its purpose is local ownership and configuration, not fleet administration.

## Control Plane

The control plane owns fleet-level orchestration:

- node registry
- scheduling
- workload definitions
- runtime and artifact metadata
- telemetry aggregation
- audit events

## Runtime Model

A workload does not contain an arbitrary shell command.

A workload references:

- workload kind
- runtime
- runtime version
- artifact
- structured parameters
- resource requirements
- expiration
- job identity

The node resolves the runtime and decides whether execution is permitted.
