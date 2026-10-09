# Lattice Node Client Web Console

## Overview

The Lattice Node Client Web Console provides a real-time, zero-dependency browser-based interface for monitoring and configuring the local `lattice-node` client daemon.

- **Standard Port**: `7444` (dedicated strictly to Node Client console per Lattice architectural guidelines; Control Plane resides on port `7443`).
- **Network Interface**: Strictly binds loopback `127.0.0.1` only. Remote network interfaces are disallowed to prevent unauthorized access.
- **IPC Protocol**: Communicates directly with the `lattice-node` core daemon via local IPC socket (`\\.\pipe\lattice-node` on Windows, `/tmp/lattice-node.sock` on Unix).

## Features

- **Telemetry & Engine Status**: Live CPU load, memory utilization, hardware snapshots, and active mining engine statistics.
- **Policy Control**: Configure local sharing policy limits (maximum CPU, RAM, and permitted workload types like Mining, AI, Rendering, Media, Research).
- **Lease Inspector**: View current active job leases, cryptographic lease signatures, and control revision history.
- **Cache Management**: Inspect content-addressed artifact and runtime storage.
- **Log Streamer**: Live miner stdout/stderr log stream viewer with auto-scroll.

## Security Controls

1. **Strict Loopback Binding**: Binds exclusively to `127.0.0.1`.
2. **CORS Hardening**: Strict origin verification; requests with cross-origin headers not originating from `127.0.0.1` or `localhost` are rejected with HTTP 403.
3. **Content Security Policy (CSP)**: `default-src 'self'` with strict script and style restrictions.
4. **Request Body Cap**: 64 KB maximum payload limit on all incoming POST requests to eliminate denial-of-service vectors.
5. **IPC Security**: Protected endpoint with error isolation and timeout bounds.
