# Lattice Node Client Web Console

## Overview

The Lattice Node Client Web Console provides a real-time, zero-dependency browser-based interface for monitoring and configuring the local `lattice-node` client daemon.

- **Standard Port**: `7444` (dedicated strictly to Node Client console per Lattice architectural guidelines; Control Plane resides on port `7443`).
- **Network Interface**: Strictly binds loopback `127.0.0.1` only. Remote network interfaces are disallowed to prevent unauthorized access.
- **IPC Protocol**: Communicates directly with the `lattice-node` core daemon via local IPC socket (`\\.\pipe\lattice-node` on Windows, `/var/run/lattice/node.sock` on Unix).

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

## Owner launch and module controls

Run `node web/node/server.mjs` as the configured local owner and open the private launch link printed in that terminal. The URL fragment is exchanged for an HttpOnly, SameSite=Strict browser session and removed from the address bar. Other local accounts cannot authorize requests merely by setting an Origin header. Do not expose or share the launch link. The bridge is an optional owner application, not a second network daemon.

The Control Trust tab shows Master, Relay and Supervisor lifecycle state, verified certificate references and the Base Node network owner. Master and Relay activation require local opt-in and valid device-bound certificates. Relay forwarding also requires a positive owner budget. Supervisor provisioning, authority-directory selection and gateway adoption require an elevated local CLI and are refused by both web and desktop bridges.

Issued public authority packages can be imported without contacting Supervisor. Synchronization failure is displayed independently from cached certificate validity. The Master catalog and owner selection use locally verified certificates. Local Master administration uses typed operations through private IPC; no shell command execution endpoint is provided.
