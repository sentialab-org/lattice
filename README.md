# Lattice

Lattice is a cross-platform distributed resource network for running user-approved workloads across Windows and Linux nodes.

## Current foundation

- Rust node daemon
- Windows Named Pipe IPC
- Unix socket fallback for Linux and macOS development
- persistent local node policy
- CPU and memory telemetry
- NVIDIA GPU detection through nvidia-smi
- Tauri 2 desktop application
- React and TypeScript desktop UI
- workload permission controls
- CPU, RAM and GPU allocation controls
- control server URL configuration
- shared protocol types
- control-plane placeholder

## Components

- `lattice-node`: local node daemon and resource supervisor
- `lattice-ipc`: local desktop-to-node IPC transport
- `lattice-protocol`: shared protocol and domain types
- `lattice-control`: control-plane foundation
- `apps/lattice-desktop`: Tauri desktop application
- `web/control`: central control dashboard placeholder
- `docs`: architecture, protocol and platform plans

## Principles

- Local user consent always wins over remote policy
- No arbitrary remote shell
- Workloads are allowlisted and versioned
- Artifacts must be verified before execution
- Resource limits are enforced locally
- Windows and Linux are first-class targets
- Mining is only one workload category

## Development

Run the node:

```bash
cargo run -p lattice-node
```

Run the desktop app:

```bash
cd apps/lattice-desktop
npm install
npm run tauri dev
```

Validate the Rust workspace:

```bash
cargo check --workspace
```

Validate the Windows Rust target:

```bash
cargo check --workspace --target x86_64-pc-windows-gnu
```
