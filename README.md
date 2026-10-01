# Lattice

Lattice is a cross-platform distributed resource network for running user-approved workloads across Windows and Linux nodes.

## Current foundation

- Rust node daemon
- Windows Service host
- Windows Named Pipe IPC
- Unix socket fallback for Linux and macOS development
- persistent local node policy
- persistent Ed25519 node identity
- Windows DPAPI private-key protection
- signed node enrollment
- pinned control-plane identity
- signed heartbeat protocol
- replay-resistant heartbeat sequence
- authenticated control connectivity state
- CPU, memory and GPU capability advertisement
- runtime health reporting
- signed remote policy synchronization
- local and remote policy intersection
- persistent effective policy state
- signed structured job leases
- explicit signed lease decisions
- persistent accepted lease state
- signed job status events
- durable status-event retry and history
- signed immutable artifact manifests
- control-plane artifact registry
- runtime-to-artifact binding
- streamed SHA-256 content verification
- local artifact cache metadata
- content-addressed immutable artifact cache
- streamed artifact download and SHA-256 verification
- bounded artifact download retries and cleanup
- artifact cache diagnostics
- signed platform-specific runtime manifests
- immutable content-addressed runtime cache
- runtime version pinning and offline cache reuse
- runtime cache diagnostics
- Tauri 2 desktop application
- React and TypeScript desktop UI
- enrollment and trust-reset UI
- local, remote and effective policy UI
- active job lease UI
- authenticated job status history UI
- workload permission controls
- CPU, RAM and GPU allocation controls
- NSIS per-machine Windows installer configuration
- automatic service install, update, start, stop and uninstall hooks
- automatic Windows service restart policy
- persistent lattice-control identity
- signed enrollment and heartbeat endpoints
- persistent enrolled-node registry
- node last-seen and online expiry tracking
- shared protocol and crypto crates
- Windows CI installer build

## Components

- `lattice-node`: local node daemon, Windows Service host and resource supervisor
- `lattice-crypto`: Ed25519 signing, verification and fingerprints
- `lattice-ipc`: local desktop-to-node IPC transport
- `lattice-protocol`: shared protocol and domain types
- `lattice-control`: control-plane service and artifact registry
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

## Node Development

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

## Control Development

```bash
LATTICE_ENROLLMENT_TOKEN=development-token cargo run -p lattice-control
```

The local development control URL is:

```text
http://127.0.0.1:7443
```

## Validation

```bash
cargo test --workspace
cargo check --workspace
cargo check --workspace --target x86_64-pc-windows-gnu
```

## Windows Installer

On Windows:

```powershell
cd apps/lattice-desktop
npm ci
npm run tauri build -- --bundles nsis
```

GitHub Actions builds the Windows NSIS installer on every push to `main` and on pull requests.
