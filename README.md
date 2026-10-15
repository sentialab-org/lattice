# Lattice

Lattice is a cross-platform distributed resource network for running user-approved workloads across macOS, Windows and Linux nodes.

## Normalized product flow

Open `/install` on the Lattice website. Ordinary nodes join publicly without tokens;
masters are participating nodes activated by a one-device dashboard token. The
operator dashboard uses account sessions. Native setup owns joining, stable IPs,
WireGuard readiness, master discovery and retries; system installers handle elevation
and boot services. Owner workload policy remains unchanged.

See [release distribution](docs/release-distribution.md), [network convergence](docs/network-convergence.md)
and [acceptance status](docs/product-normalization-acceptance.md). Source implementation
is distinct from a published or physically accepted installation.

The current release is a **Linux-first 0.2.2 pilot**, not global stable. Linux
x86_64 root installation, real hub TCP, restart, dedicated-VM reboot/reconnect and
master handover/revocation passed. Edge runs the ARM64 bootstrapper; a separate
ARM64 node installation, native Windows and Intel Mac installation remain untested.
Use an explicit version for the Linux pilot:

```bash
curl -fsSL https://lattice.sentialab.org/installer/linux.sh | env LATTICE_VERSION=0.2.2 bash
```

Master installation adds `LATTICE_ROLE=master` to `env` and requests the
dashboard activation token privately after elevation. Default stable commands
remain unavailable until the advertised native acceptance gates are complete.

## Current foundation

- Rust node daemon
- Windows Service host
- Windows Named Pipe IPC
- protected system Unix socket IPC for Linux and macOS
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
- authenticated operator runtime publication
- immutable control-plane content store
- immutable content-addressed runtime cache
- runtime version pinning and offline cache reuse
- runtime cache diagnostics
- signed release manifests and stable/beta channels
- control-plane release discovery
- node-side anti-downgrade release validation
- verified immutable update staging
- persistent update state and desktop update diagnostics
- Tauri 2 desktop application
- React and TypeScript desktop UI
- enrollment and trust-reset UI
- local, remote and effective policy UI
- active job lease UI
- authenticated job status history UI
- workload permission controls
- CPU, RAM and GPU allocation controls
- supervised XMRig mining workload
- targeted mining job queue
- mining runtime publication helpers
- NSIS per-machine Windows installer configuration
- automatic service install, update, start, stop and uninstall hooks
- automatic Windows service restart policy
- persistent lattice-control identity
- signed enrollment and heartbeat endpoints
- persistent enrolled-node registry
- node last-seen and online expiry tracking
- shared protocol and crypto crates
- configurable overlay CIDR, gateway, interface, cluster ID, and reserved IPs
- signed WireGuard network register, sync, ack, peer discovery, and NAT candidates
- stable virtual IPv4 IPAM with NBI reservations
- hub and direct path policy with relay descriptors and UDP hole punching
- handshake freshness and relay rotation fallback
- node peer cache with peer count and path policy diagnostics
- combined, bootstrapper, and master control roles with dedicated binaries
- shared lattice_control library with role-gated routers
- local role-complete release assembly without GitHub Actions

## Components

- `lattice-node`: local node daemon, Windows Service host and resource supervisor
- `lattice-update-helper`: service-safe Windows node replacement and rollback helper
- `lattice-crypto`: Ed25519 signing, verification and fingerprints
- `lattice-ipc`: local desktop-to-node IPC transport
- `lattice-protocol`: shared protocol and domain types
- `lattice-control`: legacy combined control-plane service, mounts all routes
- `lattice-bootstrapper`: network coordination, IPAM, and peer discovery server
- `lattice-master`: workload orchestration, scheduling, and command authority server
- `apps/lattice-desktop`: Tauri desktop application
- `web/control`: operator console with fleet monitor, overlay network leases, and copy-paste node enrollment
- `web/node`: local node console with network diagnostics
- `docs`: architecture, protocol, updater, platform, and network convergence plans

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
LATTICE_ENROLLMENT_TOKEN=development-token \
LATTICE_OPERATOR_TOKEN=development-operator-token \
LATTICE_PUBLIC_URL=http://127.0.0.1:7443 \
cargo run -p lattice-control
```

See `docs/mining-operator.md` for publishing a verified XMRig runtime and queuing mining jobs.

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
