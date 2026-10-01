# Lattice Implementation Plan

## Goal

Build a distributed resource network where Windows and Linux machines can opt in as nodes, expose bounded resources, receive approved workloads from a control plane, and retain local authority over what may run.

## Current status

### Completed foundation

- Rust workspace
- shared protocol crate
- local IPC crate
- Windows Named Pipe transport
- Unix socket development transport
- persistent node configuration
- CPU and memory telemetry
- NVIDIA GPU discovery
- local workload permission policy
- local resource limits
- Tauri 2 desktop shell
- React and TypeScript node UI
- control URL configuration
- Windows-target compile validation
- end-to-end IPC runtime validation

### Completed Windows service milestone

- lattice-node Windows Service entry point
- automatic delayed startup
- graceful stop and shutdown handling
- service install, update, start, stop and uninstall commands
- Windows Service recovery actions
- per-machine NSIS installer configuration
- installer hooks for service lifecycle
- lattice-node sidecar preparation
- local Named Pipe ACL for interactive users
- GitHub Actions Windows installer build

### Completed identity and enrollment milestone

- persistent node ID
- persistent Ed25519 node keypair
- Windows DPAPI protection for node private keys
- restrictive Unix identity-file permissions
- persistent control-plane identity
- signed enrollment claims
- enrollment token validation
- node proof-of-possession verification
- signed enrollment receipts
- pinned control public key and fingerprint
- persistent enrolled-node registry
- restart-persistent node identity and control trust
- Tauri enrollment and trust-reset UX
- end-to-end enrollment test against lattice-control

### Completed heartbeat and capability milestone

- signed node heartbeats
- signed control-plane heartbeat receipts
- heartbeat timestamp validation
- replay-resistant time-ordered heartbeat sequence
- persistent last-seen state
- expiry-based online window
- CPU capability advertisement
- memory capability advertisement
- GPU capability advertisement
- runtime health reporting
- node connectivity state in Lattice Desktop

### Next milestone

Continue Protocol v1 with policy synchronization:

- define signed remote policy revisions
- send control-plane policy in authenticated heartbeat responses
- persist the latest accepted remote policy on the node
- compute an effective policy as the intersection of local and remote limits
- ensure remote policy can never expand local permissions
- expose local, remote and effective policy state in Lattice Desktop

## Phase 0 — Foundation

Status: complete

- Establish monorepo and shared protocol types
- Define node identity and capability model
- Define workload categories and lifecycle states
- Define local policy model
- Define control-plane trust boundaries

## Phase 1 — Node Core

Status: active

Completed:

- configuration persistence
- OS and hardware discovery
- CPU telemetry
- memory telemetry
- NVIDIA GPU discovery
- local IPC server
- local policy validation
- Windows background service
- graceful Windows service shutdown
- Windows service recovery policy
- persistent cryptographic node identity
- secure Windows private-key storage

Remaining:

- process supervisor
- job lifecycle
- resource enforcement
- structured logs
- graceful workload recovery
- Linux systemd unit

## Phase 2 — Desktop Control

Status: active

Completed:

- Tauri 2 shell
- node status
- resource allocation settings
- workload permission toggles
- control server setting
- IPC connection to lattice-node
- Windows installer integration
- enrollment UX
- pinned control fingerprint display
- enrollment reset action
- authenticated control connectivity state

Remaining:

- tray integration
- diagnostics
- job history
- logs
- first-run onboarding
- emergency pause
- update UX

## Phase 3 — Enrollment and Protocol v1

Status: active

Completed:

- Device keypair generation
- Node enrollment flow
- Control server trust establishment
- Heartbeat
- Capability advertisement
- Replay protection

Remaining:

- Policy synchronization
- Job lease protocol
- Job status events
- Artifact manifest validation

## Phase 4 — Runtime and Artifact System

- Signed runtime manifests
- SHA-256 artifact verification
- Version pinning
- Runtime cache
- Rollback
- Native process runtime
- Container runtime
- Workload adapters
- Resource accounting

Initial adapters:

- generic native workload
- XMRig
- llama.cpp
- ComfyUI worker
- FFmpeg
- Blender

## Phase 5 — Control Plane

Started:

- persistent control identity
- enrollment endpoint
- enrolled-node registry
- authenticated heartbeat endpoint
- node health tracking
- node capability inventory
- online expiry tracking

Remaining:

- Scheduler
- Job queue
- Runtime registry
- Artifact registry
- Policy management
- Telemetry ingestion
- Audit log
- Operator authentication

## Phase 6 — Scheduler

Scheduling inputs:

- node capabilities
- CPU availability
- RAM availability
- GPU model
- VRAM
- CUDA or ROCm support
- workload permissions
- node health
- artifact locality
- operator constraints

Scheduling output:

- eligible node set
- selected node
- job lease
- resource reservation

## Phase 7 — Production Hardening

- signed releases
- automatic node updates
- certificate rotation
- artifact signing key rotation
- crash recovery
- backpressure
- rate limiting
- metrics
- Prometheus export
- integration tests
- Linux packages
- reproducible builds

## Trust Model

The control plane may request work but cannot override local user policy.

The node rejects jobs when:

- the workload category is disabled
- resource requirements exceed local limits
- the runtime is not allowlisted
- the artifact signature is invalid
- the artifact hash does not match
- the job is expired
- the control server is not trusted
- the node is paused

The protocol does not expose an unrestricted command execution primitive.
