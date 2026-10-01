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

### Next milestone

Establish persistent node identity and authenticated enrollment:

- generate a persistent node identifier
- generate a node keypair
- store identity securely
- define enrollment request and response messages
- establish control-server trust
- expose enrollment state in Lattice Desktop

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

Remaining:

- persistent cryptographic node identity
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

Remaining:

- tray integration
- diagnostics
- job history
- logs
- first-run onboarding
- enrollment UX
- emergency pause
- update UX

## Phase 3 — Enrollment and Protocol v1

Status: next

- Device keypair generation
- Node enrollment flow
- Control server trust establishment
- Heartbeat
- Capability advertisement
- Policy synchronization
- Job lease protocol
- Job status events
- Artifact manifest validation
- Replay protection

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

- Node registry
- Node health
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
