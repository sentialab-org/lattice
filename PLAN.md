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

### Completed policy synchronization milestone

- signed remote policy delivery inside heartbeat receipts
- persistent remote policy cache on the node
- monotonic policy revisions with rollback rejection
- rejection of policy changes without a revision increment
- effective policy intersection between local and remote constraints
- remote policy cannot expand local workload permissions
- remote policy cannot raise local CPU, memory or GPU limits
- local, remote and effective policy state in Lattice Desktop

### Completed job lease milestone

- structured job offers without arbitrary command execution
- file-backed control-plane job queue
- signed control-plane job leases
- separate decision deadline and accepted lease lifetime
- job eligibility filtering by effective policy and hardware capabilities
- node-side independent policy and hardware validation
- signed explicit accept and reject decisions
- idempotent control-plane decision handling
- persistent accepted lease state on the control plane
- persistent active lease state on the node
- accepted lease recovery across node restart
- Jobs view in Lattice Desktop

### Completed job status event milestone

- signed job status events
- strict accepted, preparing, running, stopping, completed and failed transitions
- replay-resistant event sequence
- event ID conflict detection
- persistent control-plane event history
- persistent node-local event history
- durable pending-event outbox on the node
- heartbeat-based retry of unacknowledged events
- idempotent control acknowledgement for retried events
- signed control-plane status receipts
- authenticated status history in Lattice Desktop
- execution remains disabled until the runtime and artifact boundary exists

### Completed artifact manifest validation milestone

- signed artifact manifest structures
- immutable artifact ID and version references
- duplicate immutable-reference rejection
- SHA-256 format validation
- streamed local file SHA-256 verification
- signed-manifest tamper detection
- exact runtime and runtime-version binding
- control-plane artifact registry
- unknown artifact jobs remain unleased
- signed artifact manifest embedded in job leases
- node-side manifest verification before lease acceptance
- local immutable artifact cache metadata
- verified-content cache state for the later downloader

### Completed artifact acquisition and immutable content cache milestone

- exact signed artifact URL downloads
- redirects disabled for artifact requests
- separate artifact HTTP client with bounded connect and request timeouts
- streaming downloads into unique temporary files
- signed Content-Length enforcement when present
- hard signed-size enforcement while streaming
- streamed SHA-256 validation before promotion
- atomic promotion into a content-addressed `objects/<sha256>` cache
- immutable cache reuse without network access
- retry with bounded backoff
- failed-download and stale temporary-file cleanup
- cache metadata preserving verified content state
- artifact cache diagnostics in NodeStatus and Lattice Desktop
- verified cache reuse confirmed after node restart with artifact endpoint offline

### Completed signed runtime manifest and runtime cache milestone

- immutable runtime manifest structures
- exact runtime ID and version pinning
- platform and architecture binding
- persistent control-plane runtime registry
- signed runtime manifests using the pinned control-plane Ed25519 identity
- scheduler fail-closed behavior for missing or incompatible runtimes
- signed runtime manifest embedded in every job lease
- node-side runtime signature and platform validation before lease acceptance
- separate immutable runtime metadata cache
- content-addressed runtime payload cache
- streamed size and SHA-256 verification before cache promotion
- offline runtime cache reuse after node restart
- side-by-side runtime versions without mutable `latest` aliases
- runtime cache diagnostics in NodeStatus and Lattice Desktop
- platform-mismatch E2E validation

### Current priority

The short-term roadmap is intentionally reprioritized.

Generic native workload execution remains important, but deployment maintainability and the first production-oriented workload come first.

#### Priority A — Secure Auto Update

Status: core implementation complete.

Completed in the current updater implementation:

- signed immutable release manifest types
- stable and beta release channels
- component version metadata
- platform and architecture binding
- SHA-256 and payload-size binding
- HTTPS-only remote payload policy with localhost development exceptions
- minimum-supported-version metadata
- persistent control-plane release registry
- signed latest-release discovery endpoint
- node-side signature verification using pinned control trust
- semantic-version downgrade rejection
- minimum-supported-version gate
- verified immutable update staging
- persistent update state
- staged update invalidation when enrollment trust or release channel changes
- desktop visibility for installed version, channel, available version, staging state, progress, rollback metadata and errors
- dedicated Windows update helper
- managed apply-plan path constraints
- stop LatticeNode before replacement
- persistent previous-executable backup
- atomic executable replacement
- service restart
- local IPC health verification
- expected-version verification
- automatic rollback on failed restart or health checks
- rollback health verification
- bounded persisted apply retries
- unit coverage for signature tampering, downgrade rejection and corrupted payload staging
- end-to-end Windows service replacement and forced-rollback CI validation

Remaining:

- release publishing and distribution automation
- production release signing operational procedure

#### Priority B — XMRig Mining Workload

Status: active.

Implemented on the mining workload branch:

- immutable signed XMRig runtime binding
- runtime SHA-256 re-verification immediately before every process start
- typed whitelist-only mining configuration
- local and remote mining permission intersection
- bounded CPU thread policy
- isolated job directory
- managed XMRig JSON configuration
- stdout and stderr capture
- sanitized child environment
- graceful and forced stop
- bounded exponential crash restart
- loopback XMRig API telemetry
- signed job lifecycle integration
- scheduler-side mining eligibility validation

Remaining before merge:

- Windows CI validation
- end-to-end fixture coverage for the managed XMRig process lifecycle

#### Deferred until after Mining MVP

- generic native process runtime
- broader runtime adapters
- ComfyUI adapter
- llama.cpp adapter
- FFmpeg adapter
- Blender adapter
- advanced scheduler
- production database migration
- operator administration API

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
- active job lease view
- authenticated job status history
- update channel selection
- update progress and lifecycle diagnostics
- rollback and error visibility

Remaining:

- tray integration
- diagnostics
- logs
- first-run onboarding
- emergency pause

## Phase 3 — Enrollment and Protocol v1

Status: complete

Completed:

- Device keypair generation
- Node enrollment flow
- Control server trust establishment
- Heartbeat
- Capability advertisement
- Replay protection
- Policy synchronization
- Job lease protocol
- Job status events
- Artifact manifest validation

## Phase 4 — Runtime and Artifact System

Status: active

Completed:

- Signed artifact manifests
- SHA-256 artifact verification primitives
- Artifact version pinning
- Runtime-to-artifact binding
- Local artifact manifest cache metadata
- Artifact download and immutable content cache
- Content-addressed SHA-256 artifact objects
- Artifact download retry, timeout and cleanup
- Artifact cache diagnostics
- Signed runtime manifests
- Platform and architecture runtime binding
- Runtime content cache
- Side-by-side rollback-safe runtime version pinning
- Runtime cache diagnostics

Remaining:

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
- signed policy distribution
- file-backed control policy revision
- file-backed job queue
- signed job leases
- signed job decisions
- persistent lease state
- signed job status endpoint
- persistent job event history
- replay-resistant status sequences

Remaining:

- policy administration API
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
