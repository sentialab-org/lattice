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

Status: core implementation complete.

Completed:

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
- managed process supervisor lifecycle fixture coverage
- restart suppression after lease expiry or policy-driven stop
- Windows CI validation

#### Priority C — Mining Operator Pipeline

Status: active.

Implemented on the operator pipeline branch:

- bearer-token protected operator endpoints
- immutable control-plane content store
- XMRig executable publication
- automatic mining-profile artifact publication
- immutable runtime and artifact registry mutation
- optional target-node mining jobs
- structured mining job creation
- operator node and job inspection
- credential redaction in job listings
- verified XMRig publication helpers for Windows and Linux
- pinned upstream XMRig archive SHA-256 bootstrap

Remaining before merge:

- final Windows CI validation
- live control-to-node test against a real enrolled node

#### Priority D — Unified Runtime Architecture

Status: next.

Goal: generalize the working XMRig execution path into a runtime-neutral architecture without regressing the Mining MVP.

Design decisions:

- `lattice-node` remains the trusted local authority and workload supervisor
- introduce a dedicated Rust `lattice-worker` process for each active lease
- runtime payloads remain immutable, signed, versioned and platform/architecture-specific
- runtime payloads and artifacts remain separate
- runtime backends execute only as descendants of the Lattice worker
- control-plane inputs remain typed and structured; no raw shell command or arbitrary argument vector
- node-to-worker control uses local IPC
- the node owns the OS resource-containment boundary for the complete worker tree
- Windows uses Job Objects; Linux uses cgroups v2 with a process-group fallback
- shutdown, lease expiry, policy revocation and emergency pause terminate the complete worker tree
- runtime adapters translate generic Lattice lifecycle/control operations into backend-specific behavior

The first public runtime contract is `lattice-miner`. XMRig is its first backend implementation. The existing `xmrig` runtime ID remains a compatibility path during migration.

See `docs/runtime-architecture.md` for the detailed design and migration sequence.

#### Priority E — Live Workload Control

Status: planned after Priority D.

Goal: mutate an already-running workload without replacing its immutable job lease.

Add a signed monotonic control-revision protocol bound to node ID, lease ID and job ID.

Initial generic controls:

- CPU limit
- memory limit
- GPU limit when enforceable
- pause
- resume
- stop

Initial mining controls:

- CPU budget and thread profile
- pool switch
- worker identity update
- pool password update
- pause and resume

Every revision is revalidated against the node owner's effective policy. The OS limit is authoritative; backend-specific settings are soft tuning only.

#### Priority F — Runtime-Neutral Server Core

Status: planned after live control is stable.

Control-plane responsibilities:

- runtime contract registry
- platform/architecture runtime variant registry
- immutable artifact/content publication
- structured workload validation
- job queue and lease store
- desired control state and revision history
- node capability and health inventory
- resource reservations
- scheduler
- telemetry ingestion
- audit history
- operator authentication and authorization
- workload-secret boundary

Mining remains the reference workload until this entire path is proven end to end.

#### Deferred until after Runtime Control MVP

- WASM runtime
- container runtime
- generic native workload runtime
- llama.cpp adapter
- ComfyUI adapter
- FFmpeg adapter
- Blender adapter
- advanced multi-node scheduling
- production database migration
- broader operator administration API

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

- extract the current XMRig executor behind the generic runtime-adapter boundary
- add the dedicated `lattice-worker` per-lease host
- add node-to-worker local control IPC
- add Windows Job Object CPU/memory containment
- add Linux cgroups v2 containment with process-group fallback
- add signed live workload-control revisions
- structured per-worker logs
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

- runtime adapter interface and dispatch
- dedicated `lattice-worker` execution host
- authenticated node-to-worker local control channel
- generic native process adapter
- OS resource containment and accounting
- live runtime-control revisions
- multi-file runtime-package format for backends requiring plugins or shared libraries
- WASM runtime
- container runtime

Adapter order:

1. `lattice-miner` using the current XMRig implementation as its first backend
2. generic native workload
3. WASM
4. container
5. llama.cpp
6. ComfyUI worker
7. FFmpeg
8. Blender

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
- runtime contract catalog
- runtime variant publication and lifecycle API
- mutable desired job-control store with monotonic revisions
- node acknowledgement state for control revisions
- scheduler resource reservations
- generalized job submission API
- telemetry ingestion
- audit log
- operator authentication and authorization
- workload-secret storage and delivery boundary

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
- exact runtime platform/architecture variant
- job lease
- resource reservation
- initial desired runtime-control revision

Running-job scheduling also tracks:

- current effective limits
- latest requested control revision
- latest node-applied control revision
- worker health
- runtime telemetry
- remaining lease lifetime

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
