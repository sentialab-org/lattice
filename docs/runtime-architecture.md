# Lattice Runtime Architecture

## Purpose

Lattice must support multiple workload families without turning the control plane into a remote shell. The runtime layer separates trust, scheduling, execution, backend-specific behavior, resource enforcement and mutable runtime control.

Mining is the reference implementation because the repository already has a supervised XMRig workload, signed runtime delivery, immutable content caching, telemetry and operator job creation.

The new architecture generalizes that working path instead of replacing it.

## Core Model

A running workload has five separate concepts:

- **Job lease** — signed initial authorization to run one structured workload.
- **Runtime contract** — the logical execution interface, such as `lattice-miner`.
- **Runtime payload** — the immutable platform-specific executable or runtime package selected for the node.
- **Artifact** — immutable workload input consumed by the runtime.
- **Control revision** — signed mutable desired state for an already-running lease.

The control plane never sends an unrestricted shell command, executable path, environment block or arbitrary argument vector.

## Process Topology

The target native topology is:

```text
LatticeNode
    |
    +-- Lattice.Worker
            |
            +-- runtime backend
```

For mining:

```text
LatticeNode
    |
    +-- Lattice.Worker
            |
            +-- XMRig
```

`lattice-node` remains the trusted authority. The worker is disposable and scoped to one active lease. Backend processes are implementation details owned by the selected runtime adapter.

On Windows, the worker and all descendants belong to one Job Object owned by the node. On Linux, the equivalent boundary is cgroups v2 when available, with a process-group fallback for lifecycle containment.

Task Manager presentation is not a security boundary. Lattice relies on real process ownership, handles and OS containment.

## Component Responsibilities

### LatticeNode

The node:

- verifies control-plane identity and signed job leases
- verifies runtime and artifact manifests
- applies local and remote policy intersection
- resolves local platform and architecture
- acquires and verifies immutable content
- owns worker lifecycle
- owns hard resource enforcement
- validates live control revisions
- signs lifecycle and telemetry reports
- kills the complete workload tree on shutdown, expiry, policy revocation or emergency pause

### Lattice Worker

`lattice-worker` is a Rust executable shipped with the node release.

One worker is created per active lease. It:

- receives a sealed local job descriptor from the node
- opens a local control channel back to the node
- selects the built-in runtime adapter
- re-verifies runtime payload content immediately before backend start
- creates the isolated job working directory
- starts and supervises the backend
- captures stdout and stderr
- translates generic control operations into backend-specific behavior
- collects backend telemetry
- performs graceful stop and bounded forced termination
- reports backend exit and crash information to the node

The worker never accepts control-plane network traffic directly.

## Runtime Adapter Contract

Every runtime adapter implements equivalent lifecycle operations:

- validate
- prepare
- start
- apply control revision
- collect telemetry
- graceful stop
- forced termination
- bounded crash recovery

The node must not contain backend-specific command-line construction.

The first adapter is `lattice-miner`. Later adapters include generic native, WASM and container execution.

## Runtime Identity

The long-term public mining runtime identity is:

```text
lattice-miner
```

XMRig is the first backend implementation, not the server-facing runtime contract.

During migration, the existing `xmrig` runtime ID remains accepted so current jobs and published manifests keep working.

A logical runtime can have multiple immutable physical variants:

```text
lattice-miner@1.0.0
    windows / x86_64
    linux   / x86_64
    linux   / aarch64
    macos   / aarch64
```

Each physical variant has its own signed SHA-256, size and download URL.

The current miner needs only a single executable payload. A later runtime-package manifest can support multiple files for backends requiring plugins, shared libraries or accelerator-specific components.

## Artifact Boundary

Runtime payloads and artifacts stay independent.

For mining:

```text
runtime  = lattice-miner implementation payload
artifact = immutable mining workload/profile input
params   = pool/account/worker and initial runtime settings
```

For a future WASM workload:

```text
runtime  = lattice-wasm host
artifact = task.wasm
```

For a future media workload:

```text
runtime  = ffmpeg runtime
artifact = media input or processing bundle
```

This allows one verified runtime to serve many jobs and keeps runtime caching separate from workload data.

## Mining Adapter

The existing XMRig implementation is the migration source.

Preserve:

- typed whitelist-only mining configuration
- exact runtime binding
- final SHA-256 verification before every spawn
- isolated job directory
- managed XMRig configuration
- sanitized child environment
- stdout/stderr capture
- graceful stop and forced termination
- bounded exponential restart
- loopback telemetry
- signed Lattice lifecycle events

Server-facing mining inputs remain structured:

- algorithm
- pool
- account or wallet
- worker identity
- pool password
- TLS
- keepalive
- huge-page policy
- initial CPU budget
- restart policy

No raw XMRig argument vector is accepted from the server.

## Local XMRig Control

Live mining control flows only through the node and worker:

```text
Control Plane
    |
    | signed control revision
    v
LatticeNode
    |
    | policy validation + hard resource limit
    v
Lattice.Worker
    |
    | loopback-only backend control
    v
XMRig
```

The worker owns any loopback XMRig API endpoint and generates a random per-job access token locally. That token never comes from the control plane and is never exposed through telemetry.

Mining controls are introduced incrementally:

- CPU budget change
- thread/profile change
- pool switch
- worker identity change
- password change
- pause
- resume
- stop

If a setting cannot be changed safely in place, the adapter performs a managed backend restart while preserving the same Lattice lease and job identity.

## Resource Control

Resource control has two layers.

### Soft Backend Control

The adapter tunes backend behavior such as:

- XMRig thread/profile configuration
- pause/resume state
- future accelerator intensity

This improves efficiency and responsiveness.

### Hard OS Control

The node owns the authoritative ceiling:

- Windows Job Object CPU and memory limits
- Linux cgroups v2 CPU and memory limits
- platform-specific GPU controls only where a safe enforceable mechanism exists

The backend may consume less than the limit but must not be able to exceed it.

Values such as 7% CPU cannot always be represented exactly by miner thread count, so the OS resource boundary is authoritative and thread count is only tuning.

## Live Control Protocol

A job lease is immutable after acceptance. Runtime mutation uses a separate signed control object.

The planned control envelope contains:

- protocol version
- node ID
- lease ID
- job ID
- monotonic control revision
- issued timestamp
- expiry timestamp
- generic resource-limit patch
- runtime-specific typed patch
- requested action

Generic actions:

- update limits
- pause
- resume
- stop

Rules:

- revisions are strictly monotonic per lease
- an identical duplicate revision is idempotent
- changed content under an already observed revision is rejected
- expired controls are rejected
- effective local/remote policy is re-evaluated on every revision
- a revision cannot expand beyond current local authority
- node persists latest accepted and latest applied revision
- node returns a signed acknowledgement containing the effective applied state

The first transport can piggyback the latest desired control state on the authenticated polling path. A later persistent authenticated stream can reduce latency without changing protocol semantics.

## Server Core

The control plane evolves from the file-backed MVP toward explicit logical services:

- node registry
- capability and health state
- runtime contract registry
- runtime variant registry
- artifact registry
- job queue
- lease store
- desired control state
- applied-control acknowledgement state
- resource reservations
- telemetry
- audit events
- workload secrets

The scheduler operates on logical runtime contracts. Platform-specific payload resolution happens after a node is selected.

A running job remains assigned to one lease while control revisions modify its desired mutable state.

## Scheduler Order

Candidate filtering should happen in this order:

1. workload permission
2. node online and healthy state
3. runtime contract support
4. platform/architecture runtime availability
5. hardware capability requirements
6. local/effective resource limits
7. current resource reservation
8. artifact/runtime locality
9. operator placement constraints

The selected node receives an exact signed runtime variant and immutable artifact references.

## Mining Operator API Evolution

Keep the current mining operator API for compatibility.

Add:

- publish a `lattice-miner` runtime variant
- create a mining job
- inspect mining telemetry
- update desired CPU budget
- change pool configuration
- pause a mining job
- resume a mining job
- stop a mining job
- inspect requested versus applied control revision

Pool passwords and other workload credentials stay redacted from list APIs. Production storage should separate secrets from normal job records and encrypt them at rest.

## Runtime Kinds

### Native

First-class and implemented first.

Used for mining, llama.cpp, FFmpeg, Blender and accelerator-heavy workloads.

### WASM

Implemented after the native worker and control protocol are stable.

A WASM runtime hosts portable sandboxed task artifacts. Host imports are capability-based and expose only explicitly approved Lattice APIs.

### Container

Implemented after native/WASM semantics are proven.

Containers are useful for complex dependency stacks and Linux-first workloads, but they are optional rather than a requirement for ordinary Lattice nodes.

### Script

Not enabled as a general remote execution primitive. Any future script runtime must have a pinned interpreter, typed entrypoint and defined sandbox. Raw shell execution remains forbidden.

## Migration Sequence

### M0 — Preserve Mining MVP

- keep current XMRig execution working
- keep current runtime/artifact manifests valid
- keep current operator API valid
- add compatibility tests before refactoring

### M1 — Extract Runtime Core

- define runtime adapter descriptors and result types
- move generic lifecycle behavior out of mining-specific code
- keep mining behavior identical behind the adapter

### M2 — Add Lattice Worker

- add the Rust `lattice-worker` binary
- define node-to-worker local IPC
- move backend process ownership into the worker
- make the node own the worker containment boundary
- prove worker-tree cleanup on crash and node shutdown

### M3 — Add Hard Resource Enforcement

- Windows Job Object CPU/memory limits
- Linux cgroups v2 CPU/memory limits
- requested-versus-effective resource reporting

### M4 — Migrate Mining Identity

- introduce `lattice-miner`
- retain `xmrig` as a temporary compatibility alias
- move XMRig-specific behavior into the mining adapter
- preserve XMRig attribution and licensing obligations

### M5 — Add Live Control Revisions

- protocol types
- server desired-state store
- node validation and persistence
- worker control IPC
- signed acknowledgements
- CPU-limit update end to end

### M6 — Add Live Mining Reconfiguration

- per-job local backend-control token
- live thread/profile changes
- pool switch
- worker/password update
- pause/resume
- managed restart fallback

### M7 — Generalize Server Core and Scheduler

- runtime-contract-aware scheduling
- exact platform/architecture variant resolution
- resource reservations
- control revision tracking
- telemetry ingestion
- audit history

### M8 — Add the Second Runtime

WASM is the preferred second architectural proof because it validates that the adapter model is not coupled to native XMRig execution.

## Test Gates

Every milestone keeps:

- `cargo test --workspace`
- `cargo check --workspace`
- Windows target validation
- desktop build
- signed-manifest tamper tests
- runtime hash re-verification tests
- process-tree cleanup tests
- lease-expiry tests
- policy-revocation tests

New integration gates:

- Node -> Worker -> fixture backend
- worker crash without node crash
- node shutdown kills worker and descendants
- CPU cap cannot exceed effective policy
- stale control revision rejection
- duplicate control revision idempotency
- live CPU change reaches the miner
- pool switch reaches the miner
- backend control endpoint is loopback-only
- server restart preserves desired control revision
- node restart recovers or safely terminates the active workload

## Non-Goals

The runtime system will not:

- expose arbitrary remote shell execution
- accept raw remote command-line arguments
- let the control plane bypass local policy
- execute unsigned or mutable runtime content
- depend on process naming or Task Manager grouping as a security mechanism
- require containers for ordinary Lattice nodes
