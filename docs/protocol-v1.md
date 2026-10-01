# Lattice Protocol v1 Draft

## Node Lifecycle

```text
UNENROLLED
    |
    v
ENROLLING
    |
    v
ENROLLED
    |
    v
ONLINE
    |
    +--> IDLE
    |
    +--> RUNNING
    |
    +--> PAUSED
    |
    +--> DEGRADED
    |
    +--> OFFLINE
```

## Cryptographic Identity

Every node creates a persistent Ed25519 keypair and a random node ID before enrollment.

The node public key is part of the enrollment claim. The corresponding private key never leaves the node.

Every control plane also has a persistent Ed25519 identity. During enrollment, the control public key is returned in a signed receipt. The node stores the control key and its SHA-256 fingerprint as pinned trust state.

Changing to a different control identity requires an explicit local enrollment reset.

## Enrollment

### EnrollmentClaim

Fields:

- protocol_version
- request_id
- node_id
- node_name
- platform
- architecture
- public_key
- client_version
- issued_at_ms

### EnrollmentRequest

Fields:

- claim
- enrollment_token
- signature

The signature is Ed25519 over the serialized EnrollmentClaim.

The control plane validates:

- protocol version
- enrollment token
- request timestamp
- public key encoding
- node proof-of-possession signature
- node ID and public-key consistency

### EnrollmentReceipt

Fields:

- protocol_version
- request_id
- node_id
- control_id
- control_public_key
- policy_revision
- issued_at_ms

### EnrollmentResponse

Fields:

- receipt
- signature

The signature is Ed25519 over the serialized EnrollmentReceipt.

The node validates:

- protocol version
- request ID
- node ID
- control signature
- control public key

The node then pins:

- control URL
- control ID
- control public key
- control public-key fingerprint
- policy revision
- enrollment timestamp

The enrollment token is not persisted by the node.

## Heartbeat

### HeartbeatClaim

Fields:

- protocol_version
- request_id
- node_id
- sequence
- issued_at_ms
- client_version
- capabilities
- health

Capabilities currently include:

- operating system
- kernel
- architecture
- CPU model
- logical CPU count
- physical CPU count
- total memory
- GPU names
- GPU memory

Health currently includes:

- runtime state
- CPU utilization
- memory usage
- active job count

### HeartbeatRequest

Fields:

- claim
- signature

The signature is Ed25519 over the serialized HeartbeatClaim.

### HeartbeatReceipt

Fields:

- protocol_version
- request_id
- node_id
- control_id
- policy_revision
- issued_at_ms

### HeartbeatResponse

Fields:

- receipt
- signature

The control plane validates the node signature, timestamp and sequence. The sequence is time-ordered and must be greater than the last accepted sequence for that node.

The control plane persists:

- last_seen_ms
- online_until_ms
- last_sequence
- capabilities
- health
- client version

A successful heartbeat is acknowledged with a control-signed HeartbeatReceipt. The node validates the pinned control ID and pinned control public key before considering the control connection healthy.

## Policy Synchronization

Remote policy is delivered only inside a control-signed HeartbeatReceipt.

A PolicySnapshot contains:

- revision
- enabled state
- allowed workload categories
- maximum CPU percentage
- optional maximum memory
- optional maximum GPU percentage
- optional maximum GPU memory

The node persists the latest accepted remote policy. A lower revision is rejected as a rollback. If policy content changes without a revision increase, the node rejects the response.

The effective policy is the intersection of local owner policy and remote control policy:

- enabled = local AND remote
- workload permission = local AND remote
- CPU limit = minimum of local and remote
- memory limit = minimum when a remote cap exists
- GPU limit = minimum when a remote cap exists
- GPU memory limit = minimum when both local and remote caps exist

The control plane can therefore restrict resource use or workload categories, but it cannot expand permissions or resource limits granted locally by the node owner.

Resetting enrollment clears the cached remote policy.

## Job Lease Protocol

Jobs are structured workload descriptions. They do not contain an unrestricted shell command.

### JobOffer

Fields:

- job_id
- workload_kind
- runtime
- runtime_version
- artifact_id
- artifact_version
- resource limits
- structured parameters
- job expiration timestamp

### JobLease

Fields:

- lease_id
- node_id
- JobOffer
- issued_at_ms
- decision_deadline_ms
- expires_at_ms

The control plane signs each JobLease independently with its pinned Ed25519 identity.

The decision deadline bounds how long an offered lease may wait for a node response. The lease expiration bounds the accepted reservation lifetime.

Before accepting, the node validates:

- control-plane signature
- node ID
- decision deadline
- lease expiration
- job expiration
- effective workload-category permission
- effective CPU, memory and GPU limits
- local hardware memory availability
- local GPU availability and VRAM when requested

### JobDecisionClaim

Fields:

- protocol_version
- request_id
- node_id
- lease_id
- job_id
- accepted
- reason
- issued_at_ms

The node signs JobDecisionClaim with its persistent Ed25519 identity and sends it to:

```text
POST /api/v1/jobs/decision
```

The control plane validates the node signature, lease ownership, lease deadline and current job state. It persists Accepted or Rejected and returns a control-signed JobDecisionReceipt.

The node verifies the receipt before persisting its local lease state.

Accepted leases are reservations only at this phase. Runtime process execution is intentionally deferred until artifact verification and runtime adapters are implemented.

## Job Status Events

After a lease is accepted, job lifecycle changes are reported as signed JobStatusEvent messages. Runtime execution is still disabled at this phase, but the protocol and durable event history are complete.

### JobStatusEvent

Fields:

- event_id
- lease_id
- job_id
- state
- sequence
- detail
- exit_code
- issued_at_ms

### JobStatusClaim

Fields:

- protocol_version
- node_id
- JobStatusEvent

The node signs the JobStatusClaim with its persistent Ed25519 identity and sends it to:

```text
POST /api/v1/jobs/status
```

The control plane validates:

- protocol version
- event timestamp
- node enrollment state
- node Ed25519 signature
- lease ownership
- lease expiration
- event ID uniqueness
- monotonic event sequence
- allowed state transition

Allowed transitions are:

```text
Accepted  -> Preparing | Failed
Preparing -> Running | Stopping | Failed
Running   -> Stopping | Completed | Failed
Stopping  -> Completed | Failed
```

The initial Accepted event is recorded after a successful lease decision.

The control plane persists each accepted event and returns a signed JobStatusReceipt. Re-sending the exact same event ID and content is idempotent and returns an acknowledgement without creating a duplicate history entry. Reusing an event ID with different content is rejected.

The node uses a durable pending-event outbox. A status event is written locally before transmission. If the process crashes or the acknowledgement is lost, subsequent heartbeats retry the same event ID and sequence until the signed receipt is verified.

Confirmed events are then moved into the node-local event history and the pending entry is cleared.

## Job States

- queued
- offered
- accepted
- preparing
- running
- stopping
- completed
- failed
- rejected
- expired
