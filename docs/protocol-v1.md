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

Status: planned next.

Remote policy will be carried only inside authenticated control-plane responses. The node will intersect remote policy with local policy so the control plane cannot expand locally granted permissions or resource limits.

## JobOffer

Fields:

- job_id
- workload_kind
- runtime
- runtime_version
- artifact_id
- artifact_version
- resources
- parameters
- expires_at

## JobDecision

Fields:

- job_id
- accepted
- reason

## JobStatus

Fields:

- job_id
- state
- started_at
- finished_at
- exit_code
- resource_usage

## Job States

- offered
- accepted
- preparing
- running
- stopping
- completed
- failed
- rejected
- expired
