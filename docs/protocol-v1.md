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

Status: planned next.

Heartbeat will carry:

- node_id
- request_id
- timestamp
- health
- capabilities
- active_jobs
- client_version
- signature

Heartbeat messages will be authenticated with the node Ed25519 key and protected against replay.

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
