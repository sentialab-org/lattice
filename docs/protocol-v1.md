# Lattice Protocol v1 Draft

## Node Lifecycle

```text
UNENROLLED
    |
    v
ENROLLING
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

## Core Messages

### EnrollmentRequest

Fields:

- node_name
- platform
- architecture
- public_key
- client_version

### EnrollmentResponse

Fields:

- node_id
- control_identity
- enrollment_token
- policy_revision

### Heartbeat

Fields:

- node_id
- timestamp
- health
- resources
- active_jobs
- client_version

### JobOffer

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

### JobDecision

Fields:

- job_id
- accepted
- reason

### JobStatus

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
