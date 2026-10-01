# Security Model

Lattice is designed around explicit node-owner consent.

## Local Authority

The node owner controls:

- whether the node participates
- which control server is trusted
- which workload categories are allowed
- CPU allocation
- memory allocation
- GPU allocation
- whether mining is allowed
- emergency pause and disconnect

Remote policy cannot raise permissions beyond local policy.

## Remote Execution Boundary

Lattice does not provide a generic remote shell.

Jobs reference known runtimes, signed artifacts and structured arguments. The node validates the request before execution.

## Artifact Verification

Production artifacts must be:

- transported over authenticated TLS
- described by a signed manifest
- verified by cryptographic hash
- mapped to an allowlisted runtime
- cached by immutable version identifier

## Auditability

The node should record:

- enrollment
- policy changes
- job acceptance and rejection
- artifact download and verification
- process start and stop
- resource usage
- runtime updates
