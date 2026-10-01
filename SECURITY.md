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

## Node Identity

Each node has a persistent Ed25519 identity.

On Windows, the node private key is protected with Windows DPAPI before it is written to disk.

On Unix development targets, identity files are restricted to mode 0600 and their containing directory is restricted to mode 0700. Production Linux hardening may additionally use an operating-system secret store.

The node private key is never sent to the control plane.

## Enrollment Trust

Enrollment requires:

- an explicitly configured control URL
- HTTPS for non-local control servers
- an enrollment token
- a signed node claim
- a signed control receipt

The control public key is pinned after enrollment. A different control identity is not accepted automatically. The local user must reset enrollment first.

Enrollment tokens are not persisted by the node.

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
- trust resets
- policy changes
- job acceptance and rejection
- artifact download and verification
- process start and stop
- resource usage
- runtime updates
