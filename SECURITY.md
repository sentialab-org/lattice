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

Artifact manifests are signed by the pinned control-plane Ed25519 identity.

Before accepting a job lease, the node validates:

- manifest signature
- immutable artifact ID and version
- exact runtime and runtime-version binding
- lowercase SHA-256 digest format
- signed artifact size
- HTTPS download URL outside localhost

Unknown artifacts are not leased by the control plane. A manifest with a valid signature but a runtime binding that differs from the job is rejected locally.

The node stores verified manifest metadata in an immutable local cache index. Reusing the same artifact ID and version with different manifest content is rejected.

Artifact downloads use the exact signed manifest URL. Redirects are disabled. Non-local URLs require HTTPS. Downloads stream into unique temporary files, enforce the signed size while receiving data, and calculate SHA-256 incrementally.

A payload is promoted into the immutable content-addressed `objects/<sha256>` cache only after both signed size and SHA-256 verification succeed. Failed downloads are removed and never promoted. Verified cached content can be reused without contacting the artifact endpoint.

Runtime execution remains disabled. The future runtime layer must verify the selected cached object immediately before execution so local post-cache tampering cannot authorize code execution.

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
