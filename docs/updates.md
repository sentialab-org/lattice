# Secure Auto Update

## Scope

The updater is responsible for discovering, authenticating, staging, applying and validating immutable Lattice component releases.

The current Windows implementation covers release discovery, authenticated staging, service-safe executable replacement, IPC/version health verification, and automatic rollback.

## Release manifest

Each release is immutable and identified by the full tuple:

- component
- version
- channel
- platform
- architecture

A ReleaseManifest contains:

- schema_version
- component
- version
- channel
- platform
- architecture
- sha256
- size_bytes
- download_url
- minimum_supported_version
- issued_at_ms

Supported release channels are:

- stable
- beta

The initial component set is:

- node
- desktop
- update_helper

Versions use semantic versioning. Mutable aliases such as latest are not valid versions.

Remote payload URLs must use HTTPS. Loopback HTTP is permitted only for local development and tests.

## Control-plane registry

The release registry is stored at:

```text
<data directory>/releases.json
```

The registry is validated when lattice-control starts.

The control plane rejects:

- unsupported manifest schema versions
- invalid semantic versions
- unknown platform or architecture values
- invalid SHA-256 values
- zero-size payloads
- invalid minimum-supported versions
- minimum-supported versions greater than the release version
- insecure non-local payload URLs
- duplicate immutable release tuples

The discovery endpoint is:

```text
GET /api/v1/releases/latest
```

Query parameters:

- component
- channel
- platform
- architecture

The highest semantic version matching the exact query tuple is signed using the persistent control-plane Ed25519 identity and returned as a SignedReleaseManifest.

An empty match returns JSON null.

## Node validation

The node checks releases only after enrollment because the pinned control public key is the release trust root.

Before a payload may be staged, the node validates:

- control-plane Ed25519 signature
- component is lattice-node
- release channel matches local configuration
- platform matches the local node identity
- architecture matches the local node identity
- target version is valid semantic versioning
- target version is not lower than the installed version
- installed version satisfies minimum_supported_version when present
- SHA-256 format is valid
- payload size is non-zero
- remote payload URL uses HTTPS

A release signed by a previous control identity is not retained as staged state after enrollment reset.

Changing release channels also clears staged update content from the previous channel.

## Staging

Update state is stored at:

```text
<node data directory>/updates/state.json
```

Verified update content is staged under:

```text
<node data directory>/updates/staging/objects/<sha256>
```

Downloads use:

- redirects disabled
- bounded request timeouts
- exact signed Content-Length checking when present
- hard signed-size enforcement during streaming
- streamed SHA-256 validation
- unique temporary files
- bounded retry
- atomic promotion only after verification

Corrupted or incomplete payloads never become staged objects.

## Persistent state

UpdateStatus tracks:

- installed_version
- release_channel
- available_version
- minimum_supported_version
- state
- downloaded_bytes
- total_bytes
- staged_version
- staged_path
- previous_version
- backup_path
- last_error
- retry_count
- checked_at_ms

State values are:

```text
idle
available
downloading
staged
applying
restarting
verifying
rolling_back
failed
```

The Windows update helper persists applying, restarting, verifying, rolling_back, idle, and failed transitions while preserving retry and rollback metadata across process boundaries.

## Windows apply boundary

The node stages only content that passed signed manifest validation and SHA-256 verification. Before replacement it writes an UpdateApplyPlan and launches the dedicated lattice-update-helper process.

The helper independently constrains every managed path:

- target must be lattice-node.exe next to the installed update helper
- state must be %PROGRAMDATA%\\Lattice\\updates\\state.json
- backup must be under the managed backup directory
- staged content must be the SHA-256-named object under the managed staging directory
- target semantic version must be greater than the current version

The apply sequence is:

1. verify the staged payload again
2. persist applying state
3. copy and sync the current node executable to the rollback path
4. copy, sync and verify the staged executable beside the installed node
5. stop LatticeNode
6. atomically replace lattice-node.exe
7. restart LatticeNode
8. persist verifying state
9. require local IPC to return the expected installed version
10. persist idle only after the health gate passes

If restart or health verification fails, the helper:

1. persists rolling_back
2. stops the failed node
3. verifies the preserved backup
4. atomically restores the previous executable
5. restarts LatticeNode
6. requires IPC to report the previous version
7. persists failed with the rollback result and increments the bounded retry counter

The previous executable is preserved through the health gate. Repeated apply attempts are bounded by the persisted retry count.

## Windows validation

The Windows CI lifecycle test installs a real LatticeNode service and validates both paths:

- successful replacement from 0.1.0 to 0.1.1 followed by IPC/version health verification
- forced 0.1.2 health mismatch followed by automatic restoration of 0.1.1

The same workflow also runs the Rust workspace tests and checks before building the NSIS installer.
