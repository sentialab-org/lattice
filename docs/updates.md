# Secure Auto Update

## Scope

The updater is responsible for discovering, authenticating, staging, applying and validating immutable Lattice component releases.

The current implementation completes release discovery and verified staging. Windows service-safe replacement and rollback are the next implementation slice.

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

The current implementation reaches staged. The remaining states are reserved for the Windows replacement and rollback helper.

## Windows apply boundary

The next updater slice must preserve these invariants:

1. Only the exact verified staged object may be installed.
2. The current executable is copied to a persistent rollback path before replacement.
3. LatticeNode is stopped before executable replacement.
4. Replacement is atomic within the target filesystem.
5. LatticeNode is restarted after replacement.
6. The new node must answer local IPC.
7. The reported installed version must equal the staged version.
8. The previous executable remains available until the health gate succeeds.
9. Any failed health gate triggers automatic rollback.
10. Retry is bounded and persisted.

The node service must never overwrite its currently running executable directly without the dedicated update helper.
