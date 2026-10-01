# Windows-first implementation

## Process model

```text
Lattice.exe
    |
    | Named Pipe
    v
LatticeNode Windows Service
    |
    +-- local policy
    +-- hardware telemetry
    +-- runtime manager
    +-- workload supervisor
    +-- control-plane client
```

Lattice Desktop is a control surface. The node service owns policy and workload lifecycle.

## Windows service

The service name is:

```text
LatticeNode
```

The display name is:

```text
Lattice Node
```

The service starts automatically with delayed auto-start and runs in its own process.

The node executable supports:

```text
--service
--install-service
--uninstall-service
--start-service
--stop-service
```

## Local IPC

Windows uses the named pipe:

```text
\\.\pipe\lattice-node
```

Remote named-pipe clients are rejected.

The pipe security descriptor grants full access to Local System and administrators and read/write access to interactive users.

The current IPC protocol supports:

- ping
- node status
- read node configuration
- update node configuration

## Node identity

The Windows node stores its persistent identity next to the local configuration. The Ed25519 private key is encrypted with Windows DPAPI before being written to disk.

The identity contains:

- persistent node ID
- Ed25519 public key
- DPAPI-protected private-key blob
- pinned control identity after enrollment
- pinned control public-key fingerprint

Resetting enrollment removes control trust but does not rotate the node identity.

## Artifact metadata cache

Verified artifact manifest metadata is stored under:

```text
%PROGRAMDATA%\Lattice\artifacts\index.json
```

The cache index records the immutable signed manifest, verification time and whether artifact content has passed size and SHA-256 verification.

Verified payloads are stored by content hash under:

```text
%PROGRAMDATA%\Lattice\artifacts\objects\<sha256>
```

Downloads are written to temporary `.part` files first, checked against the signed size and SHA-256, then atomically promoted. Verified content is reusable after restart without contacting the artifact endpoint.

## Runtime cache

Verified runtime manifest metadata is stored under:

```text
%PROGRAMDATA%\Lattice\runtimes\index.json
```

Verified runtime payloads are content-addressed under:

```text
%PROGRAMDATA%\Lattice\runtimes\objects\<sha256>
```

The node accepts only a runtime manifest signed by the pinned control identity that matches the exact requested runtime ID/version and the local Windows architecture. Runtime process execution remains disabled until the native runtime adapter milestone.

## Configuration

The Windows node stores its local configuration at:

```text
%PROGRAMDATA%\Lattice\node.json
```

The local configuration contains:

- trusted control server URL
- resource-sharing master switch
- CPU limit
- memory limit
- GPU limit
- allowed workload categories

## Installer

The Windows distribution uses the Tauri NSIS per-machine installer.

The installer:

1. requests administrator elevation
2. stops the previous Lattice Node service during upgrades
3. installs Lattice Desktop, lattice-node and lattice-update-helper
4. creates or updates the LatticeNode service
5. starts the service
6. removes the service before uninstalling files

## Automatic node updates

The node queries the enrolled control plane for the latest release matching its configured stable or beta channel, Windows platform and local architecture. Release metadata is signed by the pinned control identity and binds the semantic version, payload size, SHA-256 and HTTPS download URL.

Verified payloads are staged under:

```text
%PROGRAMDATA%\Lattice\updates\staging\objects\<sha256>
```

Persistent updater state is stored at:

```text
%PROGRAMDATA%\Lattice\updates\state.json
```

The dedicated update helper backs up the current executable, stops LatticeNode, performs an atomic replacement, restarts the service and requires IPC to report the expected version. A failed restart or health gate automatically restores the previous executable and verifies the rolled-back version before recording the failure.

## Build

On Windows:

```powershell
cd apps/lattice-desktop
npm ci
npm run tauri build -- --bundles nsis
```

The sidecar preparation step is executed automatically by Tauri before the frontend build.

## Next Windows milestones

1. signed release publication automation
2. XMRig workload supervisor
3. CPU resource enforcement
4. tray behavior and launch-on-login UX
5. signed installer distribution
