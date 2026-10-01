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
3. installs Lattice Desktop and the lattice-node sidecar
4. creates or updates the LatticeNode service
5. starts the service
6. removes the service before uninstalling files

## Build

On Windows:

```powershell
cd apps/lattice-desktop
npm ci
npm run tauri build -- --bundles nsis
```

The sidecar preparation step is executed automatically by Tauri before the frontend build.

## Next Windows milestones

1. persistent node identity and enrollment keys
2. authenticated control-plane transport
3. job lease lifecycle
4. runtime and artifact verification
5. tray behavior and launch-on-login UX
6. signed installer and updater pipeline
