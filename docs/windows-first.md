# Windows-first implementation

## Process model

```text
Lattice.exe
    |
    | Named Pipe
    v
lattice-node.exe
    |
    +-- local policy
    +-- hardware telemetry
    +-- runtime manager
    +-- workload supervisor
    +-- control-plane client
```

Lattice Desktop is a control surface. The node daemon owns policy and workload lifecycle.

## Local IPC

Windows uses the named pipe:

```text
\\.\pipe\lattice-node
```

Remote named-pipe clients are rejected.

The current IPC protocol supports:

- ping
- node status
- read node configuration
- update node configuration

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

## Next Windows milestones

1. Windows Service host and installer registration
2. persistent node identity and enrollment keys
3. authenticated control-plane transport
4. job lease lifecycle
5. runtime and artifact verification
6. tray behavior and launch-on-login UX
7. signed MSI or NSIS release pipeline
