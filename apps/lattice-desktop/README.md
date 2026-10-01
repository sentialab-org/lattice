# Lattice Desktop

Lattice Desktop is the local node control application.

The UI is React inside Tauri. It does not execute workloads directly. It communicates with the independently running lattice-node daemon.

## Windows transport

The desktop app connects to:

```text
\\.\pipe\lattice-node
```

The node rejects remote named-pipe clients.

## Unix development transport

Linux and macOS currently use:

```text
/tmp/lattice-node.sock
```

Override with `LATTICE_SOCKET`.

## Development

Terminal 1:

```bash
cargo run -p lattice-node
```

Terminal 2:

```bash
cd apps/lattice-desktop
npm install
npm run tauri dev
```
