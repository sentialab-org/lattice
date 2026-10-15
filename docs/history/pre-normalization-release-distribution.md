# Archived pre-normalization reference

Historical source notes retained for provenance. Do not use these instructions for installation or current acceptance.

# Lattice Release Distribution

Prefer the automated installers in `scripts/` over manual steps. They
take secrets from the environment only and refuse to run with missing
artifacts or tokens.

For end-user machines, publish a release tree with
`scripts/publish-release.sh <version>` and serve it over HTTP(S). Users
then install with one line, answering interactive `y/n` setup prompts:

```bash
curl https://lattice.sentialab.org/installer/linux.sh | bash
```

```powershell
irm https://lattice.sentialab.org/installer/windows.ps1 | iex
```

Installer sources live in `web/installer/` with hosting notes. Every
downloaded file is SHA-256 verified inside the installer. Serve the host
over HTTPS in production; checksums catch corruption but do not replace
TLS against an active attacker.

| Target | Script | Notes |
|---|---|---|
| RPi / Linux bootstrapper | `scripts/install-bootstrapper-linux.sh [--apply-gateway]` | aarch64 and x86_64, systemd, optional gateway WireGuard plus nftables apply |
| Linux compute node | `scripts/install-node-linux.sh` | x86_64 and aarch64, systemd, joins bootstrap then master |
| Windows compute node | `scripts/install-node-windows.ps1` | Elevated PowerShell, Windows Service, named-pipe enrollment |
| macOS master | `scripts/install-master-macos.sh` | launchd agent, HTTPS or LAN HTTP only, never joins the overlay |

`scripts/lattice-ipc.py` drives node IPC (`enroll`, `enroll-bootstrap`,
`set-network-enabled`, `status`) for automation without the desktop app.

## Build Matrix

All release binaries are built from the same workspace revision. Linux
targets pin glibc 2.28 through `zig cc` so one artifact runs on Debian
bookworm, Ubuntu jammy and newer.

| Host | Target | Packages | Artifacts |
|---|---|---|---|
| Operator Mac | `aarch64-apple-darwin` (native) | `lattice-control --bins` | `lattice-control`, `lattice-master`, `lattice-bootstrapper` |
| Ubuntu VM, Core 01 | `x86_64-unknown-linux-gnu` | `lattice-node`, `lattice-worker`, `lattice-control --bins` | `lattice-node`, `lattice-worker`, control bins |
| Windows VM | `x86_64-pc-windows-gnu` | `lattice-node`, `lattice-worker`, `lattice-update-helper` | `lattice-node.exe`, `lattice-worker.exe`, `lattice-update-helper.exe` |
| RPi Edge 01 | `aarch64-unknown-linux-gnu` | `lattice-control --bins` | `lattice-bootstrapper` |

Verify after every build:

```bash
ls -la target/release/lattice-*
ls -la target/x86_64-unknown-linux-gnu/release/lattice-*
ls -la target/x86_64-pc-windows-gnu/release/*.exe
ls -la target/aarch64-unknown-linux-gnu/release/lattice-*
./target/release/lattice-bootstrapper --version
./target/release/lattice-master --version
```

## RPi Bootstrapper Deployment

Copy `lattice-bootstrapper` (aarch64) to the RPi and run:

```bash
LATTICE_CONTROL_DATA=/var/lib/lattice \
LATTICE_ENROLLMENT_TOKEN=<secret> \
LATTICE_OPERATOR_TOKEN=<secret> \
LATTICE_CONTROL_BIND=0.0.0.0:7443 \
LATTICE_CLUSTER_ID=lattice-nbi \
LATTICE_CONTROL_ROLE=bootstrapper \
LATTICE_NETWORK_CIDR=10.77.0.0/16 \
LATTICE_NETWORK_GATEWAY_IP=10.77.0.1 \
LATTICE_NETWORK_GATEWAY_ENDPOINT=14.241.111.182:51820 \
LATTICE_NETWORK_INTERFACE=lattice0 \
LATTICE_NETWORK_RESERVED_IPS=10.77.0.2,10.77.0.3 \
LATTICE_NETWORK_PATH_POLICY=hub \
  lattice-bootstrapper
```

Bring up the gateway interface from the operator gateway view
(`GET /api/v1/operator/network/gateway`) and apply the rendered
WireGuard config plus nftables ruleset on the RPi. Public ingress must
be exactly UDP `51820` and TCP `7443`. No other member exposes a port.

## Mac Master Deployment

```bash
LATTICE_CONTROL_DATA=./data-master \
LATTICE_ENROLLMENT_TOKEN=<secret> \
LATTICE_OPERATOR_TOKEN=<secret> \
LATTICE_CONTROL_BIND=0.0.0.0:7443 \
LATTICE_CLUSTER_ID=lattice-nbi \
LATTICE_CONTROL_ROLE=master \
LATTICE_PUBLIC_URL=http://<mac-lan-ip>:7443 \
  lattice-master
```

Allow inbound TCP `7443` from `192.168.2.0/24` in the Mac firewall for
LAN bring-up. Remote nodes reach the master over the overlay only.

## Node Join Order

On every compute node, with `LATTICE_ALLOW_INSECURE_HTTP=1` set for the
test deployment:

1. Enable network opt-in and join the bootstrapper public URL
   (`http://14.241.111.182:7443`) to receive a stable virtual IP.
2. Enroll with the master over its overlay URL once the tunnel reports
   connected.

Resetting bootstrap tears down the overlay without touching workload
enrollment. Take a VM snapshot before the first join and keep the
enrollment token out of shell history and logs.
