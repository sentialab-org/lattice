# Lattice Network Convergence Plan

## Decision

Keep the hub-and-spoke WireGuard MVP as Phase 1. Converge toward the
distributed P2P `bootstrapper/master/node` architecture without breaking
existing enrollment, heartbeat, job, artifact, runtime, and update flows.

`lattice-control` is the legacy combined server. New deployments use
`lattice-bootstrapper` for network coordination and `lattice-master` for
workload orchestration. All three binaries share the `lattice_control`
library, protocol, crypto, IPAM, and runtime modules. The `/health`
endpoint reports `control_role` and `network_id` for operator inventory.

## Compatibility Mapping

| Concern | Phase 1 Hub | P2P Target | Convergence Mechanism |
|---|---|---|---|
| Overlay CIDR | `10.240.0.0/16` default | `10.77.0.0/16` | `LATTICE_NETWORK_CIDR` env, centrally configured |
| Gateway address | `10.240.0.1` | `10.77.0.1` Edge 01 | `LATTICE_NETWORK_GATEWAY_IP` env |
| Gateway endpoint | `127.0.0.1:51820` dev default | Public UDP endpoint | `LATTICE_NETWORK_GATEWAY_ENDPOINT` env |
| Interface name | `wg-lattice` default | `lattice0` | `LATTICE_NETWORK_INTERFACE` env, node and control share default |
| Network identity | `LATTICE_NETWORK_ID=lattice-main` | `LATTICE_CLUSTER_ID` | Both env names accepted, `network_id` field carries cluster ID |
| Reserved nodes | Dynamic from `.2` | `.1 Edge`, `.2 Core01`, `.3 Core02` | `LATTICE_NETWORK_RESERVED_IPS=10.77.0.2,10.77.0.3` skipped by IPAM |
| Keepalive | 25s | 25s | `LATTICE_NETWORK_KEEPALIVE_SECS` |
| Path policy | `hub` | `hub`, `direct`, later `relay` | `LATTICE_NETWORK_PATH_POLICY` env, distributed via peers response |
| Relays | Empty | Public relay list | `LATTICE_NETWORK_RELAYS=id=host:port,...` |
| Advertised endpoint | Empty | NAT traversal candidates | `LATTICE_NETWORK_ADVERTISED_ENDPOINT=host:port,...` |
| Roles | Combined control | Bootstrapper network only, master command authority | `LATTICE_CONTROL_ROLE` plus dedicated binaries |

## NBI Deployment Map

All sites currently share `192.168.2.0/24`, so the first overlay milestone
runs on one LAN before any cross-network P2P test.

| Physical host | SSH | Role | Binary | Overlay IPv4 |
|---|---|---|---|---|
| RPi 4, 4 GiB (LAN `192.168.2.252:15564`, public `14.241.111.182:15564`) | port 15564, user `zvwgvx` | Bootstrapper, future | `lattice-bootstrapper` (aarch64 Linux) | `10.77.0.1/32`, gateway and hub |
| Operator Mac | local | Master | `lattice-master` (macOS, HTTPS only) | No overlay interface, orchestrates via control API |
| Compute box (LAN `192.168.2.254:15565`, public `14.241.111.182:15565`) | port 15565, user `zvwgvx` | Compute node | `lattice-node` | Dynamic from `10.77.0.4/32` |
| Ubuntu VM (`192.168.2.240`) | via MCP or RPi jump host | Compute node | `lattice-node` (x86_64 Linux) | Dynamic from `10.77.0.4/32` |
| Windows VM (`192.168.2.241`) | via MCP | Compute node | `lattice-node` (x86_64 Windows) | Dynamic from `10.77.0.4/32` |

The master on macOS does not join the overlay. WireGuard setup is
explicitly unsupported on macOS in the node supervisor, so the master
orchestrates over HTTPS while every Linux and Windows host holds a stable
virtual IP. The RPi doubles as WireGuard hub gateway for Phase 1.

Set on the bootstrapper host:

```bash
LATTICE_CLUSTER_ID=lattice-nbi
LATTICE_CONTROL_ROLE=bootstrapper
LATTICE_NETWORK_CIDR=10.77.0.0/16
LATTICE_NETWORK_GATEWAY_IP=10.77.0.1
LATTICE_NETWORK_GATEWAY_ENDPOINT=14.241.111.182:51820
LATTICE_NETWORK_INTERFACE=lattice0
LATTICE_NETWORK_RESERVED_IPS=10.77.0.2,10.77.0.3
LATTICE_NETWORK_PATH_POLICY=hub
LATTICE_NETWORK_RELAYS=
```

Set on the master host (Mac):

```bash
LATTICE_CLUSTER_ID=lattice-nbi
LATTICE_CONTROL_ROLE=master
LATTICE_PUBLIC_URL=http://<mac-lan-ip>:7443
```

Nodes enroll against the master URL and join the overlay through the
bootstrapper gateway. Public ingress lives only on the RPi field
(`14.241.111.182`): UDP `51820` for WireGuard and TCP `7443` for the
bootstrapper API. No port is forwarded to any other member. Remote nodes
use the public gateway endpoint from first join, so hairpin and CGNAT
paths are exercised immediately instead of LAN shortcuts.

## Split Join Order

The node keeps two separate trusts: a bootstrap trust for network
coordination and a control trust for workload authority.

1. Join the bootstrapper first over its public URL. The node stores a
   bootstrap trust and receives a stable virtual IP.
2. Enroll with the master over its overlay URL once the tunnel is up.
   Workload heartbeat, policy, jobs, and status flow over the overlay,
   so the master needs no public port.
3. The network supervisor prefers the bootstrap trust and falls back to
   the combined control trust on legacy single-server deployments.

Desktop exposes both steps: the network panel joins and resets the
bootstrapper, the identity panel enrolls and resets workload control.
Resetting bootstrap tears down the overlay interface and clears peer
state without touching workload enrollment.

Plain HTTP to public or overlay addresses is rejected unless
`LATTICE_ALLOW_INSECURE_HTTP=1` is set explicitly. The flag exists only
for test deployments before TLS termination. Production must terminate
TLS in front of the bootstrapper API.

Allocate:

- `10.77.0.1/32` RPi gateway and bootstrapper identity
- `10.77.0.2/32` reserved for Core 01 GPU compute
- `10.77.0.3/32` reserved for Core 02 CPU compute
- `10.77.0.4/32` and above dynamic allocation for the VMs and `.254`

Verify no conflict with LAN, VM bridges, VPN, or existing Tailscale ranges
before applying. The default remains `10.240.0.0/16` with `wg-lattice`
until the operator explicitly switches the deployment.

Build notes:

- `lattice-bootstrapper` and `lattice-master` compile clean for
  `aarch64-unknown-linux-gnu` for the RPi.
- `lattice-node` compiles clean for `x86_64-pc-windows-gnu`.
- `lattice-node` on macOS configures the overlay with `wg-quick`
  (requires `brew install wireguard-tools` plus `wireguard-go`).
  The interface config is stored beside the node config directory and
  removed with `wg-quick down` on disable or reset.
- `lattice-node` for `aarch64-unknown-linux-gnu` additionally requires an
  `aarch64-linux-gnu-gcc` cross toolchain for the `ring` dependency. It is
  only needed if an ARM host also runs compute.

## Network API

All node requests use enrolled Ed25519 identity, fresh timestamps within
120 seconds, and monotonic per-node sequences. Peer discovery responses
are signed over receipt, peers, relays, and path policy together. Nodes
accept the new full-payload signature and fall back to receipt-only
verification during upgrades. Existing signed heartbeat and enrollment
payloads are unchanged.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/v1/network/register` | Register WireGuard public key and opt-in |
| POST | `/api/v1/network/sync` | Obtain signed desired config and revision |
| POST | `/api/v1/network/ack` | Report applied revision and interface state |
| POST | `/api/v1/network/peers` | Signed peer discovery with relays and path policy |
| POST | `/api/v1/network/candidates` | Publish NAT traversal endpoint candidates |
| GET | `/api/v1/operator/network/nodes` | List leases without private keys |
| POST | `/api/v1/operator/network/assign` | Approve and allocate stable `/32` |
| POST | `/api/v1/operator/network/revoke` | Revoke membership and routes |
| GET | `/api/v1/operator/network/gateway` | Gateway config, nftables, relays, path policy |

Peer discovery returns only enabled nodes with a virtual IP and WireGuard
key, excluding the requester and revoked or disabled allocations. Each
peer carries sanitized endpoint candidates for direct dialing. Relay
entries carry `relay_id` and `endpoint`.

## NAT Traversal and Path Selection

Policy order is `DIRECT -> HUB -> PUBLIC_RELAY`. The hub via the gateway
is always configured. Direct peers are added as most-specific `/32`
WireGuard peers alongside the overlay route, so direct traffic wins by
longest-prefix match while hub remains the fallback.

1. Node publishes candidates from `LATTICE_NETWORK_ADVERTISED_ENDPOINT`
   through `/api/v1/network/candidates`.
2. Control stores sanitized candidates per allocation and distributes them
   in `/api/v1/network/peers`.
3. Node sends UDP hole-punch packets to peer candidates before applying
   WireGuard configuration.
4. When `path_policy` is `direct`, the node renders gateway plus direct
   peers. When `hub`, it renders gateway only.
5. Handshake freshness is evaluated with a 180 second window. Stale
   handshakes fall back to hub, then rotate through configured relays with
   `select_gateway_endpoint`.

Hole punching is a NAT mapping aid for WireGuard and does not replace
WireGuard encryption, AllowedIPs cryptokey routing, or ACL enforcement.

## Node Supervisor

The node runs an independent network task alongside heartbeat, update, and
workload supervision:

1. Read local `network.enabled` opt-in and enrolled control trust.
2. Load or create a protected WireGuard keypair.
3. POST signed register, sync, report candidates, apply interface, and POST
   signed ack.
4. Fetch signed peers and refresh `network_peers.json` with peer count and
   path policy for local IPC and desktop status.
5. Retry with bounded exponential backoff and jitter. A failed network setup
   never stops heartbeat, workload, or update tasks.

Interface handling:

- Linux uses `ip` and `wg` with `address replace`, `link set up`, and
  `route replace` scoped to the overlay CIDR.
- Windows uses the official `wireguard.exe /installtunnelservice` pattern.
- Teardown removes only the Lattice-owned interface on explicit disable.

## Roles and Lifecycle

- `lattice-control`: legacy combined server, mounts all routes.
- `lattice-bootstrapper`: mounts enrollment, heartbeat presence, network
  register, sync, ack, peers, candidates, and operator network routes.
- `lattice-master`: mounts enrollment, heartbeat with scheduling, content,
  releases, jobs, and operator workload routes.
- `lattice-node`: compute worker, single executor per host.

Network lifecycle is independent from compute:

`UNCONFIGURED -> PENDING_APPROVAL -> ALLOCATED -> APPLYING -> CONNECTED`
with `DEGRADED`, `DISABLED`, and `REVOKED` branches. Heartbeat online does
not imply WireGuard connected. Workloads persist across transient control
disconnects according to lease expiry and effective policy.

## Security

- Ed25519 identity authenticates every network request. WireGuard keys are
  separate Curve25519 keys, DPAPI protected on Windows and file permission
  protected on Unix.
- The gateway forwards overlay traffic without inner NAT and enforces an
  isolated nftables forward policy for the overlay CIDR only.
- Revocation removes the peer from gateway state immediately and propagates
  disable to the node on next sync.
- Private keys never appear in API responses, logs, IPC status, or UI.

## Implementation Sequence

1. Configurable CIDR, gateway, interface, cluster ID, and reserved IPs.
   Hub behavior unchanged when env is unset.
2. Operator gateway view renders the configured interface and endpoint port.
3. Node supervisor honors the configured interface on Linux and Windows.
4. Signed peer discovery with relays and path policy, plus local peer cache.
5. Control role reporting for bootstrapper and master inventory.
6. Endpoint candidates, UDP hole punching, direct peer rendering, handshake
   freshness, and relay rotation.
7. Shared `lattice_control` library with role-gated routers and dedicated
   `lattice-bootstrapper` and `lattice-master` binaries.
8. Direct path hardening, relay fallback automation, and executable split
   follow after routed hub acceptance with stable virtual IPs.

## Environment Reference

| Variable | Default | Purpose |
|---|---|---|
| `LATTICE_CLUSTER_ID` | `lattice-main` | Cluster and network identity, alias `LATTICE_NETWORK_ID` |
| `LATTICE_CONTROL_ROLE` | `combined` | `combined`, `bootstrapper`, or `master` |
| `LATTICE_NETWORK_CIDR` | `10.240.0.0/16` | Overlay prefix |
| `LATTICE_NETWORK_GATEWAY_IP` | `10.240.0.1` | Gateway overlay address |
| `LATTICE_NETWORK_GATEWAY_ENDPOINT` | `127.0.0.1:51820` | Gateway WireGuard UDP endpoint |
| `LATTICE_NETWORK_INTERFACE` | `wg-lattice` | OS interface name, use `lattice0` for NBI |
| `LATTICE_NETWORK_RESERVED_IPS` | empty | Comma separated IPs skipped by IPAM |
| `LATTICE_NETWORK_RELAYS` | empty | `id=host:port` or `host:port` entries |
| `LATTICE_NETWORK_PATH_POLICY` | `hub` | `hub` today, `direct` upgrade path |
| `LATTICE_NETWORK_ADVERTISED_ENDPOINT` | empty | Local NAT traversal candidates |
| `LATTICE_WG_QUICK` | `wg-quick` | WireGuard setup tool override on macOS |
| `LATTICE_ALLOW_INSECURE_HTTP` | unset | Set `1` to permit plain HTTP outside localhost for test deployments |
| `LATTICE_NETWORK_KEEPALIVE_SECS` | `25` | WireGuard persistent keepalive |
| `LATTICE_NETWORK_INTERVAL_SECS` | `15` | Node reconcile interval |
