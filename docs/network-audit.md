# Lattice Network Audit and Observability

Date: 2026-10-14
Scope: overlay WireGuard hub, peer discovery, NAT traversal scaffolding,
relay rotation, bootstrapper and master role split.
Method: read-only source review, unit tests, local preflight script.
No production firewall, route, interface, or service was modified.

## Architecture Summary

The control plane authenticates enrolled Ed25519 identities and serves
signed network coordination. The data plane uses OS WireGuard interfaces
with cryptokey routing. Hub routing through the gateway is the default.
Direct `/32` peers are rendered only when path policy is `direct`.
Peer discovery is signed over receipt, peers, relays, and path policy.
Endpoint candidates are self-reported, sanitized, and distributed for
UDP hole punching. Relay entries rotate as alternative gateway endpoints.

## Strengths Verified in Code

- Peer discovery signature covers the full peer list, relays, and path
  policy. Nodes verify the full payload with receipt-only fallback.
- Per-node monotonic sequences on register, sync, ack, peers, and
  candidates reject replays. Revision downgrades are rejected.
- IPAM skips gateway, broadcast, `.0`, `.255`, assigned addresses, and
  configured reserved addresses. NBI `.2` and `.3` reservations are tested.
- Revocation disables the allocation, bumps revision, and excludes the
  peer from gateway config and future peer lists.
- WireGuard keys are separate Curve25519 keys. Windows uses DPAPI,
  Unix uses 0600 file permissions. Private keys never leave the host.
- Role-gated routers separate bootstrapper network routes from master
  workload routes. Combined control preserves backward compatibility.
- Direct peers use most-specific `/32` routes beside the overlay route,
  preserving hub fallback by longest-prefix match.
- Telemetry parses `wg show dump` for latest handshake and byte counters.
  Stale handshakes without traffic raise `HANDSHAKE_STALE`.
- Error taxonomy distinguishes `NOT_ENROLLED`, `NOT_AUTHORIZED`,
  `NOT_INSTALLED`, `ENDPOINT_UNREACHABLE`, `HANDSHAKE_STALE`,
  `ROUTE_CONFLICT`, `ACL_DENIED`, `APPLY_FAILED`, and `CONNECTED`.

## Open Risks Before Live Testing

1. Gateway UDP ingress is unverified. HTTPS success does not prove UDP.
   Run `scripts/network-preflight.sh` on the gateway and both VMs.
2. Endpoint candidates are self-reported. A malicious peer could advertise
   a spoofed endpoint. Impact is limited to failed handshakes and hub
   fallback, but direct peer authentication still relies on WireGuard
   keys, not endpoint ownership proofs.
3. Relays are configured via environment without per-relay key pinning.
   Treat relays as untrusted transport until relay keys are verified.
4. Network and workload authority are separated by server URL and pinned
   trust (bootstrap trust versus control trust), but each server still
   signs with a single Ed25519 key and there is no authority epoch or
   fencing yet. Master standby failover stays manual.
5. The Pi shares bootstrapper and master state in one data directory.
   Concurrent separate processes on the same directory are unsupported.
   Run combined mode on shared hosts.
6. Web consoles do not yet render peer, handshake, or relay diagnostics.
   Desktop and operator APIs are the source of truth for now.

## Observability Reference

Node `NetworkStatusSummary` via local IPC and desktop:

| Field | Meaning |
|---|---|
| `enabled`, `status` | Opt-in and lifecycle state |
| `virtual_ipv4` | Stable `/32` lease |
| `assigned_revision`, `applied_revision` | Desired versus applied config |
| `last_handshake_ms` | Most recent WireGuard handshake, milliseconds |
| `bytes_rx`, `bytes_tx` | Summed WireGuard transfer counters |
| `peer_count`, `path_policy` | Cached discovery size and active policy |
| `error_code` | Machine readable class, see taxonomy |
| `interface_name`, `gateway_endpoint` | Applied OS interface and gateway |
| `last_error` | Human readable detail |

Operator APIs:

| Endpoint | Diagnostics |
|---|---|
| `GET /api/v1/operator/network/nodes` | Leases with revisions, status, errors, endpoint candidates |
| `GET /api/v1/operator/network/gateway` | Interface, CIDR, path policy, relays, rendered WireGuard and nftables |
| `/health` | Control role, network ID, fingerprint, policy revision |

Preflight:

```bash
sh scripts/network-preflight.sh 10.77.0.1:51820
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\network-preflight.ps1 -GatewayEndpoint 10.77.0.1:51820
```

## Live Test Record (RPi Field Gateway)

The RPi runs combined control plus the gateway interface. Control-plane
calls from member nodes travel over the public NAT address, which proves
public ingress for TCP 7443. WireGuard data uses the LAN gateway address
for LAN members because the site router does not hairpin UDP back inside:
packet capture on the gateway showed zero arrivals from a LAN node
dialing the public endpoint. Per-node endpoint selection (direct LAN
versus public) is the P2P-phase answer; a single global endpoint cannot
serve both paths optimally.

Temporary hub because the RPi field gateway is not deployed yet: the
bootstrapper API runs on the operator Mac while the gateway WireGuard
interface runs on the Ubuntu VM. Same-host gateway and node placement is
a test artifact, not the production topology.

Proven live:

- Ubuntu `10.77.0.4` full node-driven join: register, assign with
  reserved `.2`/`.3` skipped, signed sync, interface apply, ack, status
  connected, real WireGuard handshake, encrypted ping to `10.77.0.1`.
- Windows `10.77.0.5` tunnel service install by node code, adapter up,
  routes correct, handshake plus bidirectional keepalives.
- Windows to Ubuntu through the hub with TTL 63, proving L3 forwarding
  across physical hosts.
- Dual-trust enrollment on both nodes, master registry and heartbeat live.

Bugs found only by live testing and fixed:

- Ubuntu AppArmor confines `wg` to `/etc/wireguard/`. Node configs moved
  there from `/run/lattice`.
- `wg setconf` rejects `Address` lines. Node strips `wg-quick`-only
  directives before calling setconf.
- Windows apply reinstalled the tunnel every reconcile cycle. Apply now
  skips when config matches and the service exists, with bounded retries.
- Gateway configs now render `PersistentKeepalive` per peer.

Open anomaly under investigation:

- Ubuntu-initiated ping to Windows initially showed gateway counters
  emitting replies that Windows never surfaced, while Windows-initiated
  ping through the same hub succeeded. Two stacked causes were isolated:
  the node reinstalled the Windows tunnel every reconcile cycle, and
  Windows Defender Firewall blocked inbound overlay traffic on the
  WireGuard interface. After the idempotent apply fix, a least-privilege
  inbound exception scoped to the overlay CIDR, and a stable tunnel, both
  directions pass: Windows to gateway and Ubuntu 3/3, Ubuntu to Windows
  3/3 with TTL 128 proving Windows-stack delivery. Same-host gateway and
  node routing needed explicit `/32` and policy-table care during the
  investigation; the field gateway on its own host removes that class of
  artifact entirely.

| Gate | Evidence |
|---|---|
| G0 Preflight | Preflight script on gateway and both VMs, subnet conflict review, snapshots |
| G1 Protocol and IPAM | `cargo test --workspace` including IPAM, reserved, peers signing, replay, revocation |
| G2 Linux hub | One Linux node handshakes gateway, ICMP and TCP to gateway overlay IP, LAN intact |
| G3 Two nodes | Windows and Ubuntu exchange ICMP, TCP, and UDP by overlay IP |
| G4 Security | Spoofed `/32` rejected, revoked peer removed, stale and tampered configs rejected |
| G5 Reliability | Control, node, WireGuard, and gateway restarts, WAN change, MTU check |
| G6 Regression | `cargo test --workspace`, `cargo fmt --check`, Windows CI, legacy enroll and job tests |
| G7 Rollout | One node, then two VMs, then opt-in physical nodes with proven rollback |

Rollback is local and reversible. Disable network opt-in to tear down only
the Lattice-owned interface, or revoke the lease on the control plane and
let the node converge to disabled on next sync. Existing jobs, heartbeat,
and update state are preserved.

## Steady-State Optimization
Measured per reconcile cycle before the fast path: signed register,
sync, candidates, apply with four subprocesses, ack, peer fetch with two
signature verifications, plus three file writes, every 15 seconds with no
change. After the fast path, a healthy cycle is register, sync, one
telemetry subprocess, and a conditional peer fetch. Interface apply,
config writes, and ack fire only when the desired revision, the rendered
config, or interface health actually changes.

Durability: node journal, peer cache, WireGuard keys, and identity, plus
control network, registry, job, artifact, and runtime stores, persist
with tmp-file, fsync, and atomic rename. Windows file ACLs
(SYSTEM and Administrators only) moved into the shared control helper so
the job queue keeps its at-rest boundary after the refactor.

MTU: WireGuard interface defaults to 1420. A 1500-byte DF ping through
the live tunnel passes via outer fragmentation with no blackhole, so no
MTU tuning is required on this path. Outer overhead per packet is 80
bytes (20 IP, 8 UDP, 32 WireGuard, plus inner headers).

Deadlock post-mortem: the first steady-state fast path guarded updates
with a write lock that was only dropped inside one branch of a
conditional. On later cycles the guard survived across HTTP and file
awaits, then the same task requested the non-reentrant lock again and
wedged every status reader permanently while heartbeats and ping kept
working. Fixed by scoping every guard so it drops before any await, and
hardened IPC status reads to fail fast instead of hanging. Lesson:
never conditionally drop an async lock guard; always use a block scope.

Scaling notes: registry rewrite per heartbeat and full peer fetch per
cycle are linear and fine into the hundreds of nodes. The peer fetch and
the sync interval are the documented knobs when the fleet grows past
that. HTTP control traffic stays kilobyte-scale per cycle.

## Gate Checklist
