# Lattice Virtual Network — Architecture Review & Engineering Plan

**Status:** Engineering handoff / implementation specification  
**Date:** 2026-10-13 (Asia/Bangkok)  
**Target repository:** `/Users/zvwgvx/Project/lattice`  
**Inspected branch:** `runtime-integration` tracking `miangwu/runtime-integration` (locally ahead by one commit at audit time)  
**Priority:** Routed private overlay MVP, then hardening, then opportunistic P2P.  
**Owner constraint:** Extend existing Lattice. Do not create a separate product, CnC replacement, or independent network controller project.

## 0. Executive decision

Lattice already has a signed command-and-control path for enrollment, heartbeats, workload leases, releases and policy. Preserve it. Add a separate **IP data plane** so enrolled devices communicate **bidirectionally over stable virtual IP addresses**, even when their real network is behind NAT/CGNAT.

**Phase 1 / required:** hub-and-spoke WireGuard routing through NBI Core 01 (Linux gateway). The controller allocates one stable virtual IPv4 `/32` to each approved node. The node creates a WireGuard tunnel outbound to the gateway. The gateway forwards node-to-node packets at Layer 3, without translating inner packet IPs or ports. No site LAN routing, default-route hijack, or public IPv4 is part of the MVP.

**Phase 2 / required:** robust lifecycle, node opt-in, authorization/ACL, configuration revisions, independent supervisor, Windows/Linux support and recovery tests.

**Phase 3 / optional after acceptance:** direct peer-to-peer WireGuard paths when possible, automatic fallback to routed hub, without changing virtual addresses.

**Phase 4 / deferred:** public IPv4 `/32` lease and routed public gateway; no procurement or BYOIP/BGP work in this change.

**Non-negotiable:** Lattice mining/runtime, secure update, enrollment, signed heartbeat and desktop IPC remain functional and backward compatible. Network is a separately authorized feature, not implicitly enabled by enrollment or workload permission.

## 1. Findings grounded in the current repo

Audit performed on `/Users/zvwgvx/Project/lattice` with read-only commands. No source code, server firewall, running service or route was modified during this audit.

| Existing location | Observed behavior | Consequence |
|---|---|---|
| `crates/lattice-control/src/main.rs` | Axum HTTP control service; signed enrollment and heartbeat; node registry stored on disk; `/api/v1/enroll`, `/api/v1/heartbeat`; bind defaults to `127.0.0.1:7443` | Reuse identity, registry and control trust. Introduce separate network API and data state. Never assume the HTTP port is a UDP WireGuard endpoint. |
| `crates/lattice-node/src/heartbeat.rs` | Outbound signed heartbeat via Reqwest, default interval 15 seconds; verifies server receipt, applies policy/jobs | This is coordination, not a packet transport. Do not relay arbitrary packets over heartbeat. |
| `crates/lattice-node/src/lib.rs` | Independent background tasks for heartbeat, update, workload supervisor; local IPC dispatch | Add independent network supervisor task and local IPC status/control. Do not tie mesh to job leases or miner state. |
| `crates/lattice-node/src/identity.rs` | Persistent node ID and Ed25519 identity; trust pinning; Windows machine DPAPI key protection | Use existing Ed25519 only for authenticating network requests/configuration. Generate a separate WireGuard Curve25519 keypair; protect at rest. |
| `crates/lattice-protocol/src/lib.rs` | Serialized signed requests/responses, `NodeConfig`, `NodeStatus`, IPC types | Add **new** versioned network messages; avoid modifying existing signed canonical payloads in place. |
| `crates/lattice-control/src/operator.rs` | Authenticated operator endpoint pattern | Extend operator APIs for network administration with explicit privilege checks. |
| `docs/control-plane.md` | Control binds HTTP by default, expected to run behind TLS termination in production | Network management requests still require existing TLS + signature/trust checks. |
| Workspace `Cargo.toml` | Rust workspace with control, node, protocol, crypto, IPC, worker and update helper crates | Prefer adding modules in existing crates for MVP. New workspace crate is optional only if justified by real shared complexity. |

Additional observations:

- Source search in current crates/docs/config found **no existing WireGuard, Wintun, TUN, virtual IPAM or relay implementation**. Do not claim an existing mesh module is ready.
- Current registry tracks `node_id`, identity key, heartbeat sequence, online expiry, capabilities and health. Network lease/peer/key state does not yet exist.
- Current `NodePolicy` is a **workload policy**. Reusing its `enabled` or `allow_generic` as network access permission would couple unrelated functionality.
- The local checkout is `runtime-integration`, currently ahead of its tracked remote by one commit. **Do not overwrite, reset, rebase or push that commit implicitly.** Confirm worktree/branch before changing files.
- The real server's external UDP reachability, active firewall, existing VPN subnets, VM NAT mode and production deploy layout were **not verified**. Treat these as preflight gates, not assumptions.

## 2. Requirements and exclusions

### 2.1 Functional MVP

1. An enrolled, owner-authorized device can join the Lattice overlay.
2. It receives a **stable, unique overlay IPv4** bound to its immutable Lattice node ID.
3. Gateway and peers use Layer 3. Node A can reach Node B using overlay IPv4 for ICMP, TCP and UDP as allowed by access policy.
4. Two CGNAT nodes can connect using outbound UDP connections to a publicly reachable gateway.
5. Gateway does not change source/destination IP or transport ports of **inner overlay packets** (no SNAT/MASQUERADE/DNAT of overlay traffic).
6. Normal ISP default route, local LAN, existing VPNs and control HTTPS traffic remain intact.
7. Overlay survives transient packet loss, node reconnect, dynamic endpoint changes and service restart; network status is observable.
8. A failed network setup cannot disable existing Lattice CnC or workload/update services.
9. Server can disable a node, revoke access and reissue configuration; revoked node must be removed from gateway peer and route policy.
10. Windows and Linux client implementations are explicitly tested; macOS support can follow behind a capability gate without blocking Windows/Linux acceptance.

### 2.2 Non-goals for MVP

- Public IPv4 provisioning, routed `/32` from ISP, BGP or outbound full-tunnel Internet gateway.
- L2 Ethernet bridging, DHCP broadcast relay, ARP flood, mDNS broadcast transparency, subnet-router/site-to-site LAN access.
- Browser proxying, arbitrary TCP reverse tunnels or using HTTP heartbeat as a bulk data carrier.
- Writing WireGuard cryptography, a NAT traversal protocol or a kernel driver from scratch.
- Forcing all-to-all network permissions on enrolled nodes.
- Automatically installing network drivers or changing firewall/routes without local administrator consent and a rollback path.

### 2.3 Concrete addressing example (not yet reserved)

| Member | Overlay interface IPv4 | Function |
|---|---|---|
| NBI Core 01 | `10.240.0.1/32` | WireGuard gateway/router |
| Windows VM | `10.240.0.2/32` | Enrolled peer |
| Ubuntu VM | `10.240.0.3/32` | Enrolled peer |

Use `10.240.0.0/16` **only after** verifying no conflict with LAN, VM bridges, VPN and existing mesh routes. In particular, do not reuse an existing Tailscale/100.96.x.x range. Keep network prefix centrally configurable; do not hard-code the examples into code or tests.

## 3. Architecture and packet flows

### 3.1 Control plane (existing Lattice)

```text
Windows/Ubuntu LatticeNode --HTTPS--> lattice-control
          Ed25519 identity       enroll/network-register/network-sync
                                  signed desired config + revision
```

The existing CnC HTTP path continues unchanged. New network endpoints authenticate against the **same enrolled node registry** and verify Ed25519 signatures using the registered node identity. The control signs each peer's desired network snapshot using its pinned control identity.

### 3.2 Data plane (new)

```text
Node A 10.240.0.2/32
      |  UDP WireGuard, outbound through CGNAT
      v
NBI Core 01, wg-lattice, 10.240.0.1
      |  Linux L3 forwarding + per-node ACL; inner IP unmodified
      v
Node B 10.240.0.3/32
```

Data does not pass through `lattice-control`'s HTTP request handlers; the Linux kernel WireGuard interface and forwarding path transport it. The control daemon should configure **desired state** but not parse every packet. The WireGuard gateway can be deployed on the same physical main server, while remaining a separately administered privileged operating-system component.

Packet example: inner source `10.240.0.2`, inner destination `10.240.0.3`; the gateway forwards that unchanged. NAT may still exist on the *outer* UDP transport at the client's ISP; this is not inner-overlay NAT.

### 3.3 Hub-first, P2P later

The first release intentionally uses server-routed connections, not STUN/ICE. Hub routing has predictable reachability behind most UDP-permitting CGNAT deployments. Later P2P uses a separate path-selection layer; application-facing virtual IPs must remain stable through direct↔hub transitions.

### 3.4 Gateway reachability prerequisite

Main must have a reachable UDP listener (e.g. `51820/udp` on a DNS hostname or public IP). **SSH connectivity or working HTTPS CnC does not prove incoming UDP is possible.** If main is behind CGNAT without UDP ingress, the gateway role needs an explicitly approved reachable external entrypoint or hosting change. Do not silently substitute a guessed address or deploy a production VPS.

## 4. WireGuard routing model

Use a single WireGuard interface on the Linux gateway (example `wg-lattice`) and one corresponding tunnel on each node.

**Gateway peer A:** `AllowedIPs = 10.240.0.2/32`  
**Gateway peer B:** `AllowedIPs = 10.240.0.3/32`  
**Node A's gateway peer:** `AllowedIPs = 10.240.0.0/16`  
**Node B's gateway peer:** `AllowedIPs = 10.240.0.0/16`  
**Nodes:** `PersistentKeepalive = 25` when behind NAT.

A `/32` virtual address belongs to each node interface. The overlay prefix is routed to the WireGuard interface; the public Internet default route stays with its existing physical adapter. The gateway forwards traffic from WireGuard back out to WireGuard; Linux `ip_forward=1` and explicit `FORWARD` firewall rules are required. WireGuard `AllowedIPs` performs cryptokey routing and constrains which source prefixes a peer can originate, but **it is not a replacement for network authorization/ACL**.

Illustrative Linux gateway commands (not an install script):

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo wg show
ip -4 route show
sudo nft list ruleset
```

Never install a broad `MASQUERADE` over the virtual subnet. Ensure interface ordering, `rp_filter`, host firewall and intra-interface forwarding behavior are examined in the actual Linux distribution. Configure MTU with a conservative tested default, then check PMTUD for large packets; do not hardcode a universal MTU without tests.

**Isolation:** the overlay grants no automatic access to host LANs, physical NICs, management interfaces, other private prefixes or the Internet via the hub. The first firewall policy allows only approved peer-to-peer overlay traffic; default deny outside allowed destinations.

## 5. WireGuard platform integration

### 5.1 Linux gateway and Linux node

- Prefer the Linux kernel WireGuard implementation plus official `wg` tooling; it is already optimized for the OS.
- In the initial MVP, use a small privileged reconciliation adapter with a deterministic interface name and controlled subprocess arguments (no shell interpolation of untrusted input).
- Generate the gateway configuration from approved state; keep configuration and keys outside source control, with restrictive file permissions.
- Apply per-peer adjustments with a minimal-disruption mechanism (e.g. `wg syncconf` where suitable). Avoid tearing down every existing tunnel on one peer change.
- Manage routes and firewall transactionally: compute diff, validate, snapshot previous state, apply, health-check, restore previous state on failure.
- On reboot, recreate the approved tunnel before reporting `CONNECTED`. Do not toggle unrelated kernel sysctls globally if narrower alternative works; if `ip_forward` is necessary, persist and document the change with rollback.

### 5.2 Windows node

- **Windows-first client support matters** because existing Lattice includes a Windows Service and test Windows VM.
- Use the official supported WireGuard for Windows tunnel/service integration rather than a custom network driver. The documented tunnel-service pattern supports installing a named tunnel from a configuration file. Confirm installed version, deployment rights, licensing/distribution and machine policy before bundling or invoking it.
- Generate configs in a protected system directory, accessible only to SYSTEM/administrators; do not log secrets or leave unprotected temporary configs.
- WireGuard tunnel service must be independently recoverable while LatticeNode handles reconciliation and status, without conflicting with the LatticeNode Windows Service lifecycle.
- Validate adapter routes and Windows Defender Firewall for ICMP/TCP/UDP test ports. Do not touch the machine-wide Internet default route.

### 5.3 macOS (follow-up)

- Keep protocol and configuration design portable. macOS requires a distinct utun/Network Extension or WireGuard runtime integration strategy; do not assume Linux interface names or commands work on macOS.
- Since macOS is not the Windows/Linux MVP gate, explicitly report unsupported status rather than silently degrading or claiming mesh connectivity.

### 5.4 Secrets and identity

- Keep the existing Ed25519 identity for signed **control** operations.
- Generate **distinct WireGuard tunnel keypairs** per node (Curve25519 / WireGuard keys). Public keys are registered via authenticated network API; private keys never go to main.
- Protect WireGuard private keys with Windows DPAPI/OS ACL or root-only storage on Linux. Ensure logs, IPC/status and errors never expose private keys.
- Reject re-registration of the same node with a changed WireGuard key unless the request is signed, authorized and rotates peer state atomically.

## 6. Control API, signing, IPAM and state machine

**Important compatibility rule:** Existing signed heartbeat/enrollment payloads are serialized then signed. Adding fields (including seemingly optional serde defaults) into those signed structs can change canonical bytes and cause cross-version signature failures. Do **not** embed network data into existing signed claim/receipt structures during MVP. Instead create **new, versioned network messages and endpoints**. Keep existing `PROTOCOL_VERSION` behavior intact until compatibility tests prove safe migration.

Suggested API (names may be adapted to local conventions but security semantics are mandatory):

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/network/register` | Enrolled node Ed25519 signed claim | Register WG public key and local opt-in/capability |
| POST | `/api/v1/network/sync` | Enrolled node Ed25519 signed claim | Obtain signed desired network snapshot and revision |
| POST | `/api/v1/network/ack` | Enrolled node Ed25519 signed claim | Report applied revision, interface state and error code |
| GET | `/api/v1/operator/network/nodes` | Existing operator authorization | List leases, state and peers without private keys |
| POST | `/api/v1/operator/network/assign` | Operator + explicit network role | Approve/allocate overlay IP |
| POST | `/api/v1/operator/network/revoke` | Operator + explicit network role | Revoke overlay membership / gateway routes |

Proposed signed request fields: `schema_version`, `node_id`, `request_id`, `sequence`, `issued_at_ms`, `wireguard_public_key` (register only), `last_applied_revision` (sync/ack as appropriate), plus signature. Verify enrollment key binding, identity, timestamp freshness, network-channel anti-replay sequence, size limits and schema version. The gateway should not accept arbitrary IPs declared by clients.

Proposed signed response payload:

```json
{
  "schema_version": 1,
  "node_id": "node_example",
  "control_id": "control_example",
  "network_id": "lattice-main",
  "revision": 7,
  "enabled": true,
  "virtual_ipv4": "10.240.0.2/32",
  "overlay_cidr": "10.240.0.0/16",
  "gateway_ipv4": "10.240.0.1",
  "gateway_endpoint": "vpn.example.net:51820",
  "gateway_wireguard_public_key": "BASE64_KEY",
  "allowed_overlay_routes": ["10.240.0.0/16"],
  "keepalive_seconds": 25,
  "issued_at_ms": 0
}
```

The entire payload must be signed by the pinned control key. Never trust unsigned response fields outside this payload; reject changed control identity, a downgraded network revision or mismatched node ID. The example values are placeholders, not deployment configuration. Keep the private WG key out of any API response.

**IPAM semantics**

- Storage: a dedicated `network.json`/equivalent with `network_id`, prefix, pool, gateway identity, `node_id`→IPv4 allocation, WG public key, per-node desired revision, enabled flag, ACL and application status. Do not put IPAM in the jobs queue.
- Identity: allocate by stable node ID; reuse prior lease on restart; atomically prevent duplicate IPs.
- Lifecycle: `UNCONFIGURED → PENDING_APPROVAL → ALLOCATED → APPLYING → CONNECTED`, with `DEGRADED`, `DISABLED`, `REVOKED` branches. Heartbeat online != WireGuard connected; verify handshake + packet/route health separately.
- Revocation: remove the authorized peer from gateway and its ACL immediately, then propagate disable to node when reachable. Node offline or controller outage is **not** sufficient reason to reassign its stable IP.
- Concurrency: serialize pool mutations, persist atomically (fsync + rename or equivalent) and test simultaneous join/revoke operations.
- Operator control: audit every assignment, rotation and revoke action; enforce least privilege; avoid turning the current generic token into universal access silently.
- Backward compatibility: network disabled by default in node configuration; pre-existing nodes continue to enroll, heartbeat and run jobs without WireGuard.

## 7. Module-level engineering changes

| Area | Required change | Boundaries |
|---|---|---|
| `crates/lattice-protocol/src/lib.rs` | New versioned `Network*` claims, signed snapshot, ACK/status, IPC variants; safe defaults for *unsigned/local* config | Do not alter signed legacy payload layouts casually. |
| `crates/lattice-control/src/network.rs` (new) | IPAM, authenticated register/sync/ack handlers, signed desired-state creation, revocation | No data-packet forwarding in Axum process. |
| `crates/lattice-control/src/main.rs` | Add network state to app state, register new API routes, startup validation and migrations | Preserve existing enroll/heartbeat/jobs/routes. |
| `crates/lattice-control/src/operator.rs` | Operator network listing/assign/revoke; authorization/audit | Distinguish operator control from node permission. |
| `crates/lattice-node/src/network.rs` (new) | Network supervisor: reconcile desired config, backoff/retry, healthy/failed state, shutdown, local opt-in | Runs independently from mining, jobs and update. |
| `crates/lattice-node/src/network/platform_linux.rs` (new) | System WireGuard and route adapter | No shell injection, no broad route overwrite. |
| `crates/lattice-node/src/network/platform_windows.rs` (new) | Official WireGuard tunnel service adapter | Service permissions, file protection, route/firewall checks. |
| `crates/lattice-node/src/lib.rs` | Start/stop network supervisor; add IPC status/config controls | Do not block heartbeat or worker supervisor. |
| `apps/lattice-desktop` | Local opt-in toggle, assigned IP, connection/peer status, error diagnostics | Avoid exposing private keys or auto-enabling VPN. |
| `docs/` and `scripts/` | Deployment, preflight, rollback, VM smoke tests | No hard-coded real credentials or public endpoints. |

Whether to add a dedicated `lattice-network` workspace crate is an implementation judgment. **Do not create a new repository/project**. For MVP, two modules plus shared protocol structs are probably sufficient.

### 7.1 Reconciliation algorithm

1. Read local opt-in and enrolled control trust. If disabled/unenrolled, report disabled; only remove **Lattice-owned** interface/routes on explicit disable/revoke.
2. Generate/load a protected WG keypair. POST signed registration and sync request.
3. Verify server identity and signed desired-state snapshot; reject replay, revision downgrade, invalid prefix, overlapping routes, unapproved gateway endpoint or private-key leakage.
4. Compute config diff against last applied state. Persist an apply journal and previous known-good config.
5. Validate privilege/driver/tooling; create or update the named interface and route strictly for overlay prefix; apply minimal firewall changes.
6. Confirm handshake plus local route/interface health, then post signed ACK. Handshake alone is not proof node-to-node forwarding works.
7. On failed apply, restore last known-good Lattice-owned configuration; retry with bounded exponential backoff and jitter, without shutting down CnC/runtime.
8. On reboot, reconcile previous trusted state and sync latest revision when CnC returns. When controller temporarily disappears, leave healthy existing tunnel operating unless it has been locally disabled or explicitly revoked.

### 7.2 Node networking vs job policy

Define separate local `network.enabled` opt-in and separate server-side `network.authorized`. A node is connected only when **both** are true. Workload `enabled`, mining permission, GPU/CPU allocation and job state must not toggle mesh connectivity. Re-enrollment reset should clear control trust and revoke/reset network trust in a documented, safe way.

## 8. Testing matrix and gates

Use the existing Windows and Ubuntu VMs; take snapshots before touching adapters/routes. Tests should include **two independent clients behind separate NATs** to validate the CGNAT use case, plus the Linux gateway. If both VMs share one bridge/NAT, add a second isolated network path or a remote test node; same-LAN success does not prove CGNAT readiness.

| Gate | Checks | Passing condition |
|---|---|---|
| G0 — Preflight | Identify correct repo/branch, gateway host interface, reachable UDP ingress, conflicts with `10.240.0.0/16`, existing WireGuard/Tailscale, OS capabilities | Written evidence, no production network changes |
| G1 — Protocol/IPAM | Duplicate allocation, restart persistence, replay, signed config binding, mismatched node, revoked peer, concurrent requests | Unit/integration tests pass |
| G2 — Linux hub | 1 Linux node handshakes gateway; ICMP/TCP/UDP to gateway overlay IP; original LAN and default Internet work | Repeatable reboot/reconnect, no overlay NAT |
| G3 — Two nodes | Windows↔Ubuntu ping, SSH or test TCP listener and UDP exchange by overlay IP | Bidirectional while nodes may be behind NAT |
| G4 — Security | Node cannot spoof another /32; peer outside ACL blocked; disabled node loses access; malformed/signed stale config rejected | Negative tests pass |
| G5 — Reliability | Restart control only, restart node service, restart WireGuard, gateway restart, WAN IP change, tunnel UDP interruption, MTU check | Expected recovery and consistent status; no lost CnC |
| G6 — Regression | `cargo fmt --check`, `cargo test --workspace`, Rust clippy if available, Windows compile/CI, legacy enrollment/heartbeat/job/update tests | No regression in existing Lattice functionality |
| G7 — Staged rollout | One test node, then two VMs, then opt-in selected physical node | Manual rollback proven before expansion |

Minimal smoke actions after the platform adapter is configured:

```bash
ping 10.240.0.1
ping 10.240.0.3
ip route get 10.240.0.3
wg show
```

Windows examples:

```powershell
ping 10.240.0.1
ping 10.240.0.3
Get-NetRoute -AddressFamily IPv4
Get-NetAdapter
```

Diagnostics should distinguish `NOT_ENROLLED`, `NOT_AUTHORIZED`, `NOT_INSTALLED`, `ENDPOINT_UNREACHABLE`, `HANDSHAKE_STALE`, `ROUTE_CONFLICT`, `ACL_DENIED`, `APPLY_FAILED`, `CONNECTED` rather than reducing everything to online/offline. No invented performance SLA; record measured RTT and throughput via `ping`/`iperf3` using actual test topology.

## 9. Risk register and mitigations

| Risk | Mitigation |
|---|---|
| Main does not have reachable UDP port | Verify external UDP before implementing hub; deploy a minimal approved ingress only if needed. Do not assume HTTPS implies UDP. |
| Competing routes from Tailscale/other VPN | Prefix conflict detection; fail closed and show error; never replace system default route. |
| Server as single point of failure | Accept for MVP; peer tunnels keep running if only control process goes down; document eventual relay/HA. |
| CnC upgrade changes signed JSON | New signed network API and schema; preserve old signed structures and verify cross-version tests. |
| Privileged system command compromise | Narrow adapter, validated arguments, no arbitrary shell, signed desired config, dedicated OS ACLs. |
| Peer can access main's management LAN | Explicit firewall boundary: overlay-only allowlist, no unrestricted `wg0 → eth0` routing. |
| Spoofed virtual addresses | Unique WG peer AllowedIPs `/32`, ACL, no client-selected IPs, anti-replay. |
| Network change disconnects operator | Canary VM, snapshot, staged apply, auto-rollback, out-of-band management preserved. |
| Inconsistent revoke vs config | Gateway revoke applies immediately; controller reconciles nodes later; stable IP quarantine. |
| Windows adapter/service behavior varies | Use official documented integration, pin tested versions and test in actual Windows VM. |

## 10. Delivery sequence / small PRs

**PR 0 — Audit & design freeze (no runtime changes)**  
Document exact UDP reachability, planned address pool, production deployment, OS versions, driver availability, old/new signed serialization behavior. Take snapshots. Confirm branch and retain any local unpushed commit. **Do not proceed to network changes if gateway ingress is unresolved.**

**PR 1 — Protocol and IPAM (no network adapter)**  
Add new signed network API models; controller IPAM persistence; node registration/sync/ack; auth, audit, stable `/32`; unit tests for replay/conflict/migration/authorization. Legacy CnC tests green.

**PR 2 — Gateway routing (Linux, one peer)**  
Implement privileged gateway reconciler and narrowly scoped nftables rules; `wg-lattice` and route validation. One Linux test node connects via UDP. Packet capture confirms forwarding path and no inner NAT.

**PR 3 — Linux node supervisor + recovery**  
Local opt-in, key storage, independent supervisor, apply journal/rollback, limited overlay routes, IPC diagnostics; verify daemon/control restarts.

**PR 4 — Windows adapter + two-node smoke**  
Official WireGuard tunnel service integration, Windows route/firewall validation, VM test Windows↔Ubuntu. Installer strategy documented and tested.

**PR 5 — UI, observability, policy hardening**  
Show virtual address, handshake age, peer mode, bytes, error codes; enforce signed config revisions/ACL, revoke and operator audit; add automated integration tests and rollout docs.

**PR 6 — Optional P2P spike, not required for MVP**  
Evaluate endpoint discovery/STUN/hole punching and direct peer WG under actual multi-CGNAT cases; decide on proven library/reuse. Keep hub fallback and stable virtual IPs. No premature NAT traversal implementation in PRs 1–5.

### Definition of done for the requested change

- NBI Core 01 routes private packets between at least two enrolled devices via unique IPv4 addresses.
- Two peers communicate bidirectionally via overlay TCP, UDP and permitted ICMP; overlay source IP is preserved.
- No requirement to buy public IPv4 for individual devices; no port forward is required at client sites.
- Existing job/heartbeat/update/miner flows remain operational when network is disabled, healthy, or failed.
- Owner opt-in, operator authorization, ACL, signed desired config, independent health status and rollback are demonstrable.
- The engineer provides before/after test output, file list, risks, deployment/rollback instructions and commits **only with explicit instruction**. Do not force-push or modify unrelated branches.

## 11. Implementation notes for Antigravity

1. Start with **repo inspection**, not immediate code changes. Review this document against live code and report any divergence before editing.
2. Reuse **existing node ID, enrollment registry, Ed25519 trust and operator authentication**; never invent new credentials or replace CnC.
3. Keep existing signed heartbeat/enrollment types unchanged until compatibility is rigorously verified. A separate network protocol is preferred.
4. Do not write a custom VPN or reinvent WireGuard. Use the OS-supported implementation on Linux/Windows.
5. For the first working demonstration, implement **hub-and-spoke L3 route**, NOT full P2P. Even without P2P, peers talk to each other at virtual IPs.
6. Do not install/enable firewall, IP forwarding, network interface, drivers or public endpoints on production server until G0 is satisfied and rollback is ready.
7. Avoid hardcoding machine names, IPs, credentials, interface paths or external DNS. Validate them against actual deployment.
8. Follow repository conventions; do not add source-code comments unless explicitly asked by the owner. Maintain small, testable changes.
9. After every PR, run relevant tests and summarize: touched files, architecture decisions, test commands/results, remaining blockers, actual network changes, rollback path.
10. Do not combine this with miner service refactoring, gaming mode, update protocol redesign or a new standalone product.

## 12. References (design validation)

- WireGuard official quick start and keepalive: https://www.wireguard.com/quickstart/
- WireGuard Windows tunnel service enterprise documentation: https://github.com/WireGuard/wireguard-windows/blob/master/docs/enterprise.md
- Official WireGuard Go platform guidance: https://github.com/WireGuard/wireguard-go
- Internal repository: `README.md`, `docs/control-plane.md`, `docs/protocol-v1.md`, `crates/lattice-control/src/main.rs`, `crates/lattice-node/src/heartbeat.rs`, `crates/lattice-node/src/lib.rs`, `crates/lattice-node/src/identity.rs`, `crates/lattice-protocol/src/lib.rs`.

**Final scope:** Expand *existing* Lattice CnC into a separate, managed private network data plane. **First make server-routed virtual IP traffic reliable; only then add P2P and optional public IP assignment.**
