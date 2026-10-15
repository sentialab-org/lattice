# Lattice Virtual Network — Antigravity Handoff

Date: 2026-10-13
Repository: /Users/zvwgvx/Project/lattice
Inspected branch: runtime-integration, tracking miangwu/runtime-integration (ahead by one local commit at audit time)

## Scope
Extend the existing Lattice Rust CnC project with a private Layer 3 overlay. Keep enrollment, signed heartbeat, workloads, miner, secure updates and IPC working. Do not create a second project. The owner will provide the full report named LATTICE_NETWORK_ENGINEERING_PLAN.md as the canonical engineering specification.

## Verified audit
- crates/lattice-control/src/main.rs is the Axum control service; existing /api/v1/enroll and /api/v1/heartbeat use the persistent enrolled-node registry.
- crates/lattice-node/src/heartbeat.rs sends signed outbound heartbeats approximately every 15 seconds by default.
- crates/lattice-node/src/lib.rs already has independent async heartbeat/update/workload tasks; add an independent network supervisor.
- crates/lattice-node/src/identity.rs stores persistent node Ed25519 identity and pinned control trust. Create a separate WireGuard keypair, not reuse Ed25519 private bytes as tunnel key.
- crates/lattice-protocol/src/lib.rs defines signed serialization and IPC types. Avoid changing legacy signed claim/receipt layouts, which may break signatures across versions.
- No existing WireGuard/TUN/Wintun/overlay/IPAM implementation was found in the inspected source.

## Engineering order
1. Preflight gateway UDP reachability and subnet conflicts; confirm Linux server network/firewall, Windows and Ubuntu VM topology; snapshot VMs. No production changes before rollback is ready.
2. Add dedicated versioned network protocol with signed register/sync/ack endpoints, stable IPAM (/32 per node ID), explicit owner opt-in and operator approval. Keep current signed heartbeat unchanged.
3. Build Linux WireGuard gateway on NBI Core 01 (example wg-lattice), forwarding approved overlay node-to-node packets without inner NAT. Avoid system default-route changes, LAN access, or unrestricted forwarding.
4. Add independent node network supervisor, protected WireGuard keys, desired-state reconciliation, revisions, error reporting and rollback. Implement Linux adapter first.
5. Integrate official WireGuard tunnel service on Windows; demonstrate Windows VM ↔ Ubuntu VM using unique virtual IP addresses, including TCP/UDP and ICMP as firewalls permit.
6. Add ACL, revocation, health/IPC/UI, restarts and regression tests. Only after routed MVP is complete, plan direct P2P NAT traversal with hub fallback. Public IPv4 allocation is deferred.

## Acceptance requirements
The two clients can address one another by stable overlay IPs despite client-side NAT; the main acts as Layer 3 router, preserving inner packet source/destination; CnC, miner and auto-update continue functioning regardless of overlay status; network is disabled by default and cannot access local LANs by default; operator can revoke a peer; no private keys leak; routing changes are reversible; no regressions in Rust/Windows CI.

## Required delivery behavior
Inspect code before editing; respect local unpushed commit; make small PR-sized patches, run tests after each, provide changed files, CLI evidence, deployment/rollback guide and blockers. Do not install dependencies or alter production routing without preflight. No source-code comments unless explicitly requested. Do not push or force-push unless instructed.
