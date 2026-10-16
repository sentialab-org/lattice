# Offline Authority and Node Modules Implementation Plan

> Use superpowers:executing-plans directly, preserving the owner's Native execution choice. The owner reviewed the written design and instructed implementation. Do not restart design approval or create branches.

**Goal:** Every supported operation verifies locally during a Supervisor outage; all roles extend one Base Node with one host network manager.

**Architecture:** Add domain-separated Supervisor certificates and persistent signed authority updates alongside legacy messages. Nodes and Masters use issued certificates and known revocations without directory-renewal dependencies. Optional control services run as supervised modules; their network intent is applied exclusively by Base Node through protected IPC.

**Tech Stack:** Existing Rust, Tokio, Axum, Ed25519, serde, Unix/Windows IPC, native services, web/desktop bridges. No new cloud infrastructure, HA or P2P deployment.

**Spec:** ../../lattice-four-role-offline-authorization.md

## Global Constraints

- Implement directly on main in /Users/zvwgvx/Project/lattice; preserve unrelated changes and all production identities, addresses, keys, owner policy and leases.
- English repository content. One owner account authorizes multiple Masters. Each Node explicitly chooses one Master; no automatic failover.
- Supervisor reachability never decides otherwise-authorized command eligibility. No replacement 120-second/15-minute mandatory certificate renewal.
- Preserve all operation signature, target, replay, local policy and content/update gates. Ordinary public admission retains explicit terms acceptance.
- Supervisor private keys never leave their authority service. A copied certificate never proves possession of the subject private key.
- One Base Node owns the managed WireGuard interface, routes and firewall; modules use typed IPC and owned rules only. Ports 7443 control / 7444 local Node console.
- Linux native priority. Current 0.3.2 pilot stays recoverable; new acceptance must be distinguished from unit/source evidence. Global stable remains unset.

## Review Focus

1. Missed announcements: a presented authentic certificate works, while a different network/key/selected Master fails.
2. Restarts and replay: known revocations and accepted command sequences survive; lower/conflicting authority updates cannot restore rights.
3. Outage completeness: new attachment/jobs, job control, content, updates and local Master administration must work without Supervisor, not merely retained sessions.
4. Module isolation: revoking/failing Master or Relay preserves ordinary Node and other modules; disabling during a running lease cannot lose its trust/state.
5. Network ownership: duplicate daemon, old gateway writer and co-hosted modules cannot race interfaces, unrelated firewall or port 7443.

### Task 1: Signed offline protocol and crypto

Files: create protocol authority/module/network-manager types; modify crypto lib, protocol exports and product compatibility fields; crypto/protocol tests.

Interfaces: CapabilityCertificate/CertificateSubject, SignedCertificate; AuthoritySnapshot/SignedAuthoritySnapshot; CertifiedAuthorityContext; ModuleKind/ModuleState/ModuleStatus; signed GatewayIntent. Domain-aware sign_domain/verify_domain leave legacy sign/verify unchanged. Canonical encoding v1 recursively sorts object keys and permits integer JSON only.

- [x] Write failing domain-confusion, object-order, tampered-binding and legacy-signature compatibility regressions.
- [x] Implement canonical versioned envelopes and optional certificate/snapshot fields on discovery, membership admission, Master authority and heartbeat delivery.
- [x] Run crypto/protocol tests and lockfile checks; commit.

### Task 2: Supervisor certificates, updates and Relay grants

Files: create control authority.rs and capability registry; modify onboarding.rs, masters.rs, tokens.rs, lib.rs, delegation.rs; new authority integration tests.

Interfaces: publish_snapshot(AppState), membership_certificate(node_id), master certificates from existing grants, issue/revoke Relay capability; public signed authority endpoint. Signed snapshots contain explicit revocations and are persisted with monotonic revision. Legacy grant identities remain unchanged.

- [ ] Write failing certificate issuance, independent revoke, concurrent publication and restart/rollback tests.
- [ ] Publish signed grants/snapshots through discovery, explicit sync and Master responses; retain backward-compatible responses for existing clients.
- [ ] Add supervisor role alias and independently authorized Relay grants bound to node/transport identity and owner limits.
- [ ] Run control integration suites and commit.

### Task 3: Local certificate store and complete offline operation

Files: create node trust_store.rs; modify authorization.rs, enrollment.rs, setup.rs, heartbeat.rs; control masters.rs/fleet.rs/delegation.rs and heartbeat handlers; trust/admission/workload tests.

Interfaces: protected store ingest_snapshot/ingest_certificate/require_master/require_membership with pinned issuer and network, persisted revocations/high-water marks. Workload joins carry durable membership; Master responses present their certificate. Certified command context binds selected Master, target and signed command.

- [ ] Write failing stale-directory/offline-new-attachment and command tests, missed-announcement validation, restart revocation and authority downgrade tests.
- [ ] Separate network synchronization from authorization: continue with valid stored credentials after refresh errors; remove dependency on membership receipt renewal only for authenticated v2 certificate paths.
- [ ] Preserve legacy online validation, local owner consent/choice, immutable active lease and content/update checks. Persist replay acceptance before side effects.
- [ ] Ensure a revoked/failed local Master capability does not prevent the Base Node using its separately chosen valid workload Master.
- [ ] Run Node/control regressions and commit.

### Task 4: Base Node module lifecycle and local administration

Files: create node modules/{mod,process,ingress}.rs; modify protocol IPC, node lib/main/setup_cli/setup, control run_server, desktop mappings and local web bridge.

Interfaces: GetModules, EnableModule, DisableModule, ImportAuthority, SyncAuthority and typed local Master operation IPC. Module statuses are protected/persisted, subprocess executables are verified siblings, credentials stay in private storage and never argv/logs. One 7443 ingress proxies separate Supervisor/Master backends when co-hosted.

- [ ] Write failing module activation/recovery/isolation, child cleanup, co-host listener and unauthorized IPC tests.
- [ ] Supervise optional Master/Relay/Supervisor capabilities from the common Node; local enable requires owner opt-in plus issued authorization (Supervisor requires explicit authority provisioning).
- [ ] Route local owner Master administration through protected IPC so creating/controling jobs does not depend on the Supervisor dashboard being online.
- [ ] Keep controller and Node data/services decoupled; failed optional modules cannot terminate or change the Base Node identity/policy/leases.
- [ ] Run module/process/IPC suites and commit.

### Task 5: One network manager and gateway handoff

Files: create shared lattice-network crate for validated public intent/rendering/owned apply transaction; create node network_manager.rs; modify node network.rs, lib.rs, control network/reconcile.rs and module provisioning.

Interfaces: signed GatewayIntent binds network, target Node, interface, address, peer allocations, allowed forwarding and revision; NetworkManager serializes normal/Relay plans under one host singleton and applied journal. Supervisor never executes privileged networking directly in managed mode.

- [ ] Write failing double-owner, conflicting module plan, invalid peer route, rollback and unrelated-firewall preservation tests with real/fake command runners at the OS boundary.
- [ ] Apply only validated typed plans; generate WireGuard/nftables internally, preserve interface keys/IP and owned namespace. Reject arbitrary commands, paths and firewall text.
- [ ] Provision/adopt existing gateway key and authority data only through privileged local owner action; disable the old gateway writer before the new manager starts.
- [ ] Test actual Linux network namespace forwarding and service ownership; commit.

### Task 6: Product controls and unified installers

Files: web/node UI/bridge, desktop UI/IPC, control dashboard, Linux/macOS/Windows installers, release assembly and browser/installer tests.

Interfaces: local special-status controls expose verified grants and per-module lifecycle; enable/disable/import/sync map to Task 4 IPC. Full role bundles share Base Node and contain verified optional components; one Node boot service owns module startup.

- [ ] Write failing local module controls, offline Master selection/administration and installer identity-preservation regressions.
- [ ] Implement controls with clear owner consent/errors and explicit synchronization status; do not call overdue sync invalid authorization.
- [ ] Replace duplicate optional module boot/network owners with the Base Node lifecycle; preserve native recovery and private modes. Keep standalone legacy migration explicit.
- [ ] Run browser, installer and desktop suites; commit.

### Task 7: Integrated acceptance, independent review and Linux candidate

Files: integration harnesses, acceptance/recovery documentation, versioned candidate artifacts.

- [ ] Run full Rust workspace, native bridge, browser, installer and desktop build checks.
- [ ] Run isolated native Linux topology with Supervisor stopped: new attachment/job/control/content/update validations, certificate presentation, reconnect revocation, module restart and real relay TCP. Verify local admin and one network writer.
- [ ] Obtain one independent whole-change review; fix important issues with regressions and rerun affected/full checks. No review per task.
- [ ] Bump owned version, commit reviewed source and build immutable Linux candidates at one revision. Preserve previous candidates and stable state.
- [ ] Record executable versus source/native acceptance boundaries, backups and concrete migration/handoff runbook; publish/pilot only within the authorized topology and after reviewable preparation.
