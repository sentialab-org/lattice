# Master Ownership Implementation Plan

> Execute directly with superpowers:executing-plans and test-driven-development.
> The owner already chose Native execution and explicitly requested completion
> after clarifying account ownership and per-node master selection.

**Goal:** One dashboard account authorizes concurrent master nodes, while each
ordinary device explicitly selects its workload master after terms acceptance.

**Architecture:** Retain one node workload trust, replacing network-wide master
designation with protected local choice and a node-signed relay record. Reuse
the existing account, key-bound grants, elevated installers and L3 network.

**Tech Stack:** Existing Rust/Tokio/Axum, Bash, PowerShell, HTML/JS, Tauri/React.

**Spec:** [Master ownership amendment](../specs/2026-10-15-master-ownership-amendment.md)

## Global Constraints

- Work on main in /Users/zvwgvx/Project/lattice; preserve all identity, network,
  policy, active leases and existing live recovery material.
- One configured owner account; no new login or public account registration.
- Explicit terms and local master choice; no inferred consent or reassignment.
- Preserve signature freshness, revocation, rollback and local policy gates.
- Keep all repository content English. Linux native acceptance takes priority;
  untested OS gates remain untested. Do not promote stable without acceptance.

## Review Focus

1. Old automatic trust is not an owner choice: test waiting state and blocked work.
2. A second valid master cannot impersonate the selected master: test key/ID gate.
3. Stale discovery cannot undo a choice: test revision conflict/replay handling.
4. An old master cannot contribute stale telemetry for a reassigned node: test merge.
5. Declined terms and missing master components fail before activation/network join.

### Task 1: Concurrent authority and signed owner-choice reporting

Files: protocol product types; control tokens, masters, onboarding, fleet; tests
product_masters, product_fleet, product_join and shared fixture helpers.

Interfaces: MasterChoice with optional control_id and revision; optional choice
in DiscoveryClaim; onboarding recorded_choice(node_id); directory lists all
non-revoked grants. No global master-selection mutation remains.

- [x] Add/run failing two-master, independent-revocation and signed-choice tests.
- [x] Remove global designation from authorization; persist authenticated choices.
- [x] Run targeted control tests and commit.

### Task 2: Explicit local choice and terms admission

Files: protocol IPC/product; node setup, authorization, enrollment, setup_cli,
lib; control onboarding; tests for node setup, admission and IPC.

Interfaces: GetParticipation/AcceptParticipation, ListMasters/SelectMaster IPC;
MasterChoice persisted in SetupRuntime; version/digest/time TermsAcceptance in
public join. CLI setup accepts --accept-terms; masters and select-master expose
local discovery/choice. Setup reports network ready independently of workload.

- [x] Add/run failing no-consent, no-choice, busy-change, persistence and wrong-master tests.
- [x] Implement terms and choice, preserving old leases and local policies.
- [x] Run node/admission tests and commit.

### Task 3: Multi-master dashboard and local owner controls

Files: fleet forwarding/inventory; web/control, web/node bridge/UI; desktop
bridge/UI; browser and mapping tests.

Interfaces: x-lattice-master-id selects a known authorized workload target;
forward_to(master_id) signs a target-bound delegation. Merge authenticated
inventories using recorded per-node choice. Local controls use Task 2 IPC.

- [x] Add/run failing explicit-target, inventory attribution and UI-flow tests.
- [x] Implement target selection and per-device consent/master controls.
- [x] Run browser, bridge and desktop build checks and commit.

### Task 4: Complete Linux activation and regression validation

Files: elevated installer/entry scripts, installer page/docs and tests.

Interfaces: existing public role=master installer supplies full components on
an installed ordinary node and preserves state. Token-only setup rejects an
ordinary bundle with actionable upgrade instructions before consuming a token.

- [x] Add/run failing installer consent/component/upgrade regressions.
- [x] Implement Linux-first paths and maintain other platform source mappings.
- [x] Run workspace, installer, browser and desktop suites; record native limits.
- [x] Conduct one independent final review and one correction pass if needed.
- [x] Commit/push the authorized changes; prepare and verify Linux pilot using
  existing protected backups. Never conflate source checks with native acceptance.

## Completion record

2026-10-16: source tasks, independent final review and corrections are complete.
Native Linux ownership behavior was accepted on 0.3.1; final 0.3.2 installations
also passed owner CLI access, identity/key/policy/IP comparisons, Core service
restart, dedicated Ubuntu reboot and actual hub TCP. See
[Linux ownership acceptance](../../product-normalization-linux-ownership-acceptance.md).
Global stable and the untested native OS/architecture gates remain unset. The
four-role/offline proposal is a separate next phase.
