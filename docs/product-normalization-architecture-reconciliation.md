# Network Role Clarification and Implementation Reconciliation

Date: 2026-10-15.

Status: owner clarification recorded after the Linux-first 0.2.2 pilot.
This is a source audit and requirements record, not an approved replacement
implementation plan or a claim that the clarified behavior is deployed.
Further rollout is paused while the clarified contract is incorporated into
the implementation design and verified.

The clarified contract is being implemented as source version 0.3.0 under
[the ownership amendment](superpowers/specs/2026-10-15-master-ownership-amendment.md)
and [its Native execution plan](superpowers/plans/2026-10-15-master-ownership.md).
The table below preserves the audited 0.2.2 baseline, not the state of the
amendment code. Native acceptance of the new contract is recorded separately.

## Confirmed role boundaries

- A relay/bootstrapper is a publicly reachable network node. It supports
  discovery and admission, authenticates master identities, and forwards data.
- There is one master-owner dashboard account. It belongs to one person and
  may create multiple activation tokens for that person's master nodes.
  Multiple master nodes do not imply multiple accounts or independent owners.
- A master is an independent participating node. A relay/bootstrapper-issued
  token establishes its master authority by binding that authority to its key.
  The master retains a relay-issued credential locally.
- Multiple authenticated masters may operate concurrently in the same network.
  There must be no network-wide selection that authorizes only one master.
- An ordinary node accepts workloads only from the master node selected by its
  device owner. Authorization by the relay alone does not enroll that node
  under every master, including other masters belonging to the same account.
- Master activation must be available during installation or later, after an
  ordinary node obtains a token from the relay/bootstrapper. Preserve the
  participating node's identity, network keys, overlay IP, and saved policy.
- Ordinary nodes can join publicly after accepting the terms. They do not need
  an invitation token or manual admission approval.
- Public network membership is distinct from master authority and dashboard
  account access. The product must not equate membership with unrestricted
  remote command execution.
- The previously agreed owner workload policy and resource limits remain
  boundaries on master operations. The clarification does not authorize an
  arbitrary remote shell or an override of the device owner's policy.

The clarification does not change the previously selected Layer 3 relay path
or establish a new direct peer-to-peer transport requirement. Relay placement,
master authority, and the data path are separate concerns.

## Account, credential, and device model

| Entity | Cardinality and responsibility |
| --- | --- |
| Master-owner account | One account authenticates the person using the dashboard and manages that person's master nodes. |
| Activation token | The account may create multiple tokens through the relay/bootstrapper. Each activation token binds one master-node identity; it is not a second dashboard login. |
| Master node | Multiple devices may hold master authority concurrently under the same owner. Each retains its own identity, keys, overlay address, and relay-issued authorization credential. |
| Ordinary node | Public membership follows terms acceptance. The device owner selects the master node allowed to supply workloads and retains control of local resource policy. |

Creating, revoking, or taking one master node offline must not designate or
revoke all other master nodes as a side effect. Common account ownership does
not authorize automatic workload reassignment between devices. Preserve the
owner's preceding explicit choice of one workload master per ordinary node;
the latest clarification changes account ownership, not that selection rule.

## Verified source behavior

Audited source: `df4fbf3ad8b3dcfd50185bf297bfac6b796d967b` on `main`.
The 0.2.2 pilot artifacts contain runtime source revision
`7644179937a44ea57db816a83502c2009f4333b5`; the later commit records pilot
documentation. No runtime changes were made for this reconciliation.

| Area | Current implementation | Reconciliation |
| --- | --- | --- |
| Dashboard account | `auth::credentials::Account` and `AuthState.account_path` represent one configured `account.json`; token creation requires authenticated operator authority. | Reuse the existing single owner account. No additional account, public account registration, or separate password per master node is required. |
| Relay and master separation | Bootstrapper and master roles are separate; an independently enrolled node can activate master authority. | Consistent with the clarified role placement. |
| Key-bound authority | Activation proves the node and control keys. The bootstrapper returns a signed grant bound to those identities. | Consistent with relay authentication of the master key. |
| Retained credential | Setup stores the signed grant in `master/master-authority.json` and clears the original activation token. | A durable credential exists, but the original token is not retained. Do not describe these as identical token lifecycles. |
| Master cardinality | `MasterAuthorizationStore.active_master_id`, node attachment, fleet forwarding, and master authority validation select one active master for the network. | Conflicts with the owner's confirmed requirement for multiple concurrently authorized masters. |
| Activation after installation | CLI and local UI accept a master role and token, but an ordinary-node release bundle does not include `lattice-master`; the node CLI does not install the missing executable or register its service. | A token-only UI change cannot complete later activation. Add a complete upgrade path while retaining existing node state. |
| Public admission | Ordinary enrollment requires no master token or manual approval. | Retain this behavior. |
| Terms acceptance | No explicit terms acceptance flow or versioned acceptance record was found in the installer/setup/admission paths. | Missing requirement. Do not call current admission compliant with the clarified flow. |
| Initial workload permissions | `NodePolicy::default()` enables AI, rendering, media, and research; mining and generic jobs are disabled. | Defaults do not establish explicit user agreement. Joining and the permission to consume resources need clear consent semantics. This does not assert that any job ran. |
| Owner controls | Setup respects owner network disablement; local workload policy and limits constrain typed workload operations. | Preserve these boundaries and existing saved policy. |

Source anchors:

- `crates/lattice-control/src/tokens.rs`: activation bindings, grants, and
  `active_master_id`.
- `crates/lattice-control/src/masters.rs`: activation and current master
  authority validation.
- `crates/lattice-node/src/setup.rs`: persisted signed master authority,
  activation-token removal, selected-master attachment, and owner controls.
- `crates/lattice-control/src/fleet.rs`: forwarding to the selected master.
- `crates/lattice-protocol/src/lib.rs`: initial `NodePolicy` defaults.
- `crates/lattice-node/src/authorization.rs`: workload authorization against
  the single selected master and directory revision checks.
- `crates/lattice-node/src/heartbeat.rs`, `job.rs`, and `identity.rs`: one
  workload trust relationship and lease/signature handling.
- `crates/lattice-node/src/bundle.rs`, `setup_cli.rs`, and
  `scripts/install-node-linux.sh`: role-specific bundle and service setup.
- `web/control/setup.js`: active/standby terminology and global designation UI.
- `crates/lattice-control/src/auth/credentials.rs`, `auth/sessions.rs`, and
  `tokens.rs`: the configured owner account, authenticated sessions, and
  authorized token creation.

## Confirmed change impact

These source dependencies require a coordinated design amendment; removing a
single `active_master_id` check cannot establish concurrent-master support.

1. The signed master directory must represent all currently authorized
   master nodes belonging to the single account; each master must prove its
   own current relay-issued authority.
   Directory freshness, rollback rejection, and per-master revocation remain
   required.
2. Node workload trust, heartbeat delivery, lease signatures, job control,
   content downloads, runtime manifests, and updates currently depend on one
   `ControlTrust`. Retain one workload trust per ordinary node, chosen by its
   device owner, rather than selecting one global master or trusting all
   master nodes owned by the account automatically.
3. Dashboard operations must identify their intended master. Fleet inventory
   must retain the provenance of each master's reports, handle unavailable
   masters explicitly, and avoid counting one node twice. Mutations must not
   silently fan out to every master.
4. Later activation must install the complete master component, establish
   relay-authenticated authority, and register its OS service. Keep a working
   ordinary node if activation fails; do not regenerate its network identity.
5. Tests must cover at least two simultaneously authorized masters, activation
   of an already-installed ordinary node, and revocation of one master while
   another remains usable. Existing one-master handover evidence does not
   cover these cases.

## Pending decisions and acceptance

Account ownership, master cardinality, and workload association have been
clarified: one owner account can authorize multiple concurrently operating
master nodes, and each ordinary node accepts workloads only from the master
node selected by its device owner. These are recorded requirements, not
evidence that current source or pilot binaries implement them.

The exact retained master-token lifecycle and explicit terms acceptance must
be reconciled in the design before implementation. Do not silently disable
existing owner-approved workloads or overwrite saved policy while doing so.

Earlier pilot evidence remains evidence for the tested 0.2.2 contract. It does
not establish compliance with the newly clarified terms/role requirements.
Global `stable` remains unset. Linux remains the prioritized native target.
