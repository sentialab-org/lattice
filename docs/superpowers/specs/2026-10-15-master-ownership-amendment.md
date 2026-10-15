# Master Ownership and Device Choice Amendment

Date: 2026-10-15. Implements the owner's clarified requirements and instruction
to complete them directly using the previously selected Native method.
Supersedes the single globally designated master portions of the original
normalization design. This contract is not a deployment acceptance claim.

## Contract

- Keep one configured dashboard owner account; it may issue many device-bound
  activation tokens. All resulting master nodes belong to that owner.
- Multiple authenticated master nodes operate concurrently. Remove global
  designation and active/standby authorization. Revoking one master does not
  revoke ordinary membership or another master.
- A device owner explicitly selects one workload master locally. An absent,
  unavailable, or revoked selection never causes automatic reassignment.
  The network remains usable without workload attachment.
- Preserve the existing single workload trust and one active lease per node.
  Reject a change of selection while a nonterminal lease exists; the owner can
  cancel/finish it first. Preserve the choice across restarts. A pre-existing
  automatic trust pin is not evidence of an explicit owner choice.
- Report the owner's choice to the relay using a node-signed discovery claim
  and monotonically increasing choice revision. The relay uses that choice to
  attribute fleet telemetry; another master cannot claim the node's telemetry.
- Master proof remains the relay-signed grant bound to node/control keys. The
  activation code is single use; the durable signed authorization token stays
  on the master. No dashboard password is installed on master nodes.
- Later activation uses the complete elevated master installer on the existing
  installation. It supplies the missing component and service while preserving
  identity, address and local policy. Token-only setup must explain when the
  master component has not been installed.
- Public ordinary admission requires explicit acceptance of versioned technical
  participation terms. Store the acceptance locally and in the relay's signed
  join record. Do not infer consent from old policy defaults or a previous
  automatically selected master. CLI, local web UI and desktop expose consent.
- Keep typed workload operations, local policy/resource limits, account login,
  CSRF protection, directory freshness/rollback checks, identity-bound token
  recovery and the existing L3 relay path. No arbitrary remote shell.

## Interfaces and behavior

`MasterChoice { control_id: Option<String>, revision: u64 }` lives in protected
node setup state. Owner-only IPC lists authorized masters and selects/clears
one. Selection validates the fresh signed directory, persists atomically,
clears old remote policy/content-origin authorization, and drives attachment.
The authorization gate matches the persisted choice and retained trust against
any current authorized grant, never a global selection.

Discovery may carry `master_choice`; absent legacy claims do not overwrite a
recorded choice. Lower revisions or conflicting equal revisions are rejected.
Unsigned fields cannot change the owner choice. Legacy signed enrollment and
heartbeat claim layouts remain unchanged.

The dashboard selects the target master for workload operations, via a known
master ID rather than a browser-supplied URL. Inventory collects authenticated
reports from all authorized masters, merges each node once, and filters by
the node's recorded owner choice. Unavailable telemetry is explicit.

Participation terms describe public network membership, master selection,
resource permission, local limits and leaving/pausing the network. Acceptance
contains the current version, content digest and timestamp, signed as part of
public admission. This is a technical participation notice, not a claim of
legal review. Existing network identities are preserved; missing acceptance or
master selection blocks new managed workloads rather than inventing consent.

## Validation and rollout

Prove two masters can authorize concurrently; revoke one independently; prove
an unchosen authorized master cannot supply work; verify no default selection,
restart persistence and busy-node selection rejection. Verify unsigned/stale
choice changes, wrong terms and missing acceptance are rejected.

Exercise CLI/local web/desktop paths and all existing regressions. Use Linux
native pilot first, preserve recovery state and immutable old releases, and
leave global stable unset while platform or new-contract gates remain unmet.
