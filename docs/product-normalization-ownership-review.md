# Ownership Normalization Review

Date: 2026-10-16. Implementation baseline: `5ec814d` on `main`.

The independent final review found three important issues and one minor issue.
No critical findings were reported. One correction pass addresses the findings:

- Retained legacy workload trust no longer skips terms, explicit owner choice,
  signed directory validation or freshness when setup state is missing or malformed.
- Update finalization acquires the same mutation lock as owner master selection,
  revalidates authority after acquiring it, and holds it through staging and the
  Windows apply transition. A barrier-controlled test proves selection waits and
  cannot complete while application starts; deselection prevents finalization.
- Master setup rejects absent/invalid installed metadata and missing, non-regular,
  non-executable or size-mismatched master components before network admission,
  control-key generation or token redemption. Reconciliation repeats this guard.
- The setup CLI preserves the daemon's actionable component-upgrade error.

Regression evidence under `.superpowers/sdd/2026-10-15-master-ownership/` records
failing tests before the corrections and subsequent passing runs. The corrected
workspace suite passes, along with eight Chromium browser tests and 32 installer
tests (one native systemd parser check skipped on macOS). Native pilot evidence
must be recorded separately; source checks do not prove deployed behavior.

## Four-role proposal assessment

`docs/lattice-four-role-offline-authorization.md` is a proposed next architecture,
not a statement that all four roles or offline authorization are implemented.
It preserves the approved single owner / multiple masters / local master choice
contract and correctly separates forwarding from destination workload authority.

Resolve these implementation contracts before extending the current runtime:

1. Assign one owner of the host WireGuard interface, routes and firewall when
   capabilities share a machine; define service endpoints and console bindings.
2. Enumerate offline operations. Cancel/stop, resume, resource expansion and new
   jobs need distinct rules. Keep the present 120-second authority freshness gate
   until versioned bounded continuity is implemented and explicitly accepted.
3. Specify how a first-time installer obtains the expected Supervisor key and
   network identifier, including authority-key rotation and recovery.
4. Version and domain-separate signed envelopes, choose canonical encoding, and
   migrate existing signatures explicitly. Current JSON serialization must not
   silently acquire a different signing interpretation.
5. Persist authority high-water marks and bounded time state across crashes and
   clock rollback. Audit queues and signed receipts need crash-recovery behavior.
6. Keep confidentiality claims precise: the current WireGuard hub decrypts each
   hop. Payload secrecy from a Relay requires an additional end-to-end channel.

The proposed 15-minute window, RelayGrant, authority epochs, signed audit ledger,
Supervisor HA, P2P routing and new cloud placements remain future work. Reading
this proposal does not change live topology, acceptance gates or release channels.

## Native migration correction

The first Linux 0.3.0 pilot exposed a real 0.2.2 migration defect: the cached
signed directory retained `active_master_id`, whereas the new directory removed
its meaning without changing the authority revision. Equal-revision comparison
incorrectly rejected that compatibility-only change. The pilot was rolled back
to its saved 0.2.2 executables and reached ready state again with the same device
identities and overlay addresses. The immutable 0.3.0 artifacts are retained as
failed acceptance evidence; they must not become stable.

Version 0.3.1 ignores the obsolete global-designation field when comparing signed
directories, while continuing to reject changed network IDs, lower revisions and
equal-revision changes to the actual master grants. A restart/migration regression
fails on the original comparison and also verifies that conflicting authority is
still rejected. Native 0.3.1 acceptance is recorded separately.

The 0.3.1 pilot then verified network-only participation followed by explicit
owner selection on both Linux devices. A separate native owner-CLI check found
that installer-created program directories inherited mode 700. Version 0.3.2
makes only the public program root and installed bundle traversable (755);
protected state, environment and rollback directories retain private modes. A
failing installer regression captures this permission error before correction.
