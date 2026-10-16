# Linux Ownership Pilot Acceptance

Updated: 2026-10-16. Current Linux candidate: **0.3.2**. Executables and all four
Linux role bundles were built from `0e0e37578e12d91386518f593f5c612f64eedbc5`.
Global stable remains unset. Use an explicit `LATTICE_VERSION=0.3.2`.

## Deployed state

| Device | Candidate | Role and owner choice | Overlay address |
| --- | --- | --- | --- |
| Edge, Linux ARM64 | 0.3.2 | Bootstrapper and L3 gateway | 10.77.0.1 |
| Core, Linux x86_64 | 0.3.2 | Authorized master and node; explicitly selects Core | 10.77.0.4/32 |
| Ubuntu test VM, Linux x86_64 | 0.3.2 | Ordinary node; explicitly selects Core | 10.77.0.6/32 |
| Mac, macOS ARM64 | Historical 0.2.2 | Network participant; ownership migration not performed | 10.77.0.5/32 |

The existing configured dashboard account is unchanged. No secondary owner
account, password reset, identity replacement or IP reallocation was performed.
The temporary Ubuntu master was revoked, its service disabled, its private master
state archived in protected recovery storage, and its ordinary node installation
restored. It no longer acts as a workload master.

## Observed acceptance

- Both Linux devices first reached network-only participation after explicit
  terms acceptance, with no inferred master choice. Owner selection then produced
  authenticated workload attachment. Prior automatic pins were not adopted.
- During the 0.3.1 ownership pilot, one owner activated a second independent master
  on the existing Ubuntu node. Both signed grants appeared concurrently. Core
  explicitly selected that master while Ubuntu selected Core; fleet attribution
  followed each signed local choice.
- Revoking the temporary master left the primary grant valid. Core retained its
  selected, now-unavailable master and stopped workload readiness without automatic
  reassignment. An explicit local action restored its Core choice. The revoked
  local master role was then retired from the dedicated Ubuntu test device.
- Version 0.3.2 changes installer program-directory permissions and package
  versions; its workload authorization implementation is unchanged from 0.3.1.
  Both devices were actually installed with 0.3.2 and report the source revision
  above from their running daemons.
- A non-root local owner can execute the installed CLI and use protected IPC on
  both devices. Program directories are traversable; private state remains 700.
- Before/after comparisons match public node identity, complete stored WireGuard
  key material, local workload policy and allocated IP. Terms and owner choice
  persist through upgrades, Core node/master service restart and a real reboot
  of the dedicated Ubuntu VM. Core and Edge hosts were not rebooted.
- A real TCP exchange from Core to Ubuntu succeeded over the current WireGuard
  hub after the VM reboot. The temporary listener exited successfully. This is
  L3 hub acceptance, not direct P2P or payload secrecy from the relay.
- All four 0.3.2 Linux node/master archives were downloaded from the actual HTTPS
  origin and matched catalog checksums. Edge's running executable matches its
  published ARM64 candidate hash. The stable pointer remains absent.

## Source and installer checks

- Workspace: 159 passed, one ignored child-process fixture.
- Chromium account/owner flows: eight passed on the unchanged UI implementation.
- Installer suite: 33 tests, with one native systemd parser check skipped on macOS.
- Actual Linux installer suite: all 13 passed, including the systemd parser and
  program/private-state directory permissions.
- Tauri IPC mappings: two passed; desktop frontend build passed at version 0.3.2.
- One independent final review found three important issues and one minor issue;
  corrections and regressions are documented in
  [the ownership review](product-normalization-ownership-review.md). Subsequent
  native pilot failures were reproduced and corrected without claiming a second
  independent review.

## Recovery and earlier candidates

Protected native backups on Edge, Core and Ubuntu are under
`/var/backups/lattice/20261016-ownership-167a9d3`. Each contains the prior binaries,
configuration and state. Installer rollback snapshots are also retained.

The immutable 0.3.0 pilot failed migration acceptance because a compatibility-only
legacy global-designation field conflicted with cached directory comparison. Its
rollback returned both devices to ready on 0.2.2. Version 0.3.1 corrected that
comparison, but native owner CLI execution exposed private program-directory
permissions. Version 0.3.2 corrects the installer while retaining private data.
Earlier candidates remain evidence and must not become stable.

Machine-readable pilot records and logs are retained under
`.superpowers/sdd/2026-10-15-master-ownership/`; a shareable evidence copy is under
`dist/normalization-review-0.3.2/`. Credentials and activation tokens are excluded.

## Remaining acceptance boundaries

There is no native 0.3.2 Windows, Intel Mac, macOS ARM64 or separate Linux ARM64
participating-node acceptance. Edge proves the ARM64 bootstrapper deployment,
not an ARM64 node/master installer. The prior macOS ARM64 0.2.2 acceptance does
not establish the new ownership contract. No real workload was running during
this pilot; lease continuity and busy-owner-change behavior are regression-tested.

The four-role/offline proposal remains a separate architecture phase. No
Supervisor service split, RelayGrant, 15-minute offline window, authority epochs,
HA, audit ledger or new P2P/cloud deployment is claimed. Existing 120-second
workload-authority freshness gates remain in force.
