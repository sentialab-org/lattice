# Product Normalization Acceptance

Current Linux ownership acceptance is documented in
[the 0.3.2 pilot](product-normalization-linux-ownership-acceptance.md). The remainder
of this file preserves the historical 0.2.2 evidence, including its macOS test.

## Historical 0.2.2 pilot

Updated 2026-10-15 after the owner-approved production pilot. The owner prioritized
Linux when no usable Windows, Intel Mac or additional ARM64 node host was available.
The live candidate is **0.2.2**, built from
`7644179937a44ea57db816a83502c2009f4333b5`. Global stable has not been promoted.

## Live deployment

`https://lattice.sentialab.org` now routes the console, account APIs, installers
and immutable releases through the existing Edge tunnel. Only the Lattice ingress
changed. The supplied account verifier was transferred privately; login, Secure /
HttpOnly / SameSite=Strict cookies, CSRF rejection, Origin rejection and logout
were tested through the actual HTTPS origin. No plaintext account password is
stored in source, service environments or releases.

Edge runs the normalized **bootstrapper** in the existing
`lattice-control.service`, preserving its control identity, WireGuard gateway key,
`lattice0`, canonical allocations and `10.77.0.0/16`. The old workload queue was
empty before handover. Gateway reconciliation is enabled and the unrelated
Cloudflare Warp firewall table remained unchanged during enablement.

| Device | Role after pilot cleanup | Overlay address |
|---|---|---|
| Edge, Linux ARM64 | Bootstrapper / L3 gateway | `10.77.0.1` |
| Core, Linux x86_64 | Participating node and active master | `10.77.0.4/32` |
| Mac, macOS ARM64 | Participating node | `10.77.0.5/32` |
| Ubuntu pilot VM, Linux x86_64 | Participating node | `10.77.0.6/32` |

The native public installers preserved each existing node identity, WireGuard key,
address and workload policy. Mining remained disabled on Core and Mac and retained
its existing owner setting on Ubuntu. HTTPS bootstrap migration checked the same
coordinator ID and fingerprint before changing the legacy HTTP pin's URL.

## Native evidence

Reports bind the daemon's compiled revision, executable checksum and bundle
manifest to its actual service PID. A running service alone cannot pass the
network, workload-attachment or second-node TCP gates.

| Gate | Observed result |
|---|---|
| Linux x86_64 ordinary installer | Public HTTPS script, root systemd service, no enrollment token; passed on Core and Ubuntu |
| Linux x86_64 master installer | Dashboard-issued token entered on the elevated device's private TTY; master service and attachment passed |
| Linux hub network | Fresh WireGuard handshake, OS route, overlay ping and real TCP listener on another node passed |
| Linux service restart | Core node and master recovered; full native verifier passed afterward |
| Linux reboot | Dedicated Ubuntu VM rebooted, boot ID changed, identity/keys/policy/IP retained; full native verifier passed afterward |
| Linux reconnect | VM NIC disconnected and restored; native verifier rejected the disconnected state and passed after reconnection |
| Master handover | Core's actual controller pin moved to the temporary Ubuntu master and workload attachment recovered |
| Master revocation | Revoked master disappeared from the signed directory and could not be selected; node kept network access but stopped accepting its workload authority |
| Recovery after revocation | Core was selected again as the active master; temporary Ubuntu management service was disabled and its ordinary node bundle restored |
| Central management | HTTPS bootstrapper read the selected master's jobs and signed fleet inventory |
| Owner IPC | Core owner and Mac administrator accessed the installed root daemon without sudo |
| macOS ARM64 | Root launchd install, handshake/route/ping/second-node TCP and service restart passed |
| Linux ARM64 | Edge control/gateway/reconciliation and private native node IPC passed; participating-node installer not tested on a separate ARM64 device |
| Windows x86_64 / macOS x86_64 | Built and bundle-verified; native installation not tested |

The Windows VM had a black console, no connected guest agent and no available
guest access. It is not Windows installation evidence. Core host and Mac workstation
reboots were not performed. Mac reconnect, native Windows UAC/SCM/driver behavior,
Intel Mac installation and a separate Linux ARM64 participating node remain pending.
These limits are why global stable remains unset.

## Pilot corrections and release provenance

The immutable 0.2.0 pilot exposed systemd ignoring quoted `EnvironmentFile` paths.
The correction was first reproduced and then verified with the native systemd
parser for both node and master, including paths containing spaces.

The immutable 0.2.1 pilot exposed a stale Unix socket being mistaken for a newly
started daemon. Version 0.2.2 removes the owned stale socket after stopping the old
daemon and waits for the new binding. Linux and macOS socket regressions passed;
actual Linux reinstall and role transitions passed afterward. Neither older
candidate may be promoted.

All five targets and ten 0.2.2 role bundles were rebuilt, archive-validated and
checked by the native allowlist/hash verifier. All ten complete public HTTPS
downloads matched the immutable catalog. Native daemon package version remains
0.2.0; installer/bundle release 0.2.2 and the embedded source revision identify
these packaging corrections.

The independent source review covered `5e8261d..1b4a773`; all eight Important
findings were corrected in `22e8d08`. Its verified foundation has 149 Rust tests
passed, one ignored, seven Chromium flows, two Tauri mapping tests, one local socket
test and a production desktop UI build. Later installer corrections changed no
Rust behavior. The final installer suite ran 30 tests on macOS, with 29 passed and
the native systemd test skipped there; all 10 Linux installer tests passed on
Linux, including the actual systemd parser. No second independent review is claimed
for the two pilot installer corrections.

Workspace evidence is retained under `dist/normalization-review-0.2.2`, including
native reports, full public bundle hashes and `pilot-results.md`. Historical
OpenCode evidence is not reused as a fresh installation PASS.

## Recovery and publication

Protected Edge recovery is retained at
`/var/backups/lattice/20261015-normalization-pilot-22e8d08`. Core, Ubuntu and Mac
also retain their private pre-migration state and installer rollback snapshots.
Keep all recovery files private; they contain credentials and keys.

Rollback restores only owned binaries, service/environment files and routing.
Preserve all newly admitted identities and current allocations: never replace the
canonical registry with an older snapshot after new admissions. Reconcile gateway
peers from the newest canonical store. Preserve unrelated firewall tables, cloud
tunnels and workloads.

Immutable candidates remain available for explicit `LATTICE_VERSION=0.2.2` pilot
commands. The default stable installer is not released. Do not advance global
stable or describe untested target installations as accepted. See
[release instructions](release-distribution.md) and
[execution decisions](product-normalization-decisions.md).
