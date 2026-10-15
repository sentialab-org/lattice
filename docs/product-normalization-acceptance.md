# Product Normalization Acceptance

Date: 2026-10-15. Status: source implemented; independent review findings corrected and available automated gates passed.
This is not a published, installed, reboot-tested or production acceptance claim.

## Evidence boundaries

| Gate | Current evidence |
|---|---|
| Account/session/CSRF | Real local Axum API tests and Chromium login/logout/expiry tests |
| Token/activation/recovery | Durable store tests, concurrent binding, restart/lost-response tests |
| Public membership/IPAM | Signed API tests, 50 simultaneous allocations, key uniqueness and revocation |
| Gateway peer convergence | Recording-runner apply/revoke/rollback tests; kernel acceptance pending |
| Native setup | Real daemon/IPC/public-join fixture; no-handshake setup never reports ready |
| Linux/macOS adapters | Disposable filesystem/service shims and plist validation; root/reboot acceptance pending |
| Windows | Cross-target compilation; Pester/UAC/SCM not tested on a native Windows host |
| Console | Real Chromium flows at 390x844 and 1440x1000; screenshots inspected |
| Desktop/local console | Tauri bridge mapping, production UI build, real local socket bridge and daemon fixture |
| Complete release | Five target compiler/linker builds succeeded before corrections; the final staged catalog binds the corrected revision and all bundle hashes |
| Production migration | Not performed; existing Edge combined service retained |

Historical OpenCode ping/SSH evidence predates these installers. Do not reuse it as
a fresh installation PASS. Source tests, fixtures, built bundles, installation and
physical acceptance are separate gates.

## Independent review and automated verification

One fresh, read-only review covered `5e8261d..1b4a773`. All eight Important
findings were accepted and corrected in one implementation pass. The available
post-correction gates are 149 Rust tests passed, one ignored platform test, 27
installer/distribution tests, seven Chromium flows, two Tauri mapping tests, one
real local socket test and a production desktop UI build. Windows cross-compilation
passed; fresh release builds cover Linux x86_64/aarch64 and macOS arm64/x86_64 too.
Native Windows Pester/UAC/SCM and every OS root/reboot/real peer gate remain pending.

| Corrected integration | Regression evidence |
|---|---|
| First master service startup cycle | Activation persists before attachment; missing service reports pending; installer waits again without re-entering token |
| Master revocation at nodes | Signed directory persisted, checked at heartbeat/lease/control/update acceptance, late response and restart rejection |
| Master workload downloads | Bind and origin derive from signed grant; exact-origin HTTP content exception, immutable registry restart and manifest validation |
| Owner policy changes after setup | Actual GetConfig/SetConfig dispatch retains the pinned overlay endpoint and saves policy |
| Windows environment ordering | Service registration does not start it; configure environment before explicit start; native SCM remains untested |
| Legacy pending allocations | Existing empty address is assigned once and remains stable on retry |
| Central workload inventory | Selected-master signed snapshot, node key matching, health/capability merge and explicit unavailable state |
| Owner network disable/reset | Reconciliation respects disable; explicit reset suspends setup; current leases and control pin survive handover |

The managed network dependencies have pinned provenance, checksums, notices and
corresponding source. macOS arm64 tools were run without creating interfaces;
other architectures were structurally inspected. These checks do not install a
WireGuard tunnel or prove a native service.

## Observed Edge baseline and recovery

Read-only inspection found `lattice-control.service` active in combined mode,
`/var/lib/lattice`, `/etc/lattice/control.env`, `/usr/local/bin/lattice-control`,
`lattice0`, public API bind `0.0.0.0:7443`, and an HTTP public URL. The new account
cookie requires HTTPS at the browser origin. Prepare the TLS/same-origin routing
before switching the public console or installer URLs. Cloudflared is running,
but the current public `/health` request returned HTTP 404; the final origin route
still needs to be reviewed and tested. The persistent Edge job queue was empty
at inspection; recheck immediately before any role change.

Protected local recovery snapshot:
`/Users/zvwgvx/.codex/backups/lattice/20261015-normalization-edge/edge-before.tar.gz`.
The archive contains credentials and keys: keep mode 0600, never publish it or
attach its contents to a review. Its checksum and required entries were verified.

## Concrete rollout review

1. Build final reviewed 0.2.0 binaries and every target advertised by the catalog.
   Validate bundles, provenance and managed dependencies; record their hashes.
2. Stage a disposable coordinator on a separate loopback port and state directory.
   Exercise the new account/public join without modifying the running Edge state.
3. The supplied owner account has been provisioned privately in the protected local
   preparation directory beside the backup. Transfer its verifier into the reviewed
   coordinator state only during the approved migration. Never put the password in
   argv, source or release files.
4. Review and configure same-origin HTTPS routing for control, installer and release
   paths. Verify Secure cookies through the actual public origin.
5. Keep the current combined service and old workload authority until active leases
   have an explicit handover/drain plan. Do not drop jobs by merely changing its role.
6. Install/activate a participating master, verify its ordinary IP and selected
   authority, then migrate nodes through the shared setup while retaining identity,
   WireGuard keys, owner policy and existing allocations.
7. Switch Edge to the reviewed bootstrapper binary/environment only after the
   workload handover is accepted. Enable continuing gateway reconciliation.
   Retain the exact gateway key, `lattice0`, `10.77.0.0/16` and reserved addresses.
8. Publish only the reviewed immutable release; move the stable pointer last.
   Reboot/restart and reconnect each supported OS, verify overlay ping and a real
   authorized TCP connection through the hub, then verify master revocation.

Rollback restores the previous binary, owned service/environment files, stable
pointer and known-good gateway configuration from the protected snapshot. Do not
replace a live allocation store with an older one after admitting additional nodes;
reconcile new allocations first or preserve the newer identity/IP records. Preserve
unrelated firewall tables, interfaces and services.

## Read-only verification

```bash
sudo env LATTICE_NODE_BINARY=/path/to/installed/lattice-node scripts/verify-installation.sh --expected-revision <final-commit> --tcp-peer <other-overlay-ip>:<authorized-port>
```

The report binds the daemon's compiled revision, executable checksum and bundle
manifest; checks the service PID, actual gateway handshake, OS route, overlay ping,
workload attachment and a second node's TCP listener. Missing revision, stale
handshake, wrong route, service-only state or an omitted TCP probe cannot pass.
Reports label pass/fail/not-tested explicitly and contain no private keys/tokens.

## Decisions and unresolved physical gates

[Execution decisions](product-normalization-decisions.md) preserves the complete
ruling list. No review minors were deferred. No release was pushed or published,
no existing Edge service was replaced, and no owner network interface was changed
by this source implementation. Review the staged catalog and its release review
before approving a production action.
