# Product Normalization Acceptance

Date: 2026-10-15. Status: source implemented; independent review and release build in progress.
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
| Complete release | Must be rebuilt at the final reviewed source revision with managed dependencies |
| Production migration | Not performed; existing Edge combined service retained |

Historical OpenCode ping/SSH evidence predates these installers. Do not reuse it as
a fresh installation PASS. Source tests, fixtures, built bundles, installation and
physical acceptance are separate gates.

## Observed Edge baseline and recovery

Read-only inspection found `lattice-control.service` active in combined mode,
`/var/lib/lattice`, `/etc/lattice/control.env`, `/usr/local/bin/lattice-control`,
`lattice0`, public API bind `0.0.0.0:7443`, and an HTTP public URL. The new account
cookie requires HTTPS at the browser origin. Prepare the TLS/same-origin routing
before switching the public console or installer URLs.

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
LATTICE_NODE_BINARY=/path/to/installed/lattice-node scripts/verify-installation.sh --expected-revision <final-commit> --tcp-peer <other-overlay-ip>:<authorized-port>
```

The report binds the daemon's compiled revision, executable checksum and bundle
manifest; checks the service PID, actual gateway handshake, OS route, overlay ping,
workload attachment and a second node's TCP listener. Missing revision, stale
handshake, wrong route, service-only state or an omitted TCP probe cannot pass.
Reports label pass/fail/not-tested explicitly and contain no private keys/tokens.
