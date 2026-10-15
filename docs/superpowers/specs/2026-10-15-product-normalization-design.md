# Lattice Product Normalization

Date: 2026-10-15.

Status: approved by the owner on 2026-10-15. The implementation plan is the
next review artifact; implementation has not started under this design.
This document does not claim that the new installation or authentication
flows are implemented, published, installed, or live-tested.

## 1. Outcome and confirmed requirements

Lattice has one coherent product flow: obtain the installer from
`https://lattice.sentialab.org`, authorize system installation, and let the
installed services establish and maintain network membership automatically.

The owner has confirmed:

- Initial platforms are macOS, Windows, and Linux.
- A public installer lets any ordinary node join automatically. Ordinary-node
  admission requires neither an enrollment token nor manual approval.
- A master is a participating node with management authority. Master setup
  must request a separate token generated from the authenticated dashboard.
- The dashboard requires account login. The initial username is `zvwgvx`;
  the owner-provided password must be provisioned privately and is omitted here.
- Installation requires OS administrator privileges, installs the network
  integration, and registers services that start with the operating system.
- Registration, key exchange, interface configuration, and reconnection are
  automatic after installation.
- Retain the currently deployed Layer 3 hub path, `A -> Edge01/RPi -> B`.
  Direct P2P optimization is a later task, as already selected in the OpenCode
  session. Existing node identities and stable overlay IPs must survive.

Public admission is deliberate. It grants ordinary network membership, not
master authorization, dashboard access, or permission to issue workload commands.
Do not introduce a hidden shared secret or an approval queue for ordinary nodes.

## 2. Actual implementation baseline

Work only in `/Users/zvwgvx/Project/lattice`, on `main`. The baseline is local
HEAD `e689dce` plus the preserved OpenCode working-tree changes. The similarly
named `/Users/zvwgvx/projects/lattice` checkout is not the source of the network
implementation.

The existing implementation includes WireGuard key handling and OS adapters,
stable IPv4 allocation, signed network register/sync/ack/peers messages, gateway
forwarding, a node network supervisor, workload supervision, operator UI, local
node console, and partial installer/distribution scripts. Extend these paths.

Fresh baseline validation on 2026-10-15:

```text
cargo test --workspace --locked
84 passed, 0 failed, 1 ignored
```

The unwired `tokens.rs` module is excluded from that test run. This baseline
does not validate account login, master authorization, full installation,
reboot recovery, or the current live state of remote devices. A HEAD request
to the public website returned HTTP 200; that is not UI or installer acceptance.

Concrete gaps found in source:

| Area | Current behavior | Required change |
| --- | --- | --- |
| Dashboard | Prompts for a shared operator bearer token. | Account login, session lifecycle, and master-token management. |
| Authentication | `tokens.rs` is not declared or called by the control library; proposed password checking uses plain SHA-256 and trims input. | Wire authentication into actual routes; preserve exact password bytes and use a salted password hash. |
| Ordinary enrollment | Requires the shared enrollment token; network registration creates `PendingApproval`. | A dedicated public ordinary-node join flow and automatic IP allocation. |
| Gateway convergence | The installer applies a rendered gateway configuration once; the server has no continuing gateway peer reconciliation loop. | Apply newly admitted/changed/revoked peers to the owned interface automatically, preserve existing traffic, and report apply failures. |
| Master authorization | No dashboard-issued, device-bound activation path. | Validate a master token and bind authority to the participating device. |
| Linux public script | Reads interactive input from stdin, including when piped from curl. | Use the controlling terminal for interaction; fail explicitly without a terminal when required input is missing. |
| Download layout | The public script defaults to a base ending in `/releases` but also fetches `/scripts` below that base. | Separate the site base from the release root and use one published layout. |
| Linux downloaded installer | Expects `lattice-ipc.py` beside the install script, while the public downloader places it in a different directory. | Package helper files with an explicit location or replace bootstrap IPC calls with the native setup command. |
| macOS | Master script creates a user LaunchAgent and explicitly skips overlay joining. No public macOS installer exists. | System LaunchDaemons, ordinary node and master setup, and automatic WireGuard integration. |
| Windows | Requires WireGuard to be installed manually and assumes an elevated shell. | Managed dependency installation and explicit UAC elevation handling. |
| Distribution | macOS worker and Windows update helper are omitted from node bundles; some target artifacts are unavailable. | Role-complete, target-specific release manifests and fail-before-install target checks. |
| Status | A running service or successful IPC response can be printed as success while later onboarding steps are incomplete. | Report each installation and network acceptance stage separately. |

Relevant source: [control library](../../../crates/lattice-control/src/lib.rs),
[token draft](../../../crates/lattice-control/src/tokens.rs),
[IPAM and network authorization](../../../crates/lattice-control/src/network.rs),
[node networking](../../../crates/lattice-node/src/network.rs),
[public Linux installer](../../../web/installer/linux.sh),
[public Windows installer](../../../web/installer/windows.ps1),
[macOS master installer](../../../scripts/install-master-macos.sh), and
[release publisher](../../../scripts/publish-release.sh).

## 3. Approach

Two approaches can deliver the requested behavior:

| Approach | Benefits | Cost |
| --- | --- | --- |
| Shared onboarding contract with OS-specific installation adapters — proposed | One role model, one admission policy, one status model, and consistent retry/recovery behavior across platforms. Reuses the Rust node and existing network supervisor. | Requires a native setup entry point plus authentication and role activation APIs. |
| Independently extend each existing installer | Smaller individual script edits at the beginning. | Repeats protocol, approval, retry, and status logic across shell, PowerShell, Python, and the UI; divergence remains likely. |

Use the first approach. Public scripts handle downloads, elevation, dependencies,
and service registration. A native node setup command owns identity-aware join,
activation, readiness, and idempotent retry through local IPC. The running node
continues to own network reconciliation and workload lifecycle.

Keep existing binaries and the dedicated worker. This normalization does not
rewrite the runtime or replace WireGuard.

## 4. Product surfaces and role boundaries

The public site provides install instructions and the three OS entry scripts.
The authenticated dashboard provides fleet inventory, roles, virtual IPs,
capabilities, workload controls, and master-token issuance/revocation. Preserve
the existing retro monochrome design and operator controls.

An ordinary installation runs `lattice-node` and the existing worker when
needed. A master installation adds `lattice-master` to that same participating
host. It has one node identity/IP and one compute supervisor; installing master
does not create a second participating node or a second compute executor.

The bootstrapper/relay remains on Edge01. It owns network membership, IPAM,
master activation records, and the gateway. Bootstrapper deployment is an
operator infrastructure flow, not a public ordinary-node installation option.
Only the existing Edge01 public API/website and WireGuard UDP ingress are needed;
master nodes do not require a new public port forward.

The central dashboard sends workload operations through an allowlisted backend
client to the designated master's overlay endpoint. Authenticate that hop using
a short-lived, coordinator-signed operator delegation scoped to that master and
the requested operation. The master validates scope, identity binding, and
expiry. Do not distribute the dashboard password or a global operator token to
every master, and do not turn a browser-supplied URL into an unrestricted proxy.

Preserve separate bootstrap/network trust and workload-control trust. A master
has its existing control signing identity as well as its participating node
identity. Activation binds both public identities and the assigned overlay IP;
the corresponding private keys stay on that host.

## 5. Dashboard login and sessions

Provision the owner-supplied initial credential through a protected local
administration command or secret file. Store a salted Argon2id password hash;
do not embed a password or password hash in public assets, installer arguments,
source files, or release metadata. Do not trim or otherwise normalize passwords.

The proposed initial Argon2id parameters are 19 MiB memory, two iterations, and
parallelism one, followed by validation on Edge01. Use a random salt and the
standard encoded hash representation. Password verification runs off the async
request executor with bounded concurrency.

Use server-side sessions with opaque random identifiers. The production cookie
is Secure, HttpOnly, SameSite=Strict, host-only, and scoped to `/`. Store only a
digest of the session identifier. Proposed defaults are 30 minutes of inactivity
and eight hours absolute lifetime. Logout invalidates the server record.

Login and mutations use same-origin checks; authenticated mutations also require
a session-bound CSRF value. Apply bounded request bodies, login throttling, and
generic authentication failures. A browser login never returns the deployment's
shared operator token. Preserve legacy operator bearer access only as an
explicit server-side compatibility path, independent from public node admission.

Master-token management and fleet administration are authenticated in API
handlers. Hiding UI controls is not authorization. The public installation,
public join, health, and immutable release routes remain accessible as required.

## 6. Public ordinary-node onboarding

Add a versioned public join operation, separate from the legacy token-required
enrollment operation. It accepts a node-signed identity claim with a fresh
request ID/timestamp and an explicit ordinary-node intent. It cannot activate a
master, choose an arbitrary virtual IP, or grant operator privileges.

Verify identity proof, reject node-ID/key conflicts, and persist the node record.
When the node registers its distinct WireGuard public key and local network
opt-in, automatically reuse its existing allocation or assign the next free
overlay `/32`. Keep allocation and persistence serialized; duplicate/retried
requests must not consume additional addresses. Preserve revoked membership:
public re-registration cannot undo an operator revocation of the same identity.

Workload admission to a master verifies the bootstrapper-signed node membership
and the selected master binding. Public registration on the bootstrapper must
not silently convert legacy master enrollment into unauthenticated trust reset.

The coordinator returns its signed configuration, network information, and any
currently designated workload-master identity/overlay endpoint. The node pins
network trust, configures WireGuard, and then connects to an authorized master
over the overlay. No URL or secret needs to be copied by the ordinary user.

Network membership remains usable when no workload master is available. Report
`network ready / waiting for workload master` honestly; retain the network and
retry workload discovery automatically. Do not invent a successful workload
attachment. Workload opt-in and resource limits remain owned by the local user.

Keep legacy signed enrollment/heartbeat layouts unchanged. New join and role
messages have explicit versions and signature coverage rather than adding
fields to already deployed signed payloads.

## 7. Master activation

The dashboard creates a cryptographically random master activation token and
shows its plaintext once. Proposed defaults: 24-hour expiration and one device
activation. Persist only its digest plus label, creator, timestamps, revocation
state, and the eventual bound identity.

Master setup first joins the network as the host's ordinary node, then prompts
for its master token using the controlling terminal. It proves possession of
both the node key and the master's control key. The bootstrapper atomically
validates and consumes the token and records the authorized master binding.

An identical retry from the already bound identities returns the original
activation result. A different identity cannot reuse the consumed token. A lost
HTTP response or interrupted installation must not strand a valid activation.
Reject invalid, expired, revoked, or wrongly scoped tokens before starting the
master with management authority.

An unsuccessful master activation can leave the host joined as an ordinary
node, with an explicit activation failure. It must not roll back or rotate a
working node identity, and must not start an authorized master prematurely.

Persist a coordinator-signed master authorization binding for normal operation;
do not retain the enrollment token as a perpetual operator password. Include
the master identity in signed discovery so ordinary nodes can validate workload
authority. Revoking an unused token prevents activation; revoking an activated
master removes its authority and discovery entry as a distinct management action.
An online node refreshes that state through signed synchronization. During a
control outage it accepts no newly discovered master; existing workload and
lease handling retain their current policy/expiry rules.

Master authority permits the existing structured workload-management operations
for its assigned fleet. It does not imply remote shell, bootstrapper ownership,
dashboard account ownership, or an override of local workload policy.

## 8. Shared installer sequence

1. Detect OS/architecture and select a complete immutable target release.
2. Check prerequisites, existing installation, available service manager,
   routing conflicts, and required artifacts before replacing anything.
3. Obtain OS administrator elevation through sudo/UAC. Root execution satisfies
   the requirement without asking for an additional password. Never send the
   local administrator password over Lattice APIs.
4. Verify release downloads, install managed dependencies and binaries, and
   preserve existing identity, trust, IP allocation, and user policy.
5. Register/start the system services and invoke native setup over local IPC.
6. Complete public node join, automatic IP assignment, network configuration,
   and authenticated WireGuard readiness. For a master, activate its role and
   start its orchestration service on the overlay.
7. Show service status, node ID, virtual IP, role, network readiness, workload
   attachment state, and any pending action. Print success only for verified
   stages. Installed-but-not-connected is a distinct result with a nonzero
   installer exit status while the service continues bounded retries.

Read interactive input from the terminal rather than script stdin. The same
entry script must work when downloaded to disk or piped from curl. Missing
required input in noninteractive mode must fail explicitly, never loop forever.
Keep master tokens out of generated clipboard commands and process arguments.

Re-running installation is a repair/update operation, not a new identity. Use
bounded service/IPC/readiness waits instead of fixed sleeps as acceptance gates.
Keep a previous installed artifact/configuration snapshot for rollback. Do not
delete existing network state merely because a later download or health check
fails. Cleanup removes only files and interfaces owned by the installation.

## 9. Platform installation contract

| Platform | Initial targets | System integration |
| --- | --- | --- |
| macOS | arm64 and x86_64 release variants | Root-owned state under `/Library/Application Support/Lattice`, LaunchDaemons under `/Library/LaunchDaemons`, managed WireGuard tools/userspace backend, service startup before user login. |
| Linux | x86_64 and aarch64; initial automated package integration for Debian/Ubuntu with systemd | Existing `/var/lib/lattice` state, `/etc/lattice` service configuration, `lattice-node.service`, optional `lattice-master.service`, managed WireGuard tools. Unsupported package/service combinations fail preflight explicitly. |
| Windows | x86_64 | Administrator elevation, protected Program Files/ProgramData paths, managed official WireGuard installation/tunnel service, `LatticeNode`, and a master SCM host when that role is selected. |

macOS uses system LaunchDaemons, not user LaunchAgents. Handle dependency
installation without attempting to run Homebrew as root; distribute verified
managed dependencies or execute an explicitly selected package-manager step in
the invoking user's context before system installation.

Master installation includes both participating node components and orchestration
components. The master starts after overlay readiness and binds to its authorized
overlay endpoint. A master restart does not recreate the node identity or
terminate independent network membership.

Build and publish every selected target before advertising it. Missing macOS
Intel or Windows master artifacts are release blockers for those selections,
not reasons to claim cross-platform support from source alone. Native service,
elevation, and reboot acceptance are required on each advertised platform.

## 10. Site and release layout

Use one site origin and an explicit immutable release root:

```text
/                         account login / authenticated dashboard
/install                  public installation instructions
/installer/linux.sh       public Linux entry point
/installer/macos.sh       public macOS entry point
/installer/windows.ps1    public Windows entry point
/releases/<version>/<target>/...   immutable role-complete artifacts
```

An Add Node action chooses OS and ordinary/master role, then shows the matching
non-secret command. Ordinary install defaults to the public bootstrap endpoint.
Master install prompts locally for the token generated by dashboard management.
Do not require users to enter master/bootstrap URLs for the normal product flow.

Separate `site_base` from `release_root`; never derive helper-script paths by
appending `/scripts` to a base that already ends in `/releases`. Make the release
publisher produce the exact layout consumed by all installers. Stage the full
release into a temporary directory, verify checksums/completeness, and promote
it atomically. Never erase a published release before validating replacements.

Include node, worker, platform helper binaries, and selected master components.
WireGuard dependencies must have pinned provenance/version and verification.
Existing signed runtime/update validation remains active. Website HTTPS and
WireGuard UDP are separate transports; the HTTP tunnel does not replace the
existing UDP gateway ingress.

## 11. Compatibility and migration

Keep `10.77.0.0/16`, gateway `.1`, existing allocated addresses, both trust
channels, and deployed hub routing. Do not reset node or WireGuard identities.
Convert the current test/default state to explicit deployment configuration
without printing secrets or introducing a second cluster.

Replace manual site file serving with a consistent authenticated-dashboard and
public-installer route map, retaining the existing public hostname. Snapshot
the current Edge01 service/configuration and published tree first. Apply and
verify the replacement before removing the previous service or directory.

Migration of existing master hosts uses the authenticated activation mechanism;
already installed ordinary nodes retain identity/IP and can move to public join
without resetting enrollment. Keep old token enrollment available for legacy
clients during the transition. Remove normal setup's manual IP assignment,
operator-token prompt, test HTTP toggle, and per-host URL configuration.

Existing live tunnel demonstrations remain historical evidence. Deployment
acceptance for the normalized product must come from fresh installer-launched
services, not a manually started `wg-quick` interface.

## 12. Verification and completion gates

| Gate | Required evidence |
| --- | --- |
| API authorization | Account login succeeds/fails correctly; logout/session expiry works; public nodes cannot activate a master or call management APIs. |
| Public join | Empty/no enrollment token succeeds through the public node flow; identity/IP survives retry and restart; simultaneous joins receive different addresses. |
| Master tokens | Creation/list/revoke are authenticated; plaintext appears only on creation; expiry/revocation/reuse and interrupted activation behave as specified. |
| Installer harness | Piped stdin does not consume prompts; elevation is required; missing/corrupt artifacts fail before replacement; repair retains identity/policy; role/target layout matches published files. |
| Service integration | Native launchd/systemd/SCM installation, dependency installation, boot startup, and bounded recovery are demonstrated on each advertised OS. |
| Network | Fresh gateway handshake, correct overlay route, and actual authorized overlay traffic; ordinary node-to-node traffic follows the retained hub path. |
| Regression | Workspace tests, supported target checks, desktop build, existing operator controls, owner policy, signed job/manifest/update checks, and shutdown behavior remain valid. |
| Deployment | Public URL exposes login and correct public installers; fresh ordinary and master installs work from published artifacts; rollback to the prior release is available. |

Distinguish source implementation, automated tests, published artifacts, installed
services, and live acceptance in every progress report. A missing physical OS
or unavailable administrator interaction is an explicit untested gate, not PASS.

## 13. Implementation boundaries

The next implementation plan should follow these dependency boundaries:
authentication/session and master-token lifecycle; public admission and role
activation/discovery; native setup and service packaging; site/release integration;
then migration and fresh acceptance. This is sequencing guidance, not the
separate reviewed implementation plan.

Preserve all existing OpenCode work. Make targeted changes on `main`, use no
new development branch, and do not restore GitHub Actions workflows.

## References

- [Apple: Creating Launch Daemons and Agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [WireGuard for Windows: Enterprise Usage](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)
- [OWASP: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

The service and password-hashing choices follow these primary documents;
role boundaries, admission policy, migration, and sequencing are Lattice design
decisions derived from the owner's requirements and the inspected source.
