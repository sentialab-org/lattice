# Product Normalization Implementation Plan

Historical 0.2.2 plan. Global master designation is superseded by the owner's
clarification and [the master ownership plan](2026-10-15-master-ownership.md).
Do not reintroduce global designation when resuming this work.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver public automatic ordinary-node installation and dashboard-authorized master installation, with account login, stable virtual IPs, and recoverable system services across macOS, Windows, and Linux.

**Architecture:** Extend the existing bootstrapper, master, node, worker, and WireGuard hub. Add a shared signed onboarding contract and native node setup state machine, keeping OS scripts responsible for elevation, verified dependencies, and service registration. Dashboard requests reach the designated master through a narrowly scoped authenticated backend client.

**Tech Stack:** Rust 2024, Tokio, Axum, existing Ed25519/WireGuard crypto and file-backed state, RustCrypto Argon2id, Bash, PowerShell, launchd, systemd, Windows SCM, existing HTML/JavaScript dashboard and Tauri/React local desktop.

**Spec:** [Approved product normalization design](../specs/2026-10-15-product-normalization-design.md)

## Global Constraints

- Work in `/Users/zvwgvx/Project/lattice` on `main`; do not create a development branch or edit the older `/Users/zvwgvx/projects/lattice` checkout.
- Preserve the existing uncommitted OpenCode implementation and all existing identities, keys, IP allocations, policy, and workload state.
- Public ordinary-node admission requires neither an enrollment token nor manual approval. Public admission never grants management authority.
- Master setup requires a dashboard-issued token and proof of the participating node and master-control identities.
- Preserve `10.77.0.0/16`, the existing gateway/address allocations, and `A -> Edge01/RPi -> B`; do not enable direct P2P as part of this work.
- Keep separate bootstrap/network and workload-control trust. Do not modify the canonical serialization of deployed signed enrollment/heartbeat messages.
- Account username is `zvwgvx`; use the previously supplied password only through private provisioning, never repository files, logs, public artifacts, or clipboard commands.
- Password hashing uses Argon2id with 19 MiB memory, two iterations, parallelism one, and a random salt; preserve exact password bytes.
- Session inactivity is 30 minutes and absolute lifetime is eight hours; use opaque identifiers and Secure/HttpOnly/SameSite=Strict host-only production cookies.
- Master activation tokens expire after 24 hours and activate one device; identical identity-bound retries are idempotent.
- Installation requires root/sudo or Windows administrator elevation, boot services, and automatic network reconciliation.
- macOS uses root-owned `/Library/Application Support/Lattice` and `/Library/LaunchDaemons`; Linux uses `/var/lib/lattice` and `/etc/lattice`; Windows uses protected Program Files/ProgramData.
- Initial release targets: macOS arm64/x86_64, Linux x86_64/aarch64 with systemd and Debian/Ubuntu package integration, Windows x86_64. Advertise only built and verified target/role combinations.
- All repository content is English; preserve the retro monochrome console style and ports 7443/7444 from `AGENTS.md`.
- Do not restore GitHub Actions. Do not publish or change remote services merely because source checks pass; first prepare a reviewable release and rollback.

## Review Focus

1. Response lost after master-token consumption: retry by the same identities must recover the same grant; another device must be rejected. Tested in Task 4.
2. Simultaneous public joins or reinstall: IPs must remain unique and stable; a revoked identity must not regain membership by joining again. Tested in Task 3.
3. Browser requests containing manipulated target URLs or cookie-only mutations: no arbitrary proxy destination and no CSRF bypass. Tested in Tasks 1 and 5.
4. Piped installers, paths containing spaces, cancelled elevation, and unavailable stdin/TTY: finish explicitly or fail before replacing a working installation. Tested in Tasks 8-10.
5. Missing/corrupt target components or service startup without a handshake: preserve the old release and report partial failure, never installation success. Tested in Tasks 6-11 and 13.

## Baseline, preservation, and commits

The approved design is committed at `ae1d80b`, on top of `e689dce` and the preserved OpenCode working tree. The source baseline passed `cargo test --workspace --locked`: 84 passed, 0 failed, one existing ignored process fixture. This count excludes the unwired draft `tokens.rs`; it is not acceptance of the new product flow.

Before implementation, capture a protected local snapshot of the current tracked/untracked source and refs, following the existing backup at `/Users/zvwgvx/.codex/backups/lattice/20261015-103226`. Exclude runtime credentials from commits and keep runtime data/build outputs ignored. Do not use `git reset --hard`, `git clean`, blanket staging, or destructive release-directory replacement.

Before Task 1's functional edits, record a dedicated source checkpoint of the inspected OpenCode foundation, including `control/lib.rs`, `control/network.rs`, `control/network/gateway.rs`, role binaries, `node/network.rs`, and their existing protocol/crypto/state/UI/installer/docs wiring. Stage explicit paths from the preserved snapshot after the baseline test and secret check; exclude runtime data and `scripts/__pycache__`. Commit as `chore: preserve OpenCode networking foundation` so its provenance is separate from new authentication work. Subsequent task commits stage only that task's changes; use partial staging when a tracked file contains pre-existing work outside the task. Never silently leave a required untracked module out of a commit.

## File Responsibilities

| Files | Responsibility |
| --- | --- |
| `crates/lattice-protocol/src/product.rs`, `src/distribution.rs`, `src/lib.rs` | New versioned onboarding/role/setup/release types; preserve legacy signed types. |
| `crates/lattice-control/src/auth/{mod,credentials,sessions,handlers}.rs` | Password provisioning, session validation/expiry, CSRF, login/logout handlers. |
| `crates/lattice-control/src/clock.rs` | Injectable `Clock::now_ms()` for new authentication/onboarding operations and deterministic expiry tests; production uses `SystemClock`. |
| `crates/lattice-control/src/tokens.rs` | Master activation-token records, digest-only storage, atomic one-device redemption. Replace the unwired draft instead of adding a competing store. |
| `crates/lattice-control/src/onboarding.rs`, `src/masters.rs` | Public identity membership, automatic allocation, activation, signed discovery, membership proof validation. |
| `crates/lattice-control/src/network/reconcile.rs` | Gateway peer/route/firewall convergence on startup and membership changes, with applied-state reporting and rollback. |
| `crates/lattice-control/src/delegation.rs`, `src/fleet.rs` | Typed delegation and allowlisted dashboard-to-master workload requests; never an unrestricted URL proxy. |
| `crates/lattice-control/src/{lib,network,operator}.rs`, `src/bin/lattice-master.rs` | Route/state integration, role-aware authorization, existing gateway/operator compatibility. |
| `crates/lattice-node/src/{setup,setup_cli}.rs`, `src/{main,lib,enrollment,network}.rs` | Native setup via IPC, durable progress, identity/trust, readiness, retries and discovery. |
| `crates/lattice-control/src/windows_service.rs`, existing node service host | SCM integration for the master and node without another compute executor. |
| `scripts/release_manifest.py`, `scripts/publish-release.sh` | Complete target/role bundles, immutable layout, validation and atomic promotion. |
| `web/installer/{linux,macos}.sh`, `windows.ps1`, `scripts/install-*.sh`, `install-*.ps1` | Public bootstrap, elevation, managed dependencies, OS installation and rollback adapters. |
| `web/control/{auth,setup}.js`, `index.html`, `web/installer/index.html` | Account UI, role/token management, public installation instructions and non-secret commands. |
| `apps/lattice-desktop/src/App.tsx`, `src-tauri/src/lib.rs` | Local UI consumes the same setup IPC without changing saved owner policy. |
| `crates/lattice-control/tests/{support,product_*}`, `crates/lattice-node/tests/setup.rs`, `tests/installers/`, `tests/browser/` | Focused API, native setup, platform-harness and real-browser regression coverage. |

## Shared Contracts

Define these in `lattice-protocol/src/product.rs` and re-export from `lib.rs`. Use a new `PRODUCT_SCHEMA_VERSION = 1`; do not change existing `PROTOCOL_VERSION` or add fields to deployed signed claims. New envelopes sign the entire new claim, including its schema version. Credential-bearing types have redacted `Debug` implementations.

- `DashboardSession { username: String, csrf_token: String, idle_expires_at_ms: u64, absolute_expires_at_ms: u64 }` is the safe login/session JSON response. Cookie name is `lattice_session`; production requires Secure and no Domain attribute. Explicit loopback-only test configuration may omit Secure without weakening public deployment defaults.
- `NodeRole`: `Node`, `Master`, serialized as `node` and `master`; infrastructure bootstrapper provisioning is not a public setup role. New setup stages serialize as snake_case.
- `PublicJoinClaim { schema_version: u32, enrollment: EnrollmentClaim }`; `PublicJoinRequest { claim: PublicJoinClaim, signature: String }`. No role override or IP request is accepted.
- `Membership { schema_version: u32, network_id: String, node_id: String, node_public_key: String, revision: u64, issued_at_ms: u64, expires_at_ms: u64 }`; `SignedMembership { membership: Membership, signature: String }`.
- `PublicJoinResponse { receipt: EnrollmentReceipt, signature: String, membership: SignedMembership }`. The legacy enrollment receipt remains byte-compatible; membership is an independently signed addition.
- `MasterGrant { schema_version: u32, network_id: String, node_id: String, node_public_key: String, control_id: String, control_public_key: String, overlay_ipv4: String, revision: u64, issued_at_ms: u64 }`; `SignedMasterGrant { grant: MasterGrant, signature: String }`.
- `MasterActivationClaim { schema_version: u32, request_id: String, node_id: String, control_id: String, control_public_key: String, issued_at_ms: u64 }`; `MasterActivationRequest { claim: MasterActivationClaim, node_signature: String, control_signature: String, activation_token: String }`.
- `MasterDirectory { schema_version: u32, network_id: String, revision: u64, issued_at_ms: u64, active_master_id: Option<String>, masters: Vec<SignedMasterGrant> }`; `SignedMasterDirectory { directory: MasterDirectory, signature: String }`. Master overlay URLs derive from validated grant addresses and the configured port, never from browser-supplied URLs.
- `SetupOptions { role: NodeRole, bootstrap_url: String, master_token: Option<String> }`; `SetupStage`: `Preflight`, `Joining`, `Allocating`, `ApplyingNetwork`, `VerifyingNetwork`, `ActivatingMaster`, `AttachingWorkload`, `Ready`, `WaitingForMaster`, `Degraded`.
- `SetupReport { stage: SetupStage, node_id: String, virtual_ipv4: Option<String>, role: NodeRole, network_ready: bool, workload_ready: bool, error_code: Option<String> }`; no token or private key is serialized in status.

The token module produces `CreatedMasterToken { token_id: String, label: String, activation_token: String, created_at_ms: u64, expires_at_ms: u64 }` and `MasterTokenSummary { token_id: String, label: String, created_at_ms: u64, expires_at_ms: u64, revoked_at_ms: Option<u64>, activated_node_id: Option<String> }`. Persisted `MasterTokenRecord` additionally holds `token_sha256: String` and `binding: Option<ActivationBinding>`; neither digest nor plaintext is exposed in list responses. `ActivationBinding { node_id: String, node_public_key: String, control_id: String, control_public_key: String }` is immutable after first redemption. Tokens, grants, active-master selection and master revocations share one `MasterAuthorizationStore` persisted as `master-authorizations.json`; consumption and grant creation must become one atomic write, not two separately committed files.

Concrete proposed routes, all on the existing router:

| Route | Authorization |
| --- | --- |
| `POST /api/v1/auth/login`, `GET /api/v1/auth/session`, `POST /api/v1/auth/logout` | Account/session rules; no deployment operator token returned. |
| `GET/POST /api/v1/operator/master-tokens`, `POST /api/v1/operator/master-tokens/revoke` | Authenticated dashboard management; mutations require CSRF for cookie sessions. |
| `POST /api/v1/bootstrap/join` | Public signed ordinary-node proof; no enrollment token. |
| `POST /api/v1/bootstrap/activate-master` | Signed node/control proof plus activation token, or exact bound-identity recovery. |
| `POST /api/v1/bootstrap/discovery` | Existing enrolled node signature, timestamp and replay checks; signed membership/directory response. |
| `POST /api/v1/operator/masters/active`, `POST /api/v1/operator/masters/revoke` | Authenticated master management. |
| Existing operator workload routes | Authenticated session locally or scoped signed delegation on the master. |

Keep legacy `POST /api/v1/enroll` token-required and compatible. The new route carries public admission; do not make a blank legacy token an authorization bypass.

---

### Task 1: Account Login, Sessions, and Protected Management APIs

**Files:** Create the four `control/src/auth/` modules, `control/src/clock.rs`, `control/src/bin/lattice-admin.rs`, `control/tests/support/mod.rs`, and `control/tests/product_auth.rs`; modify `control/src/{lib,operator}.rs`, `control/src/network.rs`, `control/Cargo.toml`, and `Cargo.lock`.

**Interfaces:** Produce `AuthConfig`, `AuthState`, `OperatorScope::{FleetRead,TokensWrite,NetworkWrite,WorkloadRead,WorkloadWrite,MastersWrite}`, `OperatorPrincipal`, and `authorize_operator(&AppState, &HeaderMap, verified_delegation: Option<&OperatorPrincipal>, OperatorScope) -> Result<OperatorPrincipal, ApiResponseError>`. The optional delegation principal comes only from a server-side request extension created by Task 5's verifier, never an HTTP header copied into a principal; Task 1 passes `None`. Add `Clock: Send + Sync { fn now_ms(&self) -> u64; }`, `SystemClock`, and `AppState.clock: Arc<dyn Clock>`; new handlers use this clock while existing signed operations preserve their behavior. `credentials::provision(path: &Path, username: &str, password: &[u8]) -> Result<(), AuthError>` stores an encoded Argon2id hash; `AuthState::authenticate(&self, headers: &HeaderMap, scope: OperatorScope, now_ms: u64) -> Result<OperatorPrincipal, AuthError>` checks expiry/CSRF. Define `AuthError` with credential, expired, CSRF, throttled and persistence cases. Tests use `Fixture::new(role)`, `Fixture::login(user,password)`, `Fixture::advance_ms(ms)`, and `Fixture::request(method,path,json,cookie,csrf)` against a loopback Axum server with a controlled clock and temporary state. Login returns `DashboardSession`; the fixture retains the actual response cookie/CSRF values instead of inventing credentials.

- [ ] **Step 1:** Add tests `password_bytes_are_not_trimmed`, `login_sets_protected_cookie_without_operator_token`, `session_idle_and_absolute_expiry`, `logout_invalidates_cookie`, `cookie_mutation_requires_origin_and_csrf`, and `legacy_bearer_is_explicitly_separate`. Assert cookie flags; 401 after 1,800,000 ms idle or 28,800,000 ms absolute; 403 for missing/wrong CSRF or cross-origin mutation. Wrong credentials never reveal which field failed.
- [ ] **Step 2:** Run `cargo test -p lattice-control --test product_auth`; expect missing auth interfaces/routes or failing authorization assertions before implementation.
- [ ] **Step 3:** Implement the interfaces and routes, add the credential CLI with protected terminal/stdin input, bounded Argon2 verification through `spawn_blocking`, random 256-bit session IDs, digest-only session records and atomic persistence. Share authorization across network/operator handlers; add auth state through `load_state` and update every test `AppState` initializer. Preserve public join/health/release reachability and legacy behavior under an explicit compatibility setting. Never accept credentials in CLI arguments or print their values.
- [ ] **Step 4:** Run `cargo test -p lattice-control --test product_auth` and `cargo test --workspace --locked`; expect zero failures. Inspect credential/session fixture files for absence of plaintext password/session ID.
- [ ] **Step 5:** Commit explicitly reviewed foundation and auth files with `feat(auth): add account sessions and management authorization`; keep unrelated OpenCode work intact and do not stage runtime data or `scripts/__pycache__`.

### Task 2: Dashboard-Issued Master Token Lifecycle

**Files:** Replace `control/src/tokens.rs`; create `control/tests/product_tokens.rs`; modify `control/src/lib.rs`, `protocol/src/product.rs`, `protocol/src/lib.rs`, and control dependencies as needed.

**Interfaces:** Consume Task 1 authorization. Produce `TokenStore::create(label: &str, now_ms: u64) -> Result<CreatedMasterToken, TokenError>`, `list() -> Vec<MasterTokenSummary>`, `revoke(token_id: &str, now_ms: u64) -> Result<(), TokenError>`, and `redeem(token: &str, binding: &ActivationBinding, grant: SignedMasterGrant, now_ms: u64) -> Result<Redemption, TokenError>`. These are async store methods operating under one serialized store lock. `CreatedMasterToken` alone contains plaintext; persisted `MasterTokenRecord` contains digest, ID, label, created/expires/revoked timestamps and optional binding. `ActivationBinding` contains node ID/node key/control ID/control key; `Redemption { grant: SignedMasterGrant, first_use: bool }` distinguishes first use from identical retry and returns the original stored grant. Define `TokenError` cases for invalid, expired, revoked, conflicting binding and persistence failure.

- [ ] **Step 1:** Add `tokens_require_account_management`, `token_plaintext_is_creation_only`, `token_expires_after_86400000_ms`, `token_cannot_activate_two_bindings`, and `revoked_token_cannot_activate`. Inspect list and on-disk JSON to ensure neither token plaintext nor digest is returned by list APIs.
- [ ] **Step 2:** Run `cargo test -p lattice-control --test product_tokens`; expect missing routes/store or failed lifecycle assertions.
- [ ] **Step 3:** Implement the store and authenticated routes with CSPRNG-generated tokens, digest comparison, serialized mutations and durable atomic writes. Persist a candidate store image containing both token binding and grant before swapping it into memory; a failed write must not leave the token consumed only in memory. Do not migrate the old shared enrollment token into master authority. Wire the module so its tests actually execute. Add redacted credential `Debug` output and reject oversized labels/token inputs.
- [ ] **Step 4:** Run `cargo test -p lattice-control --test product_tokens`; expect zero failures including concurrent redemption of a single token by two different bindings.
- [ ] **Step 5:** Commit task paths with `feat(auth): manage one-device master activation tokens`.

### Task 3: Public Ordinary-Node Join and Automatic Stable IP Allocation

**Files:** Create `control/src/onboarding.rs`, `control/src/network/reconcile.rs`, `protocol/src/product.rs` if not already created, and `control/tests/product_join.rs`; modify control `lib.rs`/`network.rs`, node `enrollment.rs`, control Tokio process features and protocol re-exports.

**Interfaces:** Produce async `onboarding::public_join(State<AppState>, Json<PublicJoinRequest>) -> Result<Json<PublicJoinResponse>, ApiResponseError>`, async `onboarding::membership_for(&AppState, node_id: &str, now_ms: u64) -> Result<SignedMembership, ApiResponseError>`, and `network::ensure_public_allocation(&mut NetworkState, node_id: &str, wireguard_public_key: &str, now_ms: u64) -> Result<NetworkAllocation, ApiResponseError>`. Membership proof lifetime is 900,000 ms and is renewed by authenticated discovery. Add async `enrollment::join_public(client: &Client, identity: &IdentityState, bootstrap_url: &str) -> Result<BootstrapTrust, String>`. Define an onboarding directory with explicit ordinary membership and revocation state; do not change signed legacy claim layouts. Add async `reconcile::run(state: Arc<AppState>, shutdown: watch::Receiver<bool>)` and `reconcile_once(state: &AppState, runner: &dyn GatewayCommandRunner) -> Result<GatewayApplyReport, GatewayError>`; define runner methods for executing typed `GatewayCommand` values, never a remote shell/string command. The report includes desired/applied revision and a redacted error code.

- [ ] **Step 1:** Add `public_join_needs_no_token`, `public_join_cannot_request_master_or_ip`, `join_retries_preserve_identity_and_ip`, `simultaneous_joins_allocate_unique_ips`, `concurrent_reuse_of_wireguard_key_accepts_one_node`, `public_rejoin_does_not_reverse_revocation`, and `legacy_enroll_still_requires_token`. Use `10.77.0.0/16` with gateway `.1`; 50 concurrent identities must receive 50 distinct non-gateway `/32`s after network registration. Add `gateway_applies_new_peer_without_manual_command`, `revoke_removes_live_peer_before_reporting_applied`, and `failed_gateway_apply_preserves_previous_config_and_reports_degraded` with a recording command runner.
- [ ] **Step 2:** Run `cargo test -p lattice-control --test product_join`; expect 404/public-token failure or allocation pending rather than allocated.
- [ ] **Step 3:** Implement signed public join, node-ID/key conflict checks, bounded payloads, timestamp/replay validation and digest-free public responses. New public request types reject unknown fields, including attempted role/IP overrides. Automatic allocation occurs only after a registered node proves its WireGuard key and opts in. Check key uniqueness and allocate under the same write lock. Keep persistence idempotent; a partial node/directory write must be repaired by an identical retry. Trigger a separate local gateway task on register/assign/revoke and on startup, with a bounded periodic retry if a notification is missed. Reuse the gateway renderer, validate/snapshot owned configuration, and use `wg syncconf` for live peer changes without bringing down unrelated tunnels. Scope route/firewall application to the owned overlay, retain the previous working state on failure, and never expose private config in status. Gateway application must be explicitly enabled on the operator host; unavailable privileges remain a failed/pending apply gate, not a success. Retain existing allocated/revoked state and operator address management.
- [ ] **Step 4:** Run `cargo test -p lattice-control --test product_join` and `cargo test -p lattice-control network::tests`; expect zero failures. Serialize legacy enrollment/heartbeat fixtures before/after and assert identical bytes/signatures.
- [ ] **Step 5:** Commit task paths with `feat(onboarding): add public node admission and automatic IPAM`.

### Task 4: Identity-Bound Master Activation and Signed Discovery

**Files:** Create `control/src/masters.rs`, `control/tests/product_masters.rs`; modify control `lib.rs`, `onboarding.rs`, `tokens.rs`, node `enrollment.rs`/`identity.rs`, and protocol product types.

**Interfaces:** Produce async `masters::activate(&AppState, MasterActivationRequest, now_ms: u64) -> Result<SignedMasterGrant, ApiResponseError>`, async `masters::directory(&AppState, now_ms: u64) -> Result<SignedMasterDirectory, ApiResponseError>`, and `masters::verify_membership(&SignedMembership, coordinator_key: &str, expected_network: &str, now_ms: u64) -> Result<Membership, ActivationError>`. Define `ActivationError` for signature/binding/network/expiry/revocation failures. `MasterRegistry` is a view over the grants, per-master revocation and active-master fields in Task 2's shared `MasterAuthorizationStore`, not another independently persisted file. Membership and active-master discovery are refreshed on each network discovery cycle; expiry fails closed for new authority.

- [ ] **Step 1:** Add `activation_proves_both_keys`, `activation_retry_after_lost_response_returns_same_grant`, `another_device_cannot_redeem_consumed_token`, `activation_does_not_create_second_node_or_ip`, `revoked_master_disappears_from_discovery`, and `workload_admission_rejects_wrong_network_or_expired_membership`. Concurrent consumption must yield exactly one binding; revoke must not change the host's ordinary IP allocation.
- [ ] **Step 2:** Run `cargo test -p lattice-control --test product_masters`; expect missing activation/discovery or failed binding assertions.
- [ ] **Step 3:** Implement atomic activation recovery with both signatures and token validation. Bind a grant to the already allocated overlay IP. An identical signed identity pair can recover its existing grant after a lost response without requiring plaintext token retention. Different identities cannot recover it. Implement authenticated designation/revocation routes and signed directory lookup; verify membership plus the designated master binding during new workload enrollment. Leave existing lease/policy/expiry behavior intact.
- [ ] **Step 4:** Run `cargo test -p lattice-control --test product_masters` and `cargo test -p lattice-node enrollment::tests`; expect zero failures, including restart between redemption and response recovery.
- [ ] **Step 5:** Commit task paths with `feat(master): activate and discover identity-bound management nodes`.

### Task 5: Central Fleet API and Scoped Dashboard-to-Master Delegation

**Files:** Create `control/src/delegation.rs`, `control/src/fleet.rs`, and `control/tests/product_fleet.rs`; modify existing `lib.rs`, `operator.rs`, `network.rs` authorization and product types.

**Interfaces:** Produce `WorkloadOperation::{ListJobs,ListRuntimes,ListArtifacts,PublishRuntime { version: String, platform: Platform, architecture: Architecture },QueueMining,ControlJob,CancelJob}`, `OperatorDelegation { schema_version, request_id, network_id, master_control_id, operation, request_sha256, issued_at_ms, expires_at_ms }`, and its signed envelope. Use `u32` for schema version, `u64` timestamps, `WorkloadOperation` for operation, and `String` for other fields. `delegation::verify(&AppState, &SignedOperatorDelegation, operation: WorkloadOperation, body_sha256: &str, now_ms: u64) -> Result<OperatorPrincipal, ApiResponseError>` checks a 60,000 ms lifetime and replay binding. Async `fleet::forward(state: &AppState, operation: WorkloadOperation, body: Bytes) -> Result<Response, ApiResponseError>` derives the destination/path only from the valid designated grant and typed operation. Carry the encoded signed envelope in `X-Lattice-Delegation`; it is not a trusted principal until signature, route, body and scope verification succeeds.

- [ ] **Step 1:** Add `central_inventory_includes_bootstrapper_master_and_node`, `delegation_cannot_change_operation_body_or_master`, `expired_or_replayed_delegation_is_rejected`, `browser_url_cannot_select_proxy_destination`, and `bootstrapper_never_signs_job_lease`. A permitted request is executed/signed by the master; a user-supplied URL must never trigger an outbound request.
- [ ] **Step 2:** Run `cargo test -p lattice-control --test product_fleet`; expect missing fleet delegation or failed authorization assertions.
- [ ] **Step 3:** Implement typed backend dispatch, request-body digest binding and deduplicated request IDs. On master workload routes, bounded middleware verifies the exact outbound bytes and canonical typed route, restores the body for existing JSON/binary handlers, and inserts the verified principal as a request extension consumed by Task 1 authorization. Reject spoofed delegation/principal headers. Permit identical safe retries without issuing duplicate jobs; changed request content under the same ID is rejected. Keep central login credentials on Edge01. Expose consistent role/IP/capability/status inventory without gateway private config, runtime secrets or bearer tokens. Do not replace structured workload validation with generic proxying.
- [ ] **Step 4:** Run `cargo test -p lattice-control --test product_fleet` plus existing operator/job tests; expect zero failures and no secret fields in central responses.
- [ ] **Step 5:** Commit task paths with `feat(fleet): route authenticated workload controls to authorized masters`.

### Task 6: Native Setup CLI, IPC, Durable Stages, and Honest Readiness

**Files:** Create node `src/setup.rs`, `src/setup_cli.rs`, `tests/setup.rs`; modify node `main.rs`, `lib.rs`, `identity.rs`, `enrollment.rs`, `network.rs`, protocol product types and IPC variants.

**Interfaces:** Produce crate-visible async functions `setup::begin(state: Arc<AppState>, options: SetupOptions) -> Result<SetupReport, SetupError>` and `setup::status(state: &AppState) -> SetupReport`, plus async `setup_cli::run(args: &[String]) -> Result<i32, SetupError>`. `begin` starts/resumes one daemon-owned setup task and returns its current stage; the CLI polls status with the requested bounded timeout. Define `SetupError` with preflight, identity, join, allocation, network, activation, timeout and persistence cases. Add `IpcRequest::BeginSetup { options }`/`GetSetupStatus` and `IpcResponse::SetupStatus(SetupReport)`. CLI: `lattice-node setup --role node|master --bootstrap-url <url> --timeout-secs 120 --json`; master secret comes from a protected TTY or explicit `--master-token-stdin`, never an argument value. Use the configured IPC endpoint and a daemon-owned setup state machine, not a second daemon process.

- [ ] **Step 1:** Add `ordinary_setup_sends_no_token`, `master_setup_never_logs_secret`, `service_without_handshake_is_not_ready`, `setup_retry_preserves_identity_policy_and_ip`, `no_master_reports_waiting_without_tearing_down_network`, and `interrupted_master_recovers_grant_without_saved_token`. Use fake coordinator/IPC/network probes and assert persisted status excludes token/private-key fields.
- [ ] **Step 2:** Run `cargo test -p lattice-node --test setup`; expect missing CLI/IPC/state machine or incorrect readiness stages.
- [ ] **Step 3:** Implement staged setup with bounded waits, persistent non-secret progress, public join, network opt-in, automatic allocation and verified gateway readiness. Persist activation intent before sending its request; recover a bound grant without keeping plaintext token. Discover/attach only the authorized master after the tunnel is ready. Require actual overlay traffic/route evidence in addition to a handshake. Keep independent heartbeat/update/workload supervision running through degraded setup. CLI exits 0 for `Ready`, 2 for `WaitingForMaster`, and 1 for degraded/error/timeout; status explains which stages succeeded while service retries continue.
- [ ] **Step 4:** Run `cargo test -p lattice-node --test setup`, existing network/enrollment tests, and `cargo run -p lattice-node -- setup --help`; expect zero failures, stable JSON field names, and no secret-bearing flags in help/output.
- [ ] **Step 5:** Commit task paths with `feat(setup): coordinate native automatic node and master onboarding`.

### Task 7: Complete Release Bundles and Atomic Distribution Layout

**Files:** Create `protocol/src/distribution.rs`, `scripts/release_manifest.py`, `tests/installers/test_release.py`; modify `scripts/publish-release.sh` and release documentation.

**Interfaces:** Produce `ReleaseBundleManifest { schema_version: u32, version: String, target: String, role: NodeRole, files: Vec<BundleFile> }`, where `BundleFile { path: String, sha256: String, size_bytes: u64, executable: bool }`. Bundle paths are `/releases/<version>/<target>/node.tar.gz` or `master.tar.gz` for Unix and `.zip` for Windows, each with a checksum sidecar. Keep legacy loose binary URLs available. `release_manifest.py assemble --version <semver> --out <path> --targets <list>` stages validated artifacts; `validate --root <path>` checks completeness/hashes/layout; `promote --staged <path> --out <path>` performs atomic replacement with a rollback directory. Shell publisher delegates to this tool.

- [ ] **Step 1:** Add `missing_worker_or_update_helper_blocks_publish`, `corrupt_bundle_blocks_promotion`, `archive_rejects_absolute_parent_or_link_entries`, `missing_target_is_not_advertised`, `legacy_binary_paths_remain_available`, and `failed_assembly_keeps_existing_release`. Fixtures use tiny inert files, not real deployment artifacts.
- [ ] **Step 2:** Run `python3 -m unittest discover -s tests/installers -p test_release.py`; expect missing assembler or incomplete-output assertions to fail.
- [ ] **Step 3:** Implement protected temporary staging and explicit allowlisted archive contents. Include node/worker, Windows update helper, selected master binaries, matching service installers and verified managed WireGuard dependencies. Preserve and rebuild the existing loose bootstrapper/control artifacts for Edge01 from the same source revision, even though bootstrapper is not a public setup role. Build/pin dependencies with provenance and ship applicable notices. Do not invoke Homebrew as root. Require every target/role bundle and checksum before promotion; reject unsafe output roots and do not recursively delete an existing published tree. Publish a plain validated semantic-version pointer at `/releases/stable` only after complete promotion.
- [ ] **Step 4:** Run the release tests and `bash -n scripts/publish-release.sh`; expect zero failures. Validate an assembled fixture release and prove a failed promotion leaves the old fixture's hash unchanged. Real missing target artifacts remain explicit release blockers.
- [ ] **Step 5:** Commit task paths with `feat(release): assemble verified complete role bundles atomically`.

### Task 8: System-Level Linux Ordinary/Master Installer

**Files:** Modify `web/installer/linux.sh`, `scripts/install-node-linux.sh`, `scripts/install-bootstrapper-linux.sh`; create `scripts/install-master-linux.sh` and `tests/installers/test_linux.py`.

**Interfaces:** Consume Task 7 bundle layout and Task 6 setup CLI. Produce a public entry script with `LATTICE_SITE_BASE` default `https://lattice.sentialab.org`, `LATTICE_ROLE=node|master`, `LATTICE_NONINTERACTIVE=0|1`, and a validated explicit version or stable pointer. Internal installers accept `--artifact-dir`, `--role`, and `--bootstrap-url`; production paths are fixed, with sandbox path overrides available only to the test harness. Master tokens are requested by native setup after elevation. Linux node/master units use the existing root-owned state and network-online ordering.

- [ ] **Step 1:** Add `curl_pipe_reads_prompts_from_tty`, `noninteractive_missing_input_fails_without_loop`, `sudo_cancelled_does_not_replace_binaries`, `downloaded_helper_paths_are_self_contained`, `paths_with_spaces_are_preserved`, `node_installs_without_token`, `master_requires_activation`, and `failed_health_restores_old_service_and_files`. Harness shims sudo/systemctl/package tools and uses a PTY plus disposable paths; it must not change host services.
- [ ] **Step 2:** Run `python3 -m unittest discover -s tests/installers -p test_linux.py`; expect current piped-input/elevation/layout/readiness behavior to fail.
- [ ] **Step 3:** Implement a downloaded-to-disk/elevated continuation, terminal-safe prompts, verified extraction, Debian/Ubuntu dependency handling, owned service/unit/env files, bounded setup and rollback. Preserve node/WireGuard keys and policy on repair; master adds only its orchestration service. Keep bootstrapper provisioning in the separate operator script, not the public role selector; its system service explicitly enables Task 3's persistent gateway reconciler rather than relying on a one-time apply. Never alter the default route or apply unrelated firewall rules.
- [ ] **Step 4:** Run the harness and `bash -n web/installer/linux.sh scripts/install-node-linux.sh scripts/install-master-linux.sh scripts/install-bootstrapper-linux.sh`; expect zero failures. Test actual systemd install/reboot in the existing Linux VM only during Task 13's controlled acceptance.
- [ ] **Step 5:** Commit task paths with `feat(installer): automate elevated Linux node and master setup`.

### Task 9: macOS Root Daemons and Complete Ordinary/Master Installation

**Files:** Create `web/installer/macos.sh`, `scripts/install-node-macos.sh`, `tests/installers/test_macos.py`; replace `scripts/install-master-macos.sh`; modify node `config_path()` and installation migration code only where required.

**Interfaces:** Consume the same public installer variables, release manifest and setup CLI as Task 8. Produce root-owned `com.lattice.node` and optional `com.lattice.master` LaunchDaemons, explicit system config/socket paths, and managed WireGuard command paths. The legacy master script delegates to the complete installer with `--role master`; it must not create another identity or omit the node/tunnel.

- [ ] **Step 1:** Add `launchdaemon_starts_before_login`, `space_containing_application_support_path_is_valid_xml`, `root_installer_never_runs_brew_as_root`, `legacy_user_identity_moves_with_original_retained`, `root_service_can_query_and_restore_wireguard`, and `master_repair_does_not_duplicate_node_or_executor`. Parse generated plist files, inspect program arguments/ownership intent and use launchctl/WireGuard shims in the harness.
- [ ] **Step 2:** Run `python3 -m unittest discover -s tests/installers -p test_macos.py`; expect missing ordinary installer or LaunchAgent/system-state assertions to fail.
- [ ] **Step 3:** Implement protected system paths, verified managed dependencies, `launchctl bootstrap system`/`bootout` lifecycle, escaped plist values and bounded service health. Detect the invoking user's legacy state and copy/verify it before switching; keep the original recoverable. Propagate `LATTICE_CONFIG`, IPC path and managed `wg`/`wg-quick` paths consistently to services, desktop and native setup. Start master only after network activation; no login session or manual post-install `wg-quick` is required.
- [ ] **Step 4:** Run the harness, `bash -n web/installer/macos.sh scripts/install-node-macos.sh scripts/install-master-macos.sh`, and `plutil -lint` on fixture plists; expect zero failures. Native administrator/reboot acceptance stays a separate gate, never a mock PASS.
- [ ] **Step 5:** Commit task paths with `feat(installer): install macOS network services as system daemons`.

### Task 10: Windows UAC, Managed WireGuard, and Master SCM Hosting

**Files:** Modify `web/installer/windows.ps1`, `scripts/install-node-windows.ps1`, node service integration and control role entry point; create `scripts/install-master-windows.ps1`, `control/src/windows_service.rs`, and `tests/installers/windows.Tests.ps1`; update platform-specific Cargo dependencies.

**Interfaces:** Public PowerShell uses the same site/version/role contract. The elevated disk-backed installer consumes `-ArtifactDir`, `-Role`, `-BootstrapUrl`; secrets are entered after elevation. Add `lattice-master --service|--install-service|--start-service|--stop-service|--uninstall-service` with service name `LatticeMaster`, retaining the existing `LatticeNode` service and independent worker lifecycle. Configure master startup dependency/readiness without creating a second node process.

- [ ] **Step 1:** Add Pester cases `UacCancellationLeavesExistingInstallation`, `PipelineInvocationRelaunchesProtectedDiskScript`, `WireGuardDependencyInstalledAndVerified`, `NodeBundleIncludesUpdateHelper`, `TokenNotInRelaunchArgumentsOrTranscript`, `ScmFailureRestoresPreviousArtifacts`, and `MasterDoesNotStartBeforeOverlayAuthorization`.
- [ ] **Step 2:** Run `Invoke-Pester -Path tests/installers/windows.Tests.ps1 -CI` in Windows; expect the existing assumed-elevation/manual-dependency behavior to fail. If PowerShell/Windows is unavailable, record the gate as unavailable rather than passing it with Bash checks.
- [ ] **Step 3:** Implement UAC continuation, signed/verified managed WireGuard installation, protected ACLs, explicit subprocess exit checks, service recovery policy and transactional repair. Reuse the existing Windows service-host pattern for the master. Include the update helper and preserve its rollback integration. Never set machine-wide test HTTP flags as a normal installer side effect.
- [ ] **Step 4:** Run Pester, `cargo check --workspace --locked --target x86_64-pc-windows-gnu`, and the controlled Windows service install/restart checks; require zero failures. A compile check alone is not SCM/UAC acceptance.
- [ ] **Step 5:** Commit task paths with `feat(installer): automate Windows elevation dependencies and master services`.

### Task 11: Same-Origin Dashboard Login, Tokens, and Installation UI

**Files:** Modify `web/control/index.html`, create `web/control/auth.js`, `web/control/setup.js`, and `tests/browser/{package.json,package-lock.json,playwright.config.mjs,control-auth.spec.mjs}`; modify control route/static asset integration and `web/installer/{index.html,README.md}`.

**Interfaces:** `auth.js` exports `login`, `logout`, `loadSession`, and `authenticatedFetch(path, init)`; the last uses same-origin cookies and the current session CSRF value, never browser-stored deployment tokens. `setup.js` exports pure `buildInstallCommand({siteBase,os,role,version}) -> string` and token-management UI actions. Serve `/install`, three public OS entry scripts and immutable release assets from an explicit release root, alongside protected account/management APIs.

- [ ] **Step 1:** Add a minimal locked Playwright test package and local test-server fixture, then real-browser tests for login/logout and unauthorized direct management access; master-token creation/list/revoke; ordinary installation with no token field; all three OS command selections; no secret in clipboard/URL/storage; expired-session return to login; and central fleet role/IP inventory. Include a malformed site URL test proving command generation cannot inject a shell/PowerShell expression. Install only this test package's locked dependencies and required test browser during execution.
- [ ] **Step 2:** Run `npm --prefix tests/browser test`; expect missing login/session/static routes or existing bearer-prompt behavior to fail. Browser fixtures use temporary local test credentials, not the owner's credential or production services.
- [ ] **Step 3:** Implement the account view and authenticated console without redesigning the approved visual style. Preserve existing controls through Task 5's same-origin backend, remove manual cross-origin network-token setup from the normal flow, and show role prefixes plus independent service/network/workload readiness. Public install scripts remain reachable while logged out. Master token plaintext appears once and is entered locally, never embedded in copied commands.
- [ ] **Step 4:** Run browser tests, syntax-check the served JavaScript, and capture/render desktop and narrow-screen states. Verify login, Add Node OS/role selection, token lifecycle and existing job actions against the real local server; inspect screenshots before acceptance.
- [ ] **Step 5:** Commit task paths with `feat(console): unify account login role activation and installation flows`.

### Task 12: Local Desktop Uses Shared Setup and Preserves Owner Control

**Files:** Modify `apps/lattice-desktop/src/App.tsx`, `src-tauri/src/lib.rs`, and local node-console enrollment UI where it duplicates ordinary-token setup; add focused IPC/command mapping tests alongside the Rust Tauri bridge.

**Interfaces:** Consume `BeginSetup`, `GetSetupStatus`, and `SetupReport` from Task 6. Add async Tauri commands `setup_node(options: SetupOptions) -> Result<SetupReport, String>` and `get_setup_status() -> Result<SetupReport, String>` that delegate to local IPC, not direct identity-file editing. The UI starts setup once and polls status; it does not block the UI on the full readiness timeout. The web node console calls its loopback bridge for the same request/status operations; it never becomes a public management server.

- [ ] **Step 1:** Add tests that ordinary setup omits token input, master activation requires its token, setup reports contain no secret, and repair does not overwrite saved CPU/memory/workload policy or pinned trust. Assert both local surfaces display `WaitingForMaster` separately from network failure.
- [ ] **Step 2:** Run the bridge tests; expect missing setup command/IPC mapping or old token-required ordinary enrollment to fail.
- [ ] **Step 3:** Wire the shared workflow into the existing UI and bridge, retain reset/diagnostics and explicit owner workload controls, and align the system IPC/config path introduced on macOS. Keep port 7444 loopback-only. Do not introduce a second daemon when opening the desktop app.
- [ ] **Step 4:** Run `cargo test --manifest-path apps/lattice-desktop/src-tauri/Cargo.toml` and `npm --prefix apps/lattice-desktop run build`; require zero failures. Exercise real IPC-to-daemon setup with fixture credentials before reporting UI integration complete.
- [ ] **Step 5:** Commit task paths with `feat(desktop): reuse native setup without changing owner policy`.

### Task 13: Migration, Release Review, and Fresh End-to-End Acceptance

**Files:** Update `README.md`, `docs/{network-convergence,release-distribution,control-plane}.md`; create `scripts/verify-installation.sh`, `scripts/verify-installation.ps1`, and `docs/product-normalization-acceptance.md`; preserve any pre-existing documentation edits during reconciliation.

**Interfaces:** Verification commands output a redacted report with `source_revision`, `artifact_sha256`, OS/role/service state, node ID/IP, handshake age, actual overlay probe result, workload attachment state, and explicit pass/fail/not-tested gates. Acceptance records distinguish historical OpenCode results from the new installer-launched run.

- [ ] **Step 1:** Add harness cases `verification_rejects_service_only_success`, `verification_rejects_stale_handshake_or_wrong_route`, `reinstall_keeps_identity_ip_and_policy`, and `rollback_restores_prior_release_after_gateway_or_service_failure`; fail the report if a mandatory field is inferred rather than observed.
- [ ] **Step 2:** Run the verification harness and intentionally feed incomplete fixture reports; expect failure for service-only, stale-handshake and missing-artifact inputs.
- [ ] **Step 3:** Reconcile docs against implemented behavior, collect a complete immutable release and protected backups of Edge01 service/configuration/published files, and prepare the exact deployment and rollback actions. Keep the current gateway IP/keys and overlay allocation store. Provision the previously supplied account privately; do not request or print the owner's sudo password. Obtain the owner's review of the concrete release/deployment actions if publishing is not already authorized for that run.
- [ ] **Step 4:** Run workspace tests/checks, supported Windows/Linux target checks, desktop build, installer harnesses and browser flows. On actual machines, install ordinary and master from the staged/published entry scripts, reboot/restart, disconnect/reconnect, verify overlay ping and an authorized TCP connection across the hub, then test revoked master authority. Record each OS/architecture separately. Build missing release artifacts rather than reusing stale target directories; unavailable OS/admin/remote access remains NOT TESTED.
- [ ] **Step 5:** After all available gates pass, commit only reviewed implementation/docs and report any remaining physical gates. Publish/deploy only the reviewed release with rollback ready; fresh live acceptance must succeed before calling the normalized product delivered. Do not claim release completion from the earlier 84-test baseline or hand-started tunnels.

## Plan Self-Review and Execution Handoff

- Spec sections 1-4 map to Tasks 3-6 and 11-12; account/session requirements map to Task 1; token lifecycle to Tasks 2 and 4; delegation/fleet to Task 5.
- Spec sections 8-10 map to Tasks 6-11; compatibility and migration map to Tasks 3-6 and 13; verification/completion gates map to every task's tests and Task 13's physical acceptance.
- All five Review Focus cases have named tests in their owning tasks. Existing signed formats, local policy, deployment topology and the public-join decision are explicit constraints, not optional follow-up work.
- Native execution is recommended because these tasks share protocol/auth/setup interfaces and the working tree contains substantial preserved work. A single implementer can track those dependencies and staging boundaries; obtain an independent final review after implementation.
- Required next step: the owner reviews this plan and selects native execution or subagent-driven execution before implementation. This plan is not a record of completed code changes.
