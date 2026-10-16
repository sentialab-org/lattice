# Lattice Four-Role Architecture and Offline Authorization
**Status:** Design updated with owner decisions; runtime and protocol implementation pending
**Date:** 2026-10-16
**Baseline reviewed:** local `main` at `f7c4aa1`; current Linux runtime 0.3.2
**Scope:** network roles, offline trust, relay forwarding, audit continuity, device placement, migration and acceptance

## 1. Executive summary

Lattice should distinguish four public-facing infrastructure roles:

1. **Supervisor** — the network authority for identity, membership, master and relay authorization, bootstrap/discovery, allocation and signed audit checkpoints.
2. **Relay** — an ordinary participating node with an **additional, separately authorized network-forwarding capability**. It can also accept permitted workloads.
3. **Master** — an ordinary participating node with an **additional, independently authorized workload-controller capability**. It can also run ordinary-node workloads.
4. **Node** — an ordinary participant with local resource policies, network connectivity, workload runtime and an owner-selected workload master.

The core trust principle is that **the Supervisor issues authority; the destination Node independently verifies that authority**. A Relay forwards authorized network traffic but is not responsible for deciding whether a received workload command may execute. The Supervisor must not be an online dependency for every packet or every command.

The owner clarified two architecture decisions on 2026-10-16:

- **All supported commands must work without a live Supervisor**, including new workloads and changes to existing workloads, within the issuing Master's authority and the receiving owner's policy. Do not limit offline use to existing jobs or impose the previously proposed 15-minute window.
- **Every participating installation starts as an ordinary Base Node.** A protected local special-status control enables separately authorized Master, Relay or Supervisor modules. The Base Node retains one network manager; modules do not each create or reconcile their own WireGuard interfaces.

Nodes retain the authentic **public** Supervisor key. After Master registration, the Supervisor signs the Master's identity/key authorization and distributes it to Relays and online Nodes. The Master can also present that unchanged signed authorization with a command, allowing offline verification by a Node that missed the announcement.

The existing 0.3.2 implementation supports signed master grants and explicit local Master choice, but still requires a directory no older than **120 seconds**. Its membership and master-server authorization also have online/freshness dependencies. These must be refactored coherently; this design is not implemented by deleting one timeout.

This is a design update, not a claim that the running Linux pilot has acquired offline authorization or the new module lifecycle.

## 2. Terminology and responsibility boundaries

| Role | Identity and authority | Network responsibilities | Workload responsibilities |
| --- | --- | --- | --- |
| Supervisor | Root of trust, public key directory, signed grants, revocation, bootstrap, audit checkpoints | Publishes signed membership, routes and relay discovery metadata; may co-host a Relay | Does not implicitly command all Nodes |
| Relay | Registered Node plus separately signed relay authorization and scope | Forwards and accounts for overlay traffic; advertises verified endpoint and capabilities | Retains regular Node ability to accept work subject to local policy |
| Master | Registered Node plus identity-bound MasterGrant | Uses overlay/P2P/Relay transport as an ordinary Node | Signs typed workload requests for explicitly attached Nodes; schedules and monitors jobs |
| Node | Registered participant with its own private keys and consent | Connects to the overlay and optionally supports direct P2P | Selects one Master locally, verifies each command, enforces local policy and resource limits |

### 2.1 Composition, not four incompatible device implementations

- **Base Node** is the common client/runtime foundation.
- **Relay** = Base Node + `relay_forwarding` capability.
- **Master** = Base Node + `workload_master` capability.
- One physical device may carry Node + Relay + Master capabilities when explicitly authorized.
- **Supervisor** is a separately provisioned authority module/service on the same Base Node foundation. Its signing keys and authority remain isolated from the client, Relay and Master modules; enabling a local flag cannot create a trusted Supervisor identity.
- `lattice-worker` remains a workload-execution process and **is not a fifth network role**.
- User-facing role labels and internal capability flags must not be conflated. Capability authorization is explicit, scoped and revocable.

### 2.1.1 Module activation and host networking

Install and run one Base Node per host. Its protected local special-status controls enable a set of capabilities, rather than replacing the node with a different device identity:

```text
Base Node
  + identity, consent, local owner policy, workload runtime
  + persistent certificate/revocation store
  + one privileged NetworkManager
  + optional Master module
  + optional Relay module
  + explicitly provisioned Supervisor module
```

The module lifecycle is `disabled -> verifying -> starting -> active`, with explicit `suspended`, `revoked` and `failed` states. Persist enabled capabilities and their verified grant references atomically. Starting a module requires installed verified components, owner opt-in and the appropriate signed capability. A previously issued certificate can be activated locally without a live Supervisor; a bare checkbox or an unredeemed activation token is not a signed grant.

**Only the Base Node NetworkManager may mutate the managed WireGuard interface, transport keys, addresses, peers, routes, forwarding rules and firewall.** It is one process/owner per host, with a protected singleton lock. Master, Relay and Supervisor services submit typed desired-state requests over protected local IPC; they never invoke competing `wg-quick`, `wg syncconf`, route or firewall reconcilers. NetworkManager validates and serializes requests, merges the capability configuration, applies it transactionally and reports the applied revision.

Activating Relay adds authorized forwarding to that existing interface. Activating Master adds scheduling and signed command handling. Activating Supervisor adds authority issuance/distribution. None of these transitions regenerates the Base Node identity, transport key or allocated IP. Disabling or revoking one module withdraws only its capability and owned network rules; the ordinary node and other valid modules continue operating.

The authority service remains decoupled from the node client and its workload executor. Optional modules may be separate supervised processes with separate data directories; they do not gain direct network-management ownership. When Supervisor and Master share a host, use one control ingress on port **7443** with separate namespaces/private backends, rather than two listeners competing for that port. The local Node console remains on **7444**.

A migration must transfer the current gateway reconciler's ownership to NetworkManager without running both writers. Persist a handoff marker and applied configuration; verify exclusive ownership before enabling forwarding, and retain a rollback path.

### 2.2 Ownership model

Keep the currently approved contract: **one configured master-owner dashboard account can activate multiple concurrent Master devices**. An activation token is single-use and device-bound. Each Master retains a Supervisor-signed grant, not the dashboard password.

Each ordinary Node owner chooses **one workload Master** at a time. Supervisor authorization makes a Master eligible; it does **not** automatically attach any Node to that Master. Do not introduce automatic reassignment on Master failure. A selected Master cannot override local resource limits, owner consent, or an active lease's immutable trust relationship.

A Supervisor may deny network membership or relay/master privileges according to signed policy, but it is **not** a universal remote-workload administrator.

## 3. Identity and certificate model

### 3.1 Independent identities

Every participant generates and retains its own signing identity locally. WireGuard transport keys are separate from identity signing keys. No Master, Relay, or ordinary Node gives its private identity key to the Supervisor. The Supervisor retains its own root/trust-signing material in protected storage, with planned key rotation and recovery.

The device's stable `node_id`, identity key, WireGuard key, membership record and allocated `10.77.x.x` address must survive role upgrades, reinstalls and permitted migrations.

### 3.2 Proposed signed records

Define versioned, domain-separated signed envelopes using deterministic canonical encoding, explicit `network_id`, `schema_version` and `issuer_key_id`.

**MembershipCertificate**
- `node_id`, `identity_public_key`, `network_id`, stable overlay address.
- `issued_at`, `not_before`, explicit validity policy and `membership_revision`. Existing 15-minute membership receipts must not remain an implicit online-renewal dependency for offline commands.
- Supervisor signature; optional accepted-participation version/digest binding.

**MasterGrant**
- Existing identity binding: `node_id`, node key, `control_id`, control key and overlay address.
- Add explicit `grant_id`, `not_before`, `authority_epoch`, constrained operation scopes and issuer key ID. Grant validity must be separate from directory age; do not derive expiry from the last Supervisor contact. An optional signed expiry is a separate explicit credential policy, not a hidden offline timeout.
- Signed by the Supervisor; independent grant and revocation for each concurrent Master.
- The one-time activation token remains a bootstrap credential; it is never needed in workload requests.

**RelayGrant**
- `node_id`, transport identity/key binding, `relay_id`, permitted forwarding scope, endpoint identity, bandwidth class and an explicit credential validity policy independent of directory age.
- Scope binds routing responsibility to a Node but does **not** authorize workload control.
- Owner must separately opt in to forwarding, quotas and acceptable resource usage.

**SignedAuthoritySnapshot**
- `network_id`, monotonic `authority_epoch`, `directory_revision`, `issued_at`, issuer key ID and signed grants/revocations. Discovery hints can have refresh times; their age alone does not invalidate an independently verified grant.
- Eligible Masters and Relays, each record's validity and relevant revocations.
- Signature over the **entire** snapshot. Consumers persist the newest validated snapshot atomically and reject rollback or conflicting equal-revision content.
- If compressed or represented as a Merkle structure, proofs must authenticate the same root and revision. A fresh full snapshot is not mandatory for every command: a presented Supervisor-signed grant and persisted known revocations support local verification.

**OwnerMasterChoice**
- Existing `MasterChoice { control_id: Option<String>, revision: u64 }` stored in protected local state and signed in discovery claims.
- Only an authenticated local owner action may change the choice.
- Never treat a Supervisor recommendation, unsigned discovery field, previous automatic pin, or Relay hint as owner approval.

**SignedWorkloadCommand**
- `network_id`, `issuer_control_id`, `target_node_id`, `command_id`, `sequence` or nonce, issue/expiry timestamps, typed operation and payload digest, relevant lease ID and authorization context.
- Signed by the issuing Master identity and accompanied by, or referencing, its Supervisor-signed grant. Node validates the command signature, replay protection, target/network, correct Master choice and local policy. Existing-job commands bind the appropriate lease; new jobs create a lease after authorization. No live Supervisor lookup is part of this check.
- Raw arbitrary shell commands are outside the permitted operation model.

These are **proposed protocol extensions**, not assertions that the present Rust structs already contain every field.

### 3.3 Trust bootstrap

A previously admitted Node pins the authentic Supervisor public key and network ID. During initial join, the installer must authenticate the Supervisor endpoint and key fingerprint through an approved trust-establishment mechanism; HTTPS alone is not sufficient to prevent a misconfigured or substituted authority.

Public ordinary admission continues to require explicit acceptance of versioned participation terms. No invitation token is required for ordinary membership. Master promotion requires the owner-issued activation token and binding proofs.

### 3.4 Signed authorization distribution

1. A Base Node generates its identity and Master control key locally. Registration proves possession of those keys to the Supervisor and uses an activation token issued by the one owner account.
2. Supervisor signs a grant binding `network_id`, grant ID/revision, Node identity, Master control ID/key and operation scope. Only the Supervisor retains its authority private key.
3. Supervisor sends a signed announcement containing the grant to reachable Relays and online Nodes. Receivers verify it against their already pinned Supervisor public key before atomic persistence.
4. Relays and Nodes may forward the unchanged signed objects. The carrier does not gain issuance authority. Deduplication and acknowledgments support eventual delivery; absent/offline recipients synchronize when reachable again.
5. A Master includes its certificate with a command when needed. A destination that missed the announcement can authenticate the certificate locally without calling Supervisor or waiting for a new directory.
6. The destination verifies both the Supervisor signature on the grant and the Master's signature on the command. Knowing a public key or copying a certificate is not proof of possession of the Master's private key.
7. Signed revocations and key-rotation updates use the same distribution path. Persist known revocations/high-water marks; reject replayed older records that would restore revoked authority. The node's local Master choice and workload policy remain independent gates.

This is eventual signed distribution, not a requirement that every Node be online during registration. Registration that creates a new Supervisor-signed authorization requires the signing authority, or a package already issued by it. Local use/activation of an issued package is distinct from redeeming a one-use token and does not create another signing authority.

## 4. How A -> Relay -> B authenticates an offline Master

**Example:** A is Core 01 and has an authorized Master identity; B is the Mac and has locally selected A; Relay is an available cloud participant; the Supervisor is temporarily unreachable.

```text
                      Supervisor (temporarily offline)
                       | signed grants + snapshots
                 [previously cached on peers]
                       |
 A: Master Core 01                           B: Mac Node
 + signed MasterGrant                        + pinned Supervisor trust key
 + identity private key                      + chosen Master = Core 01
 + signed command                            + cached/presented Master certificate
         |                                                    ^
         | overlay packet / authenticated end-to-end message  |
         v                                                    |
               Relay (regional/cloud Node + forwarding)
               forwards to B using permitted routing metadata
               does not decide permission to execute the job
```

1. B already pins the Supervisor public key/network and has explicitly chosen A. A receives a Supervisor-signed MasterGrant. B may have cached it through an announcement, or receive it attached to the command.
2. A creates a typed, time-bounded, signed request addressed specifically to B and transmits it over an available overlay route.
3. The Relay verifies the network/forwarding context needed for safe routing; it forwards the packet and does not confer Master authority.
4. B verifies the Supervisor signature on A's grant using its pinned public key, the grant's identity/key/network/scope bindings, local Master choice, known revocations and A's signature on the command. An old or unavailable directory does not itself reject the command.
5. B checks command replay/sequence, operation scope, resource limits and owner policy. It can create a new approved workload or control an existing lease offline; its permission decision does not require a Supervisor response.
6. If any mandatory check fails, B rejects the workload command **even if WireGuard connectivity and Relay routing are healthy**.

**The destination Node, not the Relay, decides whether A is its authorized Master.** A Relay may enforce network admission and anti-abuse rules, but must not be promoted into a workload authority by virtue of forwarding traffic.

## 5. Supervisor outages: all commands verify locally

### 5.1 Accepted operation policy

Here, **offline** means the Supervisor is unreachable. Master, Relay and destination Node still need an available transport path to exchange a command; an entirely disconnected device cannot receive one.

All supported commands are eligible for local offline verification: new job admission, start, pause, resume, stop/cancel, status, and workload/resource/update operations already permitted by the Master's signed scope and the owner's policy. Do not introduce an offline-only deny list, a 120-second directory dependency or the previously proposed 15-minute continuity limit.

| Operation | Supervisor unreachable | Required local authority |
| --- | --- | --- |
| New workload, start, pause, resume, stop/cancel and status | Allowed | Verified Master grant and command signature, selected Master, replay checks and owner policy |
| Resource/workload changes | Allowed within granted and owner-approved limits | Signed operation and appropriate lease/revision; cannot enlarge owner limits without a local owner action |
| Release/runtime/artifact operations | Allowed when otherwise permitted and payloads are reachable/cached | Existing signed release/content checks and update safety gates; no new Supervisor freshness dependency |
| Existing network sessions and Relay forwarding | Continue | Previously admitted peers, verified Relay scope and local ACL/resource policy |
| Local module activation/deactivation | Allowed for installed components with already-issued authorization | Protected owner action, valid signed capability and NetworkManager acknowledgment |
| Creation of a new Supervisor-signed identity or capability | Requires the authority's signature | Live signing authority or an already-issued, correctly bound authorization package; no fabricated signature or offline double redemption of a one-use token |
| Revocation/authority update reception | Apply verified records as soon as received from any carrier | Supervisor signature, monotonic revision/epoch and atomic persistence |
| Audit upload | Queue while unreachable; reconcile later | Crash-safe signed local receipts; pending central attestation does not alone block an otherwise authorized command |

Offline availability does not grant new operation scopes, select a different Master, remove participation consent, enlarge owner policy or permit arbitrary remote shell access. Such an operation is rejected identically online and offline.

### 5.2 Credential lifetime, commands and revocation

The deciding input is an authentic issued grant plus the verifier's persisted trust/revocation state, rather than a recent heartbeat or directory fetch. Preserve the existing grant model's absence of an automatic expiry unless an explicit credential-lifetime policy is separately adopted. Do not silently replace the removed online dependency with a different short mandatory renewal interval for membership, Master/Relay grants or snapshots.

A signed grant remains usable offline until its locally known revocation, an explicit signed validity restriction, authority-key invalidation or local owner withdrawal applies. Any separately configured signed expiry must be visible as a credential policy. Command TTL/sequence, immutable lease binding and execution/update safety checks are distinct from Supervisor reachability and remain enforced. Supervisor loss alone neither cancels a lease nor changes an owner's selected Master.

**An offline verifier cannot know a revocation it has not received.** Under the selected availability policy it may continue accepting a subsequently revoked Master's authentic commands until a signed revocation reaches it. Do not claim an upper bound or instantaneous global revocation without a separately adopted expiry/coordination policy. On reconnection, apply learned revocations before processing queued commands; already applied side effects cannot be undone retroactively.

Persist certificates, revocations, accepted revisions and command replay counters across daemon/system restarts. Snapshot high-water marks prevent replacing a newer snapshot with an older one; they do not by themselves revoke an older issued grant that remains authorized under the known revocation/key policy. Reject conflicting equal-revision records, downgrade attempts, wrong networks and unauthorized key replacement. Clock rollback must not revive an explicitly expired command or certificate, reset replay protection, or erase known revocations.

### 5.3 Current implementation gap

The 0.3.2 runtime still enforces directory freshness in both `authorization::require()` and `enrollment::validate_discovery()`. Membership receipts expire, Master admission uses recent membership, and the Master server refreshes authority during normal setup. Those online dependencies must be separated from local certificate/command verification as one coherent protocol change. A failed refresh should affect synchronization diagnostics, not invalidate otherwise authorized offline commands.

Retain request anti-replay, tamper detection, local policy, owner choice and artifact/update validation when implementing this change. Do not obtain offline availability by broadly skipping authorization on network errors.

## 6. Relay design and data-plane separation

Relay = Base Node plus a resource-isolated forwarding capability. Recommended properties:

- Prefer a public IPv4/IPv6 address or a reachable forwarded UDP endpoint; stable endpoints, high uptime and sufficient symmetric bandwidth improve selection. The Relay module requests its rules from the single Base Node NetworkManager.
- Advertise signed or authenticated endpoint candidates, region, transport support, load, latency, health and available forwarding capacity.
- Apply per-peer route ACLs, source-address anti-spoofing, rate limits, bandwidth quotas, ingress abuse controls and fair scheduling.
- Reserve CPU, memory and network bandwidth for the base node, its existing workloads and control operations; relay forwarding must never exhaust the host.
- Relay revocation removes forwarding eligibility while preserving ordinary membership unless that membership is separately revoked.
- Any Node may decline Relay service or leave the network under its owner policy. High durability is a selection preference, not a precondition for an ordinary Node's membership.

### 6.1 Transport and confidentiality

The proven current network path is a **WireGuard L3 hub** (`A -> Edge01 -> B`) in `10.77.0.0/16`. The hub decrypts packets on its own WireGuard interface and forwards them, so per-hop WireGuard encryption **must not be represented as confidentiality from the hub/Relay**.

Provide application-layer end-to-end authentication for commands regardless of transport. Use authenticated end-to-end encryption (for example, mutually authenticated TLS or an end-to-end secure channel) for sensitive payloads when the Relay must not read them. Do not allow an untrusted Relay to substitute a destination public key.

Direct P2P may be an optimization. A P2P-first/Relay-fallback policy requires endpoint discovery, NAT traversal, route selection, path health and hysteresis; it is **not** a property of the currently accepted 0.3.2 Linux pilot.

### 6.2 Discoverability without a live Supervisor

Pre-admitted members may retain a last-known, signed peer/relay directory and try previously verified endpoints within policy. Previously established WireGuard sessions can continue forwarding even when API discovery is unavailable. Cached endpoint reachability and signed authorization validity are separate concerns; old discovery metadata does not by itself revoke a grant.

A Relay going offline must not force the application to trust another, unauthenticated Relay. Alternate Relay selection must use Supervisor-signed authorization and endpoint identity plus path health. A Relay can present an authentic previously issued grant that the receiver has not seen before. Discovery cannot invent new Supervisor signatures, override known revocations or substitute a new key for an existing identity.

## 7. Audit: hash-linked commands and signed receipts

Supervisor serves as the authority/audit aggregation point, **not a synchronous bottleneck for every packet**. Log security-relevant *control events*, not all transit packets:

- Membership join, renewal and revocation.
- Master/Relay grant issuance, renewal and revocation.
- Owner Master choice changes.
- Workload admission, start, cancellation, completion and policy-rejection events.
- Authority key rotation, directory revision and signed checkpoint publication.

Suggested event envelope:

```text
AuditEvent {
  schema_version, network_id, event_id,
  actor_id, target_id, event_type,
  actor_sequence, issued_at,
  payload_sha256, previous_actor_event_hash,
  authority_epoch, actor_signature
}
```

The Supervisor validates and records receipts, assigns durable ledger ordering, and issues **signed checkpoints** (root/hash, sequence, epoch, timestamp). Use append-only storage with atomic persistence, backups and independently retained checkpoints.

During an outage, each actor stores a bounded, crash-safe local event chain and signed acknowledgments from counterparties where available; uploads reconcile when the Supervisor recovers. Mark events as `pending_attestation` until centrally acknowledged.

Important limitations: a hash chain makes tampering evident only relative to a previously trusted checkpoint. An attacker controlling an entire uncheckpointed log may rewrite or omit events. Event timestamps from a compromised device are not a trusted global order. Never claim full completeness or instant cross-device ordering during a Supervisor outage. A blockchain is not required.

## 8. Device placement for the available NBI estate

| Device | Known or reported capacity | Proposed placement | Caveats |
| --- | --- | --- | --- |
| NBI Edge 01 | Raspberry Pi 4; 4 GiB RAM; public endpoint; ~99% uptime | **Primary Supervisor + low/medium-traffic Relay** | Protect authority CPU/RAM and durable registry. Do not make this the only high-volume transit path. |
| NBI Core 01 | i5-14600K, RTX 5060 Ti; additional 1 TB HDD reported | **Primary Master + CPU/GPU Compute Node** | Protect Master scheduler from saturated mining/inference workloads; use fast storage for latency-sensitive state where available. |
| NBI Core 02 (planned) | i5-14500, 16 GiB DDR5-4400, 500 GiB SATA SSD | **Second independent Master + CPU Node** | Not yet deployed; avoid designing around an assumed RAM upgrade. |
| Mac | macOS personal workstation | **Development and ordinary test Node**, optionally locally activated Master | Do not assume 24/7 operation, reboot permission or public inbound reachability. |
| AWS instances | Ephemeral rental, regions and quotas vary | **Regional Relay + opportunistic Compute Node** | Verify ingress/egress pricing, outbound transfer quotas, IP lifecycle and machine uptime. Never place sole authority material here. |
| Azure server | Rental/server reported; Hong Kong location unverified | **Candidate regional Relay + compute** | Confirm actual region and reachable UDP endpoint before treating it as a Hong Kong routing point. |

Keep the edge's existing `10.77.0.1` allocation and all existing node `/32` allocations unchanged. Existing native pilot evidence records Core `10.77.0.4`, Mac `10.77.0.5`, and Ubuntu VM `10.77.0.6`; do not reinterpret these as evidence of the new Relay or offline-auth capabilities.

Cloud Relays should be transient and dynamically discoverable, with endpoint health, signed capability policy and explicit withdrawal. A route becoming unreachable and an authorization being revoked are separate states. A dedicated standby Supervisor is a separate future HA effort; copying the root signing key to an arbitrary ephemeral cloud VM is not an acceptable shortcut.

## 9. Proposed implementation workstreams

### P0 — Confirm policy and compatibility boundaries

- Record the owner-selected policy: all supported commands, including new jobs, verify locally without a live Supervisor. No blanket offline timer; explicit signed restrictions and local owner policy still apply.
- Confirm Relay admission and owner opt-in semantics.
- Decide whether a single standalone Supervisor or an HA/standby design is in scope; do not assume distributed consensus.
- Define protocol version negotiation and rejection behavior for old clients and stale grants.

### P1 — Protocol and cryptography

- Extend `crates/lattice-protocol/src/product.rs` with versioned scoped Relay/Master grants, signed announcements/revocations and command envelopes with certificate presentation.
- Reuse the current signed membership and explicit MasterChoice contracts; do not create a second independent master-ownership system.
- Add signing-domain separation, key IDs, rotation semantics, epoch monotonicity, explicit validity semantics and deterministic serialization. Persist offline verification and replay state.
- Ensure each signed message binds its network, issuer, target and operation to prevent cross-protocol and cross-network replay.

### P2 — Supervisor state and audit

- Adapt the current bootstrapper's identity, token and signed-directory responsibilities into a **Supervisor** service boundary without regenerating existing keys or allocations.
- Add Relay capability registry, grant issuance/revocation, signed snapshots, durable audit append and checkpoint publication.
- Retain the existing one-owner/multiple-masters product contract and explicit participation acceptance.
- Ensure unrelated network forwarding remains operational when Supervisor APIs restart.

### P3 — Base Node, Master and Relay

- Add locally authorized Relay opt-in, routing resources, bandwidth quotas, per-peer ACLs and Relay-specific health metrics to the Base Node or an isolated child service.
- Add protected special-status controls and persisted capability lifecycle on the common Base Node. Keep Master, Relay and Supervisor services decoupled behind typed local interfaces.
- Refactor Node and Master admission/command validation around locally verified issued certificates; remove mandatory directory/membership refresh as an offline command dependency without removing signature, replay or owner-policy checks.
- Make NetworkManager the only privileged writer of WireGuard/routes/firewall, including Relay forwarding; migrate the current gateway reconciler through an exclusive handoff.
- Keep ordinary membership and valid workload capabilities operational when a different special module is stopped, fails activation or is revoked.
- Independently validate presented/cached grants, known revocations, explicit MasterChoice, command signatures, persisted replay counters, lease context and local policy on the receiving Node.
- Cache signed directories atomically; never silently import an unsigned Relay claim as authorization.

### P4 — Network selection and operational controls

- Preserve the tested L3 hub as the initial route.
- Add signed Relay discovery, region-aware health and failure handling, offline certificate presentation/synchronization and explicit path-selection diagnostics.
- Benchmark Relay forwarding throughput and CPU on the RPi and cloud hosts; do not assume a Raspberry Pi's Ethernet rating equals encrypted overlay throughput.
- Treat P2P-first routing as a separately gated optimization with a fallback path.
- Expose Supervisor/Relay/Master/Node modules, verified grants, local policy, synchronization state and module health in CLI and consoles. An overdue sync is not an authorization failure by itself.

### P5 — Migration, verification and release

- Introduce new protocol versions and staged feature gates without destructive renaming or replacing the working deployment.
- Preserve `network.json`, signing/WireGuard identities, IPAM, local participation consent, owner Master choice, all existing leases and recovery backups.
- Validate on an isolated test topology, then designated pilot nodes; require explicit operator approval before deploying live.
- Keep current 0.3.2 Linux acceptance, historical 0.2.2 evidence and unpromoted global stable distinct from the future four-role/offline candidate.

## 10. Acceptance test matrix

| Test | Required result |
| --- | --- |
| Two concurrent authorized Masters | Both accepted independently; one account, two distinct device-bound grants |
| Explicit local selection | B accepts A only if B's owner selected A; rejects other authorized Masters |
| Relay transparency | The same signed workload command yields the same authorization result with a direct route or via Relay |
| Supervisor unavailable | All supported command categories, including new jobs, verify locally under existing authority and owner policy; no unsigned authority appears |
| Signed directory stale | Otherwise valid commands continue without a mandatory directory refresh |
| Missed Master announcement | Command-carried Supervisor certificate authenticates the Master without contacting Supervisor |
| Master grant known revoked or explicitly expired | Reject using persisted signed restrictions; no implied reassignment |
| Revocation not yet delivered | Demonstrate eventual enforcement on receipt; do not claim immediate global revocation |
| Relay grant revoked | Forwarding permission removed while ordinary Node capability remains intact |
| Tampered/replayed command | Invalid signature, wrong target/network, stale sequence or expired request rejected |
| Downgraded authority snapshot | Lower epoch/revision or conflicting same revision rejected |
| Clock adjustment/restart | Replay counters and known revocations persist; explicit expiry cannot be bypassed |
| Multiple modules on one host | Exactly one network writer and one managed identity/interface; no competing 7443 listeners |
| Module activation failure/revocation | Ordinary Node and other valid modules remain functional with unchanged keys/IP |
| Relay outage | Verified alternative path or explicit degraded state; no unauthenticated route promotion |
| Supervisor API restart | Established forwarding preserved; persistence intact |
| Audit offline/reconnect | Actor chains survive crashes, resume upload and reconcile with signed checkpoints |
| Node owner policy | Remote Master/Supervisor cannot force mining, execute arbitrary shell or increase a resource limit |
| Migration | No unintended change to IDs, private keys, allocated IPs, existing leases, master choice or other host services |

Run normal unit and integration regressions, adversarial authorization tests, native WireGuard peer-to-peer/relay traffic checks and resource saturation tests. Build success is not native-install or production-acceptance evidence.

## 11. Resolved owner direction and remaining details

Resolved by the owner on 2026-10-16:

1. All supported commands work without a live Supervisor after the relevant signing authority has been issued. New jobs are included; the earlier deny-new-work/15-minute recommendation is superseded.
2. Supervisor signs registered Master identity/key authorizations and distributes them to Relays and online Nodes. Recipients already pin the Supervisor public key; presented signed certificates also cover missed announcements.
3. All devices share the ordinary Base Node foundation. Protected special-status activation starts the corresponding module instead of creating a competing node/network installation.

The proposed implementation makes one Base Node NetworkManager the host network writer and retains one-account/multiple-Masters with one locally chosen workload Master per Node. These concrete interfaces remain design work until implemented and verified.

Remaining details must not undo the resolved offline policy: exact grant/rotation encoding, optional explicit credential lifetimes, Relay eligibility/quotas, initial Supervisor fingerprint provisioning, HA scope, end-to-end payload secrecy and audit checkpoint witnesses. No hardcoded authority-renewal timeout is inferred from these open items.

## 12. Source and evidence references

- `AGENTS.md` — repository rules, English-language documentation and role separation.
- `docs/product-normalization-decisions.md` — approved network/ownership decisions and rollout history.
- `docs/superpowers/specs/2026-10-15-master-ownership-amendment.md` — multiple Masters under one account, explicit Node selection, consent and migration.
- `docs/product-normalization-architecture-reconciliation.md` — audited pilot and unresolved implementation distinctions.
- `docs/network-convergence.md` and `docs/network-audit.md` — signed discovery and current WireGuard routing behavior.
- `docs/product-normalization-linux-ownership-acceptance.md` — current 0.3.2 Linux pilot and native-test boundaries.
- `docs/product-normalization-acceptance.md` — historical 0.2.2 evidence.
- `crates/lattice-protocol/src/product.rs` — current signed grant, directory and master-choice schemas.
- `crates/lattice-node/src/authorization.rs` — live-source 120-second directory freshness enforcement.

**Implementation boundary:** Owner direction above updates the written design. This edit does not change running services, certificates, firewall, IP assignments, workload policy or release channels, and is not offline-runtime acceptance evidence. Preserve the existing pilot while implementing and testing the new protocol/module lifecycle in a separate planned change.
