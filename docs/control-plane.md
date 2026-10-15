# Lattice Control Plane

The bootstrapper owns network membership, stable overlay IP allocation and master
management authority. A master is an ordinary participating node with an additional
signed management grant. It coordinates workloads only while designated active.
The existing L3 topology remains `A -> Edge/RPi -> B` on `10.77.0.0/16`.

## Account and role setup

Provision the dashboard account privately using `lattice-admin provision --help`.
The data directory contains an Argon2id account verifier and digest-only sessions,
not a plaintext password. Serve the console and APIs through the same HTTPS origin;
production cookies are Secure, HttpOnly and SameSite=Strict. Mutations require an
in-memory CSRF token and the expected Origin. Sessions expire after 30 minutes idle
or eight hours absolute; logout invalidates the session.

`LATTICE_CONTROL_BIND` selects the HTTP listener, `LATTICE_CONTROL_DATA` selects
private persistent state, and `LATTICE_PUBLIC_URL` sets the external origin.
`lattice-bootstrapper` and `lattice-master` select their respective roles;
`lattice-control` retains combined-mode compatibility. An existing combined Edge
must retain workload authority until an explicit handover, as described in
[acceptance](product-normalization-acceptance.md).

`LATTICE_ENROLLMENT_TOKEN` and `LATTICE_OPERATOR_TOKEN` are optional compatibility
credentials. Configure them explicitly only when retaining old clients. Ordinary
public setup never needs these deployment credentials. Do not put account passwords
or master tokens in process arguments or service environments.

## API contracts

| Path | Authority and behavior |
|---|---|
| `/api/v1/auth/{login,session,logout}` | Account session lifecycle; same-origin login and mutations |
| `/api/v1/bootstrap/join` | Public signed node claim, key binding, stable IP, signed membership |
| `/api/v1/bootstrap/activate-master` | One-device activation token plus node and control signatures; identical retry recovers its grant |
| `/api/v1/bootstrap/discovery` | Fresh signed node claim returns membership and signed master directory |
| `/api/v1/operator/master-tokens` | Account list/create; plaintext activation token returned only by creation |
| `/api/v1/operator/master-tokens/revoke` | Account mutation invalidates an unused token |
| `/api/v1/operator/masters` | Account view of activated grants and active master |
| `/api/v1/operator/masters/{active,revoke}` | Account selection/revocation of management authority |
| `/api/v1/operator/fleet` | Central role/IP/capability/health/policy inventory |
| `/api/v1/operator/network/*` | Account network inventory, allocation and revocation |
| Existing operator workload APIs | Account authority; bootstrapper delegates only typed operations to the selected grant-derived overlay endpoint |
| `/api/v1/master/join` | Signed membership and node proof admit a workload participant |
| `/api/v1/enroll` | Legacy token-required signed enrollment, separate from public joining |
| `/api/v1/heartbeat` | Signed heartbeat and replay protection; master authority required on activated product masters |

Delegation binds the selected master, network, operation, request body and expiry.
Mutation IDs and results are persisted; a crash during an ambiguous mutation fails
closed for inspection. Read requests do not create durable result-cache entries.
Central inventory merges a short-lived signed snapshot from the selected master
with coordinator membership and IP records, matching each node public key. Missing
master inventory is reported as unavailable. A managed node persists the signed
directory, rejects new authority after signed removal, and checks it again for
responses that were already in flight. Existing leases retain their policy and
expiry handling; master handover waits for them instead of changing their pin.

Revoking an unused activation token and revoking an activated master's management
grant are distinct actions in the console.

## State and compatibility

Retain the existing control identity, allocation store, node/WireGuard keys and
owner policy during migration. Public admission enables networking; it does not
enable mining or override local workload consent. New signed product structures
are versioned separately from existing signed protocol claims.

The existing job lease, artifact/runtime manifest, policy intersection, event and
heartbeat contracts remain available. See the
[archived protocol reference](history/pre-normalization-control-plane.md) for those
formats. Historical deployment steps in that document are not normalization
acceptance evidence. Current [release instructions](release-distribution.md) and
[acceptance boundaries](product-normalization-acceptance.md) are authoritative.

A product master binds only its signed overlay address on port 7443 and advertises
that same origin for content. Plain HTTP is permitted for exact authenticated
master content objects over WireGuard; unrelated HTTP origins remain rejected.
Owner policy edits retain the exact existing control pin, and disabling networking
or explicitly resetting setup is respected by background reconciliation.
