# Lattice Control Plane

## Current Scope

The current control-plane implementation provides:

- persistent Ed25519 control identity
- health endpoint
- node enrollment endpoint
- node signature verification
- signed enrollment receipts
- persistent enrolled-node registry
- authenticated heartbeat endpoint
- signed heartbeat receipts
- replay rejection
- last-seen tracking
- online expiry tracking
- node capability inventory
- node health inventory
- signed policy distribution through heartbeat receipts
- persistent file-backed policy revisions
- file-backed job queue
- signed job lease delivery
- signed node lease decisions
- persistent job lease state

## Environment

Required:

```text
LATTICE_ENROLLMENT_TOKEN
```

Optional:

```text
LATTICE_CONTROL_BIND
LATTICE_CONTROL_DATA
```

Defaults:

```text
LATTICE_CONTROL_BIND=127.0.0.1:7443
LATTICE_CONTROL_DATA=./data
```

## Development

```bash
LATTICE_ENROLLMENT_TOKEN=development-token cargo run -p lattice-control
```

Local nodes may enroll against:

```text
http://127.0.0.1:7443
```

## Production Transport

lattice-control currently serves plain HTTP and should bind to a private interface or loopback behind a TLS reverse proxy.

A non-local Lattice Node refuses enrollment URLs that do not use HTTPS.

## Endpoints

### GET /health

Returns:

- control ID
- control public-key fingerprint
- protocol version

### POST /api/v1/enroll

Accepts a signed EnrollmentRequest and returns a signed EnrollmentResponse.

The enrollment token is compared in constant time.

### POST /api/v1/heartbeat

Accepts a signed HeartbeatRequest from an enrolled node.

The endpoint validates:

- protocol version
- heartbeat timestamp
- node enrollment state
- node Ed25519 signature
- monotonic heartbeat sequence

It returns a control-signed HeartbeatResponse. Eligible nodes may receive one independently signed job lease with the heartbeat response.


## Policy

The control policy is stored at:

```text
<data directory>/policy.json
```

If the file does not exist, lattice-control creates revision 1 with permissive constraints. The default policy therefore does not expand or restrict the node owner's local policy.

A policy contains workload-category permissions and optional resource caps. The node computes its effective policy by intersecting these constraints with local owner settings.

Policy revisions must be greater than zero. Nodes reject revision rollback and reject changed policy content that reuses an existing revision.

The current control process loads policy at startup. Editing `policy.json` currently requires restarting lattice-control. A policy administration API remains part of the later control-plane management work.

## Job Queue

The control job queue is stored at:

```text
<data directory>/jobs.json
```

The current queue is file-backed and loaded when lattice-control starts. Operator job submission APIs are intentionally deferred until operator authentication exists.

A queued job contains a structured JobOffer and state. The heartbeat path filters queued jobs using the node's reported effective policy and hardware capabilities before creating a lease. The node repeats its own validation and remains authoritative for acceptance.

Offered leases use a short decision deadline. If no decision arrives before that deadline, the job returns to the queued state while the overall job expiration remains valid. Accepted leases remain reserved until their lease expiration or a later job-status transition.

### POST /api/v1/jobs/decision

Accepts a node-signed JobDecisionRequest.

The endpoint validates:

- protocol version
- decision timestamp
- node enrollment state
- node Ed25519 signature
- lease ownership
- lease decision deadline
- current job state

The resulting Accepted or Rejected state is written back to `jobs.json` and acknowledged with a control-signed receipt.

## Registry

The enrolled-node registry is stored in:

```text
<data directory>/nodes.json
```

For each node it currently stores:

- identity metadata
- client version
- enrollment timestamp
- last-seen timestamp
- online-until timestamp
- last heartbeat sequence
- hardware capabilities
- runtime health

The control identity is stored in:

```text
<data directory>/control-identity.json
```

On Unix these files are restricted to mode 0600.
