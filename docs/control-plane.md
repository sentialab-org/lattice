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

It returns a control-signed HeartbeatResponse.

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
