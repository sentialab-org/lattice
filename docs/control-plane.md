# Lattice Control Plane

## Current Scope

The current control-plane implementation provides:

- persistent Ed25519 control identity
- health endpoint
- node enrollment endpoint
- node signature verification
- signed enrollment receipts
- persistent enrolled-node registry

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

The enrolled-node registry is stored in:

```text
<data directory>/nodes.json
```

The control identity is stored in:

```text
<data directory>/control-identity.json
```

On Unix these files are restricted to mode 0600.
