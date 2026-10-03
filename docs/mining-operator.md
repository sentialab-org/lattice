# Mining Operator Pipeline

The mining operator API turns the XMRig workload implementation into an operational control-plane flow without exposing arbitrary command execution.

## Configuration

Set an operator token before using operator endpoints:

```text
LATTICE_OPERATOR_TOKEN=<strong-random-token>
```

Set the public control URL that nodes can use to download immutable content:

```text
LATTICE_PUBLIC_URL=https://control.example.com
```

For localhost development, the default public URL is `http://127.0.0.1:7443`. Production public URLs must use HTTPS because node runtime and artifact validation rejects non-localhost HTTP URLs.

Operator endpoints are disabled when `LATTICE_OPERATOR_TOKEN` is not configured. Operator requests use:

```text
Authorization: Bearer <operator-token>
```

## Publish XMRig

Lattice does not execute an upstream ZIP or tar archive. The publication helper downloads the official XMRig release archive, verifies its pinned upstream SHA-256, extracts the executable, and uploads only that executable to the control plane.

The current bootstrap pin is XMRig 6.26.0.

Windows or PowerShell:

```powershell
./scripts/publish-xmrig.ps1 -ControlUrl https://control.example.com -OperatorToken $env:LATTICE_OPERATOR_TOKEN -Platform windows
```

Linux:

```bash
./scripts/publish-xmrig.sh https://control.example.com "$LATTICE_OPERATOR_TOKEN"
```

The control plane stores the executable under a SHA-256 content address, persists an immutable `xmrig@<version>` runtime manifest for the uploaded platform and architecture, and creates the matching immutable mining-profile artifact.

Publishing the same immutable runtime content again is idempotent. Publishing different content under the same runtime version/platform/architecture is rejected.

## Inspect nodes

```bash
curl -H "Authorization: Bearer $LATTICE_OPERATOR_TOKEN" \
  https://control.example.com/api/v1/operator/nodes
```

Use the returned node ID to target a mining job to one node. Omitting `target_node_id` leaves the job available to the first eligible node.

## Queue a mining job

```bash
curl -X POST \
  -H "Authorization: Bearer $LATTICE_OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  https://control.example.com/api/v1/operator/jobs/mining \
  -d '{
    "target_node_id": "node_example",
    "runtime_version": "6.26.0",
    "algorithm": "rx/0",
    "pool": "pool.example.com:443",
    "wallet": "replace-with-wallet",
    "worker": "worker-01",
    "password": "x",
    "threads": 4,
    "cpu_percent": 50,
    "memory_mb": 4096,
    "huge_pages": true,
    "tls": true,
    "keepalive": true,
    "donation_level": 1,
    "restart_limit": 3,
    "duration_seconds": 3600
  }'
```

The control plane validates the structured mining parameters before the job enters the queue. It rejects unknown runtime versions, missing mining-profile artifacts, invalid thread/config fields, invalid resource limits, unknown target nodes, and durations outside 10 seconds to 7 days.

The scheduler still applies each node's effective local-and-remote policy before leasing the job. A target node with mining disabled or insufficient resources will not receive the job.

## Inspect jobs

```bash
curl -H "Authorization: Bearer $LATTICE_OPERATOR_TOKEN" \
  https://control.example.com/api/v1/operator/jobs
```

Job records expose the queue and signed lifecycle state. Pool passwords are redacted in the operator listing.

## Immutable content

Published runtime and mining-profile payloads are served from:

```text
/api/v1/content/<sha256>
```

Content objects are verified against their path SHA-256 before being returned and are served with immutable cache headers. Nodes independently verify the signed manifest size and SHA-256 again during acquisition, and XMRig is re-hashed immediately before every process spawn.
