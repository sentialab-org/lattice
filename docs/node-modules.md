# Base Node installation and optional modules

Status: development implementation; the current production release is unchanged. Native Linux release acceptance and the independent whole-change review are tracked separately in the offline-modules plan. macOS and Windows source/build checks do not establish native acceptance.

Every new Node and Master bundle contains the same verified Base Node, worker, Master, Supervisor and administration components. The role choice selects setup behavior. It does not create another network identity or another Master boot service. Only the Base Node service starts optional modules and owns the managed interface.

## Device installation

Use the elevated public installer for the desired operating system. Ordinary participation requires explicit acceptance of the displayed terms and no invitation token. Master setup privately requests a one-use activation token from the owner dashboard. Reinstallation and later activation retain the device's identity, transport key, owner policy, selected Master and allocated address.

Linux and macOS installers record the invoking owner's UID for protected IPC; shared socket-group membership alone does not grant another local account control. Root remains authorized for provisioning. Windows uses the protected local service pipe. The desktop application and optional Node web console use the same typed daemon operations.

The web console is a separate local owner application: run `node web/node/server.mjs` from the source checkout and open its private terminal launch link. It binds loopback port 7444, requires its private browser session for every API request, and denies Supervisor provisioning and gateway adoption. The Base Node control ingress remains on 7443. The optional web bridge is not an automatically installed network service.

## Offline use and explicit owner choice

The local Control Trust screen supports:

- Reading per-module lifecycle state and verified certificate references.
- Opting into Master or Relay, or disabling either module.
- Setting a positive Relay forwarding budget, bounded by its signed grant.
- Importing a previously issued public authority package and explicitly synchronizing authority.
- Selecting one eligible Master from locally verified certificates without a legacy directory fetch.
- Running typed local Master administration with cached authority.

A failed synchronization is reported separately from certificate validity. Cached or presented credentials are checked against the pinned Supervisor key, signed scope, explicit validity and known revocations. A valid certificate never substitutes for local owner choice or workload policy. New authority issuance and redemption of an unused activation token require Supervisor; using an already issued certificate does not.

The elevated CLI exposes the same operations without exposing private keys:

```sh
lattice-node modules
lattice-node network-manager
lattice-node masters
lattice-node select-master --id CONTROL_ID
lattice-node authority import < issued-authority.json
lattice-node authority sync
lattice-node module enable --kind master
lattice-node module enable --kind relay --forwarding-limit-bps 8000000
lattice-node module disable --kind relay
printf '%s\n' '{"operation":"fleet_inventory","body_base64":""}' | lattice-node local-master
```

`local-master` takes `LocalMasterRequest` JSON on standard input. Its `WorkloadOperation` type restricts inventory, jobs, content publication and resource-control routes; it is not an arbitrary HTTP or shell passthrough. Runtime publication can use the bounded binary/base64 CLI path. Browser request bodies remain limited to 64 KiB.

## Linux Supervisor provisioning and gateway handoff

Supervisor provisioning requires a verified complete bundle, an explicit HTTPS public origin, an authority directory and OS administrator rights. For an existing deployment, retain its original account, signing identity, network descriptor and gateway transport key together. Do not provision a new account or initialize replacement keys over that deployment.

For fresh authority state, provision the one owner account privately and initialize the authority offline before starting a module:

```sh
sudo /path/to/bundle/lattice-admin provision \
  --data-dir /var/lib/lattice-supervisor --username OWNER
sudo /path/to/bundle/lattice-admin initialize-supervisor \
  --data-dir /var/lib/lattice-supervisor --public-url https://authority.example
```

Initialization starts no network writer or listener. Repeated initialization preserves keys. A partially missing authority must be recovered; initialization refuses to generate a replacement root over the remaining records.

The maintained Supervisor installer replaces the historical standalone bootstrapper installer. It delegates to the common Base Node installer, preserves the configured interface name, stops fixed legacy network writers through the protected handoff, imports the exact transport key before ordinary registration can create one, and starts Supervisor plus Relay under the Base Node:

```sh
sudo bash scripts/install-bootstrapper-linux.sh \
  --artifact-dir /path/to/verified/bundle \
  --authority-dir /var/lib/lattice-supervisor \
  --public-url https://authority.example \
  --adopt-gateway
```

For an existing authority, point `--authority-dir` at its original protected directory. For a fresh empty directory the installer also accepts `--owner-user OWNER` and prompts privately for its account password. Terms are displayed for explicit acceptance; `--accept-terms` is available for an owner-approved unattended invocation.

Gateway adoption is an explicit administrator action. Its protected checkpoint retains legacy service state, source hashes and transport identity. The imported interface is applied only through the Base Node manager. Disabling Relay removes only its owned forwarding capability. It does not discard the Node identity or replace the transport key.

The installer retains binary/service recovery snapshots and handoff diagnostics. Ordinary Linux rollback restores previous enabled/running states, including a previously stopped Master. After a partially completed authority handoff, inspect the retained handoff and legacy-service checkpoints before restarting any old network writer. Never run the legacy reconciler alongside the Base Node manager.

`verify-installation` checks the supervised Master module rather than requiring a second Master service. It rejects a concurrently running legacy Master service. Service startup alone remains insufficient: artifact/source provenance, handshake, route, overlay probe, workload readiness and peer TCP evidence are still required.
