# Lattice Network Convergence

The normalized source retains the deployed WireGuard L3 hub: `A -> Edge01 -> B`.
The intended overlay is `10.77.0.0/16`. Existing `network.json`, gateway keys,
reserved addresses and allocations take precedence over new-install defaults.
Direct P2P is not selected by normalization.

Ordinary nodes submit a fresh signed public join claim without an enrollment token.
They then prove a separate WireGuard key with local network opt-in. Allocation,
key uniqueness and durable updates are serialized. Reinstall reuses the same node
identity and IP; a public rejoin cannot undo a revocation.

The bootstrapper coordinates membership and network state. Its explicitly enabled
`LATTICE_GATEWAY_RECONCILE=1` task applies peers at startup, on membership changes
and every 15 seconds. `wg syncconf` updates the owned interface. The dedicated
nftables table accepts intra-overlay forwarding and restricts traffic involving
that interface; its base policy does not drop unrelated host forwarding. Apply
errors retain the prior peer configuration and produce a degraded report.

A master is one participating node plus a workload-control identity. Dashboard
activation proves both keys and binds management authority to its allocated IP.
The grant and token consumption are one durable transaction. The same identities
can recover the original grant after a lost response without storing the token.
Master revocation retains the ordinary node/IP and removes its authority from the
signed directory. New authority fails closed when directory freshness expires.

The native node setup service owns public admission, network opt-in, discovery,
activation, workload attachment and retries. It requires a fresh gateway handshake,
a verified OS route and a successful overlay probe before reporting network ready.
A missing workload master is `waiting_for_master`, separately from network failure.
The device owner's workload categories and resource limits remain authoritative.

## Current deployment evidence

Read-only SSH inspection on 2026-10-15 found Edge01 running
`lattice-control.service` in **combined** mode, with `/var/lib/lattice`,
`/etc/lattice/control.env`, `/usr/local/bin/lattice-control`, and `lattice0`.
It is not yet the normalized bootstrapper deployment. A protected snapshot of
these owned files was verified locally before any migration. No remote service
was restarted or replaced during source implementation.

The earlier OpenCode overlay ping/SSH results are historical evidence, not
acceptance of the new installers. See [acceptance](product-normalization-acceptance.md)
and [the archived engineering notes](history/pre-normalization-network-convergence.md).
