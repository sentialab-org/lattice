# Lattice Product Requirements — Checkout Correction

Recorded: 2026-10-15.

## Correction

The earlier source inventory in this document was withdrawn. It inspected the
wrong checkout, `/Users/zvwgvx/projects/lattice`, and must not be used to infer
which features are missing from the owner's active work.

The authoritative working directory identified by OpenCode session
`ses_ec7028751ffepq330iJ6HRFOZX` is **`/Users/zvwgvx/Project/lattice`**.
That checkout is on **`runtime-integration`**, with local HEAD **`6f5d19d`**,
one commit ahead of its tracking ref, and extensive uncommitted network work.
Checking the remote branch at `b7f863b` omitted that work.

The actual checkout contains stable virtual IPv4 allocation, WireGuard network
configuration, gateway forwarding, network coordination APIs, node network
supervision, discovery/direct-mode code, installers, and release distribution.

The inspected session records a hub-and-spoke deployment in `10.77.0.0/16`:
Edge/RPi gateway `10.77.0.1`, Core01 `10.77.0.4`, Mac `10.77.0.5`, and Ubuntu VM
`10.77.0.6`. Its tool output includes successful overlay ping and SSH results.
These are historical session results, not a fresh connectivity check.
The selected deployed path is `A -> RPi L3 gateway -> B`; direct P2P operation
was not established by that acceptance evidence.

Account login and dashboard-generated enrollment tokens were only starting
when the session ended with a provider HTTP 400 error. Protocol types and an
unwired token module exist; completed account authentication is not verified.

## Confirmed Product Requirements to Carry Forward

- Continue from the actual OpenCode working tree and preserve its local changes.
- Master means a participating node with management authority.
- Initial installer platforms are macOS, Windows, and Linux.
- The website provides complete system installation and automatic onboarding.
- Dashboard management requires account login; the initial username is `zvwgvx`.
- Master setup requires a dashboard-issued token.
- Install at system scope with OS administrator elevation, network integration,
  boot services, and automatic registration and reconnection.
- Keep supplied credentials out of repository documentation and public assets.

This file is a correction and requirements record in the older checkout, not
a design specification for the active working tree. No implementation changes
were made to the active OpenCode checkout during the session inspection.
