# Lattice public installation

Open `/install` on the coordinator site. Ordinary nodes use public signed admission,
without enrollment tokens or manual approval. The installer records the current
participation terms on the device and never interrupts for them. Master setup accepts a
dashboard-issued 24-hour activation token with `--token` or asks for it privately after
elevation; never place that token in a URL or release artifact. Relay installs stand up
the Base Node first and report the relay role as pending until the supervisor grants it.

The public scripts download a role-complete immutable bundle and verify its checksum,
archive entries, manifest and component hashes before replacing services. Releases
appear in the catalog only after assembly and validation. An unavailable release
returns an explicit download failure and must not replace an installed version.

Supported source adapters: Linux systemd on Debian/Ubuntu, root macOS LaunchDaemons,
and Windows administrator/SCM. Platform acceptance is tracked separately in
`docs/product-normalization-acceptance.md`.
