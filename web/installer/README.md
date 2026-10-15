# Lattice public installation

Open `/install` on the coordinator site. Ordinary nodes use public signed admission,
without enrollment tokens or manual approval. Master setup asks for a dashboard-issued
24-hour activation token after administrator elevation. Never embed that token in a
URL, command, transcript, browser storage, or release artifact.

The public scripts download a role-complete immutable bundle and verify its checksum,
archive entries, manifest and component hashes before replacing services. Releases
appear in the catalog only after assembly and validation. An unavailable release
returns an explicit download failure and must not replace an installed version.

Supported source adapters: Linux systemd on Debian/Ubuntu, root macOS LaunchDaemons,
and Windows administrator/SCM. Platform acceptance is tracked separately in
`docs/product-normalization-acceptance.md`.
