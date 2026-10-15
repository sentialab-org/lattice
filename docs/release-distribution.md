# Lattice Release Distribution

The product uses one role-complete immutable bundle per OS/architecture and role.
The public website serves `/install`, `/installer/{linux,macos}.sh`,
`/installer/windows.ps1`, `/releases/stable`, and
`/releases/<version>/<target>/{node,master}.{tar.gz,zip}`.

Ordinary installation requires administrator elevation and no enrollment token.
Master installation asks for a dashboard-issued activation token privately after
elevation. Account passwords and activation tokens never belong in copied commands,
release assets or service arguments.

## Build and assembly

Version 0.2.1 includes the native Linux pilot correction. The immutable 0.2.0
candidate remains available for audit and must not be promoted: native systemd
ignored its quoted `EnvironmentFile` paths. Both generated services now use the
native path syntax, verified by the actual systemd parser with paths containing
spaces. `scripts/build-release.py` refuses a
dirty source checkout, builds binaries with the exact source revision embedded in
the node and records per-target SHA-256 hashes. Linux uses `cargo-zigbuild` with
glibc 2.28; Windows GNU uses MinGW. Install the Rust targets and build tools first.

`python3 scripts/prepare-network-dependencies.py` builds pinned portable macOS
dependencies and downloads the checksum-pinned Windows MSI without installing them.
It records source revisions, hashes and license notices, and produces the matching
source archive for redistribution. Prepared files live in
`target/network-dependencies/<target>`:

- macOS: `wg`, `wg-quick`, `wireguard-go`, portable Bash 4+, notices and provenance.
  Stock macOS Bash 3 cannot run upstream `wg-quick`. Do not run Homebrew as root,
  or ship a Bash binary linked to private Homebrew libraries on another machine.
- Windows: official `wireguard.msi`, notices and provenance. The installer requires
  a valid WireGuard publisher Authenticode signature before invoking MSI.
- Linux: Debian/Ubuntu installs WireGuard, iproute2 and ping through apt.

```bash
python3 scripts/build-release.py --targets linux-x86_64,linux-aarch64
python3 scripts/release_manifest.py assemble --version 0.2.1 --out dist/staged-0.2.1 --targets linux-x86_64,linux-aarch64
python3 scripts/release_manifest.py validate --root dist/staged-0.2.1
```

Assembly fails on missing/stale/corrupt components. All selected targets must be
complete; unavailable targets are never advertised. The manifest lists exact file
hashes, sizes, executable bits, role, target, version and source revision. Archive
validation rejects traversal, absolute paths, duplicate entries and links. The
native verifier checks the extracted allowlist before service replacement.

The loose bootstrapper/control binaries remain available at the previous immutable
version/target paths and come from the same build record as the public bundles.
No GitHub Actions workflow is created by this change.

## Promotion and rollback

`promote --staged <path> --out <document-root>` validates before adding an immutable
version directory and atomically replacing the stable pointer. Old version trees
and `stable.previous` remain available. Remote upload, website routing, credential
provisioning and service migration require the concrete release review documented
in [acceptance](product-normalization-acceptance.md).

Installers snapshot owned binaries and service files before replacement. Identity,
WireGuard keys, IP allocation and owner policy are retained. A failed setup restores
old binaries/services and keeps diagnostic and identity state for recovery. Fixture
rollback tests do not prove actual systemd/launchd/SCM acceptance.

[Archived deployment notes](history/pre-normalization-release-distribution.md) retain
historical manual instructions and must not be used as current install guidance.
