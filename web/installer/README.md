# Lattice Web Installer

One-line installers served from this directory. Mirror `web/installer/`
and the `scripts/` and `releases/` trees assembled by
`scripts/publish-release.sh` onto the download host so these URLs work:

- `http://<host>/installer/linux.sh`
- `http://<host>/installer/windows.ps1`
- `http://<host>/releases/<version>/<target>/<binary>`
- `http://<host>/releases/<version>/<target>/<binary>.sha256`
- `http://<host>/scripts/<installer-script>`

Usage:

```bash
curl https://<host>/installer/linux.sh | bash
```

```powershell
irm https://<host>/installer/windows.ps1 | iex
```

Both installers are interactive with `y/n` prompts and defaults. Set
`LATTICE_NONINTERACTIVE=1` with all inputs in the environment for
unattended runs. Secrets are prompted silently and never written to disk
except the service environment files owned by the installer
(`/etc/lattice/*.env` mode 0600, Windows service account scope).

## Hosting

Any static file server works. Nginx example:

```nginx
server {
    listen 80;
    server_name lattice.sentialab.org;
    root /var/www/lattice;
    location / {
        add_header Cache-Control "no-store";
    }
}
```

Serve over HTTPS in production. The installers verify SHA-256 checksums,
which catch corruption and mirror tampering but do not replace TLS
against an active attacker on plain HTTP.
