use lattice_protocol::{ModuleKind, ReleaseBundleManifest};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
};
use tokio::process::{Child, Command};

pub(super) struct VerifiedComponent {
    path: PathBuf,
    kind: ModuleKind,
}
pub(super) struct ModuleChild {
    child: Child,
}
impl VerifiedComponent {
    pub(super) fn load(bundle: &Path, kind: ModuleKind) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for item in [bundle.to_path_buf(), bundle.join("manifest.json")] {
                let meta = std::fs::symlink_metadata(item)
                    .map_err(|_| "trusted module bundle required")?;
                if meta.file_type().is_symlink()
                    || meta.mode() & 0o022 != 0
                    || meta.uid() != unsafe { libc::geteuid() }
                {
                    return Err("module bundle ownership rejected".into());
                }
            }
        }
        let name = match kind {
            ModuleKind::Master => "lattice-master",
            ModuleKind::Supervisor => "lattice-control",
            ModuleKind::Relay => {
                return Err("Relay runs inside the Base Node network manager".into());
            }
        };
        let name = if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.into()
        };
        let bytes = std::fs::read(bundle.join("manifest.json"))
            .map_err(|_| "verified module bundle required")?;
        if bytes.len() > 65536 {
            return Err("invalid module manifest".into());
        }
        let manifest: ReleaseBundleManifest =
            serde_json::from_slice(&bytes).map_err(|_| "invalid module manifest")?;
        if manifest.schema_version != 1
            || manifest.version != env!("CARGO_PKG_VERSION")
            || manifest.source_revision.len() != 40
            || !manifest
                .source_revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("module version mismatch".into());
        }
        let entry = manifest
            .files
            .iter()
            .find(|f| f.path == name && f.executable)
            .ok_or("install the optional module component")?;
        let path = bundle.join(&name);
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| "module executable missing")?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != entry.size_bytes
            || metadata.len() == 0
            || metadata.len() > 256 * 1024 * 1024
        {
            return Err("invalid module executable".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o111 == 0
                || metadata.mode() & 0o022 != 0
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err("module executable ownership rejected".into());
            }
        }
        if lattice_crypto::sha256_hex(
            &std::fs::read(&path).map_err(|_| "module verification failed")?,
        ) != entry.sha256
        {
            return Err("module executable digest mismatch".into());
        }
        Ok(Self { path, kind })
    }
    pub(super) fn spawn(&self, data: &Path, public_url: &str) -> Result<ModuleChild, String> {
        let mut cmd = Command::new(&self.path);
        cmd.env_clear()
            .current_dir(data)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in [
            "PATH",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "LATTICE_RELEASE_ROOT",
        ] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env("LATTICE_CONTROL_DATA", data)
            .env("LATTICE_NODE_MANAGED", "1")
            .env("LATTICE_GATEWAY_RECONCILE", "0")
            .env("LATTICE_PUBLIC_URL", public_url)
            .env(
                "LATTICE_CONTROL_ROLE",
                if self.kind == ModuleKind::Master {
                    "master"
                } else {
                    "supervisor"
                },
            );
        #[cfg(unix)]
        cmd.env("LATTICE_CONTROL_SOCKET", data.join("module-http.sock"));
        #[cfg(windows)]
        cmd.env("LATTICE_CONTROL_PIPE", private_pipe(data));
        cmd.env("LATTICE_SOCKET", crate::ipc_endpoint());
        if self.kind == ModuleKind::Master {
            cmd.env(
                "LATTICE_OPERATOR_TOKEN_FILE",
                data.join("module-operator-token.json"),
            );
        }
        cmd.spawn()
            .map(|child| ModuleChild { child })
            .map_err(|_| "module process could not start".into())
    }
}
#[cfg(windows)]
pub(super) fn private_pipe(data: &Path) -> String {
    format!(
        r"\\.\pipe\lattice-module-{}",
        &lattice_crypto::sha256_hex(data.to_string_lossy().as_bytes())[..32]
    )
}
impl ModuleChild {
    pub(super) fn id(&self) -> Option<u32> {
        self.child.id()
    }
    pub(super) fn exited(&mut self) -> Result<bool, String> {
        self.child
            .try_wait()
            .map(|s| s.is_some())
            .map_err(|_| "module process status unavailable".into())
    }
    pub(super) async fn stop(&mut self) -> Result<(), String> {
        if self.exited()? {
            return Ok(());
        }
        #[cfg(unix)]
        if let Some(pid) = self.id() {
            unsafe { libc::kill(pid as i32, libc::SIGTERM) };
        }
        #[cfg(windows)]
        self.child.start_kill().map_err(|_| "module stop failed")?;
        if tokio::time::timeout(std::time::Duration::from_secs(5), self.child.wait())
            .await
            .is_err()
        {
            self.child.start_kill().map_err(|_| "module stop failed")?;
            self.child.wait().await.map_err(|_| "module reap failed")?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::*;
    fn bundle(body: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let name = if cfg!(windows) {
            "lattice-master.exe"
        } else {
            "lattice-master"
        };
        std::fs::write(dir.path().join(name), body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join(name),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        crate::setup::write_private(
            &dir.path().join("manifest.json"),
            &ReleaseBundleManifest {
                schema_version: 1,
                source_revision: "a".repeat(40),
                version: env!("CARGO_PKG_VERSION").into(),
                target: "linux-x86_64".into(),
                role: NodeRole::Master,
                files: vec![BundleFile {
                    path: name.into(),
                    sha256: lattice_crypto::sha256_hex(body),
                    size_bytes: body.len() as u64,
                    executable: true,
                }],
            },
        )
        .unwrap();
        dir
    }
    #[test]
    fn changed_or_symlinked_module_cannot_start() {
        let dir = bundle(b"component");
        assert!(VerifiedComponent::load(dir.path(), ModuleKind::Master).is_ok());
        let name = if cfg!(windows) {
            "lattice-master.exe"
        } else {
            "lattice-master"
        };
        std::fs::write(dir.path().join(name), b"different").unwrap();
        assert!(VerifiedComponent::load(dir.path(), ModuleKind::Master).is_err());
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.path().join(name)).unwrap();
            std::fs::write(dir.path().join("outside"), b"component").unwrap();
            std::os::unix::fs::symlink(dir.path().join("outside"), dir.path().join(name)).unwrap();
            assert!(VerifiedComponent::load(dir.path(), ModuleKind::Master).is_err());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn supervised_module_is_reaped_on_disable() {
        let dir = bundle(b"#!/bin/sh\nexec sleep 100\n");
        let component = VerifiedComponent::load(dir.path(), ModuleKind::Master).unwrap();
        let data = tempfile::tempdir().unwrap();
        let mut child = component
            .spawn(data.path(), "https://example.test")
            .unwrap();
        let pid = child.id().unwrap();
        assert!(!child.exited().unwrap());
        child.stop().await.unwrap();
        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            -1,
            "disabled module must not remain running"
        );
    }
}
