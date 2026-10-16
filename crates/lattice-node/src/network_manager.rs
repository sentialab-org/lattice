//! The Base Node is the single host owner of network mutation.
use std::path::PathBuf;

pub(crate) fn acquire_host() -> Result<lattice_network::HostLock, String> {
    let path = match std::env::var_os("LATTICE_NETWORK_OWNER_LOCK") {
        Some(path) => PathBuf::from(path),
        None => {
            #[cfg(windows)]
            {
                PathBuf::from(
                    std::env::var_os("PROGRAMDATA").unwrap_or_else(|| r"C:\ProgramData".into()),
                )
                .join("Lattice")
                .join("network-owner.lock")
            }
            #[cfg(unix)]
            {
                PathBuf::from(lattice_ipc::UNIX_SOCKET_PATH).with_file_name("network-owner.lock")
            }
            #[cfg(not(any(unix, windows)))]
            {
                return Err("host network ownership unsupported".into());
            }
        }
    };
    lattice_network::HostLock::acquire(&path)
}

#[cfg(unix)]
pub(crate) async fn check_ipc_path() -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path =
        std::env::var("LATTICE_SOCKET").unwrap_or_else(|_| lattice_ipc::UNIX_SOCKET_PATH.into());
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                return Err("IPC path is not an owned socket; preserve and inspect it".into());
            }
            if tokio::net::UnixStream::connect(&path).await.is_ok() {
                return Err(
                    "another Node owns the IPC socket; stop its service before migration".into(),
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("IPC socket metadata unavailable".into()),
    }
}
