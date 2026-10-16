//! Private transport for a Base Node managed controller module.
use axum::Router;
use std::path::Path;
type Error = Box<dyn std::error::Error + Send + Sync>;

#[cfg(unix)]
pub async fn serve(
    app: Router,
    data: &Path,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = data.join("module-http.sock");
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err("module socket path is not a socket".into());
            }
            if tokio::net::UnixStream::connect(&path).await.is_ok() {
                return Err("module backend already running".into());
            }
            std::fs::remove_file(&path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|v| *v).await;
        })
        .await;
    let _ = std::fs::remove_file(path);
    result.map_err(Into::into)
}

#[cfg(windows)]
pub async fn serve(
    app: Router,
    data: &Path,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error> {
    let name = format!(
        r"\\.\pipe\lattice-module-{}",
        &lattice_crypto::sha256_hex(data.to_string_lossy().as_bytes())[..32]
    );
    let listener = PrivatePipeListener {
        name: name.clone(),
        pending: Some(private_pipe(&name, true)?),
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|v| *v).await;
        })
        .await?;
    Ok(())
}
#[cfg(windows)]
struct PrivatePipeListener {
    name: String,
    pending: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}
#[cfg(windows)]
impl axum::serve::Listener for PrivatePipeListener {
    type Io = tokio::net::windows::named_pipe::NamedPipeServer;
    type Addr = String;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let server = match self.pending.take() {
                Some(s) => s,
                None => match private_pipe(&self.name, false) {
                    Ok(s) => s,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            if server.connect().await.is_ok() {
                return (server, self.name.clone());
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.name.clone())
    }
}
#[cfg(windows)]
fn private_pipe(
    name: &str,
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ptr::null_mut;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        },
    };
    let text = "D:P(A;;GA;;;SY)(A;;GA;;;BA)\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                &mut attributes as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
            )
    };
    unsafe {
        LocalFree(descriptor as _);
    }
    result
}
