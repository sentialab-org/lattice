use lattice_crypto::{decode_bytes, encode_bytes, encode_key, generate_private_key, public_key};
use lattice_protocol::{
    Architecture, ControlTrust, EnrollmentState, EnrollmentStatus, NodeIdentity, Platform,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::System;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    identity: NodeIdentity,
    private_key_blob: String,
    trust: Option<ControlTrust>,
}

#[derive(Debug, Clone)]
pub struct IdentityState {
    path: PathBuf,
    record: StoredIdentity,
    private_key: [u8; 32],
}

impl IdentityState {
    pub async fn load_or_create(path: PathBuf) -> Result<Self, String> {
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => Self::from_stored(path, &content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::create(path).await,
            Err(error) => Err(error.to_string()),
        }
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.record.identity
    }

    pub fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    pub fn trust(&self) -> Option<&ControlTrust> {
        self.record.trust.as_ref()
    }

    pub fn status(&self) -> EnrollmentStatus {
        EnrollmentStatus {
            state: if self.record.trust.is_some() {
                EnrollmentState::Enrolled
            } else {
                EnrollmentState::Unenrolled
            },
            identity: self.record.identity.clone(),
            trust: self.record.trust.clone(),
        }
    }

    pub async fn set_trust(&mut self, trust: ControlTrust) -> Result<(), String> {
        self.record.trust = Some(trust);
        self.persist().await
    }

    pub async fn clear_trust(&mut self) -> Result<(), String> {
        self.record.trust = None;
        self.persist().await
    }

    pub async fn update_policy_revision(&mut self, revision: u64) -> Result<(), String> {
        let Some(trust) = self.record.trust.as_mut() else {
            return Err("node is not enrolled".to_string());
        };

        if trust.policy_revision == revision {
            return Ok(());
        }

        trust.policy_revision = revision;
        self.persist().await
    }

    async fn create(path: PathBuf) -> Result<Self, String> {
        let private_key = generate_private_key();
        let public_key_value = encode_key(&public_key(&private_key));
        let identity = NodeIdentity {
            node_id: format!("node_{}", Uuid::new_v4().simple()),
            node_name: System::host_name().unwrap_or_else(|| "lattice-node".to_string()),
            platform: current_platform(),
            architecture: current_architecture(),
            public_key: public_key_value,
            created_at_ms: unix_time_ms(),
        };
        let private_key_blob = protect_private_key(&private_key)?;
        let mut state = Self {
            path,
            record: StoredIdentity {
                identity,
                private_key_blob,
                trust: None,
            },
            private_key,
        };
        state.persist().await?;
        Ok(state)
    }

    fn from_stored(path: PathBuf, content: &str) -> Result<Self, String> {
        let record: StoredIdentity =
            serde_json::from_str(content).map_err(|error| error.to_string())?;
        let private_key = unprotect_private_key(&record.private_key_blob)?;
        let expected_public_key = encode_key(&public_key(&private_key));

        if expected_public_key != record.identity.public_key {
            return Err(
                "node identity public key does not match the stored private key".to_string(),
            );
        }

        Ok(Self {
            path,
            record,
            private_key,
        })
    }

    async fn persist(&mut self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| error.to_string())?;
            secure_directory(parent)?;
        }

        let content = serde_json::to_vec_pretty(&self.record).map_err(|error| error.to_string())?;
        tokio::fs::write(&self.path, content)
            .await
            .map_err(|error| error.to_string())?;
        secure_file(&self.path)
    }
}

pub fn identity_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("identity.json")
}

pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn current_platform() -> Platform {
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Unknown
    }
}

fn current_architecture() -> Architecture {
    match std::env::consts::ARCH {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        _ => Architecture::Unknown,
    }
}

#[cfg(windows)]
fn protect_private_key(private_key: &[u8; 32]) -> Result<String, String> {
    use std::ptr::null;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: private_key.len() as u32,
        pbData: private_key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };

    unsafe {
        LocalFree(output.pbData.cast());
    }

    Ok(encode_bytes(&protected))
}

#[cfg(windows)]
fn unprotect_private_key(value: &str) -> Result<[u8; 32], String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let mut protected = decode_bytes(value)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let mut description = null_mut();
    let result = unsafe {
        CryptUnprotectData(
            &input,
            &mut description,
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let decrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };

    unsafe {
        LocalFree(output.pbData.cast());
        if !description.is_null() {
            LocalFree(description.cast());
        }
    }

    decrypted
        .try_into()
        .map_err(|_| "invalid DPAPI private key length".to_string())
}

#[cfg(not(windows))]
fn protect_private_key(private_key: &[u8; 32]) -> Result<String, String> {
    Ok(encode_bytes(private_key))
}

#[cfg(not(windows))]
fn unprotect_private_key(value: &str) -> Result<[u8; 32], String> {
    decode_bytes(value)?
        .try_into()
        .map_err(|_| "invalid private key length".to_string())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}
