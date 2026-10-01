use crate::AppState;
use crate::content_cache::{ContentSpec, ensure_content};
use crate::identity::unix_time_ms;
use lattice_crypto::{valid_sha256_hex, verify};
use lattice_protocol::{
    ApiError, Architecture, Platform, ReleaseChannel, ReleaseComponent, ReleaseManifest,
    SignedReleaseManifest, UpdateState, UpdateStatus,
};
use semver::Version;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

pub fn state_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("updates")
        .join("state.json")
}

pub async fn load(
    path: &Path,
    installed_version: &str,
    release_channel: ReleaseChannel,
) -> Result<UpdateStatus, String> {
    let mut status = match tokio::fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str::<UpdateStatus>(&content)
            .map_err(|error| error.to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            default_status(installed_version, release_channel.clone())
        }
        Err(error) => return Err(error.to_string()),
    };

    status.installed_version = installed_version.to_string();
    if status.release_channel != release_channel {
        status.release_channel = release_channel;
        status.available_version = None;
        status.minimum_supported_version = None;
        status.state = UpdateState::Idle;
        status.downloaded_bytes = 0;
        status.total_bytes = None;
        status.staged_version = None;
        status.staged_path = None;
        status.last_error = None;
        status.retry_count = 0;
    }

    Ok(status)
}

pub async fn run(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let interval_seconds = std::env::var("LATTICE_UPDATE_INTERVAL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(900)
        .clamp(60, 86_400);
    let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                if state.identity.read().await.trust().is_none() {
                    continue;
                }

                if let Err(error) = check_once(&state).await {
                    let snapshot = {
                        let mut status = state.update_status.write().await;
                        status.state = UpdateState::Failed;
                        status.last_error = Some(error);
                        status.retry_count = status.retry_count.saturating_add(1);
                        status.checked_at_ms = Some(unix_time_ms());
                        status.clone()
                    };
                    let _ = save(&state.update_state_path, &snapshot).await;
                }
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn check_once(state: &Arc<AppState>) -> Result<(), String> {
    let (trust, platform, architecture) = {
        let identity = state.identity.read().await;
        (
            identity
                .trust()
                .cloned()
                .ok_or_else(|| "node is not enrolled".to_string())?,
            identity.identity().platform.clone(),
            identity.identity().architecture.clone(),
        )
    };
    let channel = state.config.read().await.release_channel.clone();
    let installed_version = env!("CARGO_PKG_VERSION");

    let response = state
        .http
        .get(format!("{}/api/v1/releases/latest", trust.control_url))
        .query(&[
            ("component", "node"),
            ("channel", channel_name(&channel)),
            ("platform", platform_name(&platform)),
            ("architecture", architecture_name(&architecture)),
        ])
        .send()
        .await
        .map_err(|error| format!("release query failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Ok(error) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("{}: {}", error.code, error.message));
        }
        return Err(format!("control server returned HTTP {status}"));
    }

    let signed = response
        .json::<Option<SignedReleaseManifest>>()
        .await
        .map_err(|error| format!("invalid release response: {error}"))?;

    let Some(signed) = signed else {
        let snapshot = {
            let mut status = state.update_status.write().await;
            status.release_channel = channel;
            status.available_version = None;
            status.minimum_supported_version = None;
            status.state = UpdateState::Idle;
            status.downloaded_bytes = 0;
            status.total_bytes = None;
            status.last_error = None;
            status.retry_count = 0;
            status.checked_at_ms = Some(unix_time_ms());
            status.clone()
        };
        save(&state.update_state_path, &snapshot).await?;
        return Ok(());
    };

    let target = validate_signed(
        &trust.control_public_key,
        &signed,
        &channel,
        &platform,
        &architecture,
        installed_version,
    )?;
    let installed = Version::parse(installed_version)
        .map_err(|error| format!("invalid installed version: {error}"))?;

    if target == installed {
        let snapshot = {
            let mut status = state.update_status.write().await;
            status.release_channel = channel;
            status.available_version = None;
            status.minimum_supported_version = signed.manifest.minimum_supported_version.clone();
            status.state = UpdateState::Idle;
            status.downloaded_bytes = 0;
            status.total_bytes = None;
            status.last_error = None;
            status.retry_count = 0;
            status.checked_at_ms = Some(unix_time_ms());
            status.clone()
        };
        save(&state.update_state_path, &snapshot).await?;
        return Ok(());
    }

    let available_snapshot = {
        let mut status = state.update_status.write().await;
        status.release_channel = channel.clone();
        status.available_version = Some(signed.manifest.version.clone());
        status.minimum_supported_version = signed.manifest.minimum_supported_version.clone();
        status.state = UpdateState::Available;
        status.downloaded_bytes = 0;
        status.total_bytes = Some(signed.manifest.size_bytes);
        status.last_error = None;
        status.checked_at_ms = Some(unix_time_ms());
        status.clone()
    };
    save(&state.update_state_path, &available_snapshot).await?;

    let downloading_snapshot = {
        let mut status = state.update_status.write().await;
        status.state = UpdateState::Downloading;
        status.clone()
    };
    save(&state.update_state_path, &downloading_snapshot).await?;

    let staged_path = stage_payload(
        &state.content_http,
        &state.update_state_path,
        &signed.manifest,
    )
    .await?;

    let staged_snapshot = {
        let mut status = state.update_status.write().await;
        status.state = UpdateState::Staged;
        status.downloaded_bytes = signed.manifest.size_bytes;
        status.total_bytes = Some(signed.manifest.size_bytes);
        status.staged_version = Some(signed.manifest.version.clone());
        status.staged_path = Some(staged_path.to_string_lossy().to_string());
        status.last_error = None;
        status.retry_count = 0;
        status.checked_at_ms = Some(unix_time_ms());
        status.clone()
    };
    save(&state.update_state_path, &staged_snapshot).await?;
    Ok(())
}

pub fn validate_signed(
    control_public_key: &str,
    signed: &SignedReleaseManifest,
    channel: &ReleaseChannel,
    platform: &Platform,
    architecture: &Architecture,
    installed_version: &str,
) -> Result<Version, String> {
    verify(control_public_key, &signed.signature, &signed.manifest)
        .map_err(|error| format!("release manifest signature is invalid: {error}"))?;
    validate_manifest(&signed.manifest)?;

    let manifest = &signed.manifest;
    if manifest.component != ReleaseComponent::Node {
        return Err("release component is not lattice-node".to_string());
    }

    if &manifest.channel != channel
        || &manifest.platform != platform
        || &manifest.architecture != architecture
    {
        return Err("release manifest does not match the requested channel or local platform".to_string());
    }

    let installed = Version::parse(installed_version)
        .map_err(|error| format!("invalid installed version: {error}"))?;
    let target = Version::parse(&manifest.version)
        .map_err(|error| format!("invalid release version: {error}"))?;

    if target < installed {
        return Err(format!(
            "release downgrade rejected: installed {installed}, offered {target}"
        ));
    }

    if let Some(minimum) = manifest.minimum_supported_version.as_deref() {
        let minimum = Version::parse(minimum)
            .map_err(|error| format!("invalid minimum supported version: {error}"))?;
        if installed < minimum {
            return Err(format!(
                "installed version {installed} is below release minimum supported version {minimum}"
            ));
        }
    }

    Ok(target)
}

pub fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("unsupported release manifest schema version".to_string());
    }

    Version::parse(&manifest.version)
        .map_err(|error| format!("invalid release version: {error}"))?;

    if matches!(manifest.platform, Platform::Unknown) {
        return Err("release platform must be explicit".to_string());
    }

    if matches!(manifest.architecture, Architecture::Unknown) {
        return Err("release architecture must be explicit".to_string());
    }

    if !valid_sha256_hex(&manifest.sha256) {
        return Err("release SHA-256 must be lowercase 64-character hexadecimal".to_string());
    }

    if manifest.size_bytes == 0 {
        return Err("release size must be greater than zero".to_string());
    }

    if let Some(minimum) = manifest.minimum_supported_version.as_deref() {
        Version::parse(minimum)
            .map_err(|error| format!("invalid minimum supported version: {error}"))?;
    }

    let url = manifest.download_url.trim();
    if !url.starts_with("https://")
        && !url.starts_with("http://127.0.0.1")
        && !url.starts_with("http://localhost")
        && !url.starts_with("http://[::1]")
    {
        return Err("release download URL must use HTTPS outside localhost".to_string());
    }

    Ok(())
}

pub async fn stage_payload(
    client: &reqwest::Client,
    update_state_path: &Path,
    manifest: &ReleaseManifest,
) -> Result<PathBuf, String> {
    validate_manifest(manifest)?;
    let update_root = update_state_path
        .parent()
        .ok_or_else(|| "update state path has no parent directory".to_string())?;
    let staging_root = update_root.join("staging");
    let spec = ContentSpec {
        sha256: &manifest.sha256,
        size_bytes: manifest.size_bytes,
        download_url: &manifest.download_url,
    };
    ensure_content(client, &staging_root, &spec, 3, "release").await
}

fn default_status(installed_version: &str, release_channel: ReleaseChannel) -> UpdateStatus {
    UpdateStatus {
        installed_version: installed_version.to_string(),
        release_channel,
        available_version: None,
        minimum_supported_version: None,
        state: UpdateState::Idle,
        downloaded_bytes: 0,
        total_bytes: None,
        staged_version: None,
        staged_path: None,
        previous_version: None,
        backup_path: None,
        last_error: None,
        retry_count: 0,
        checked_at_ms: None,
    }
}

async fn save(path: &Path, status: &UpdateStatus) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
        secure_directory(parent)?;
    }

    let content = serde_json::to_vec_pretty(status).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
}

fn channel_name(channel: &ReleaseChannel) -> &'static str {
    match channel {
        ReleaseChannel::Stable => "stable",
        ReleaseChannel::Beta => "beta",
    }
}

fn platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::Macos => "macos",
        Platform::Unknown => "unknown",
    }
}

fn architecture_name(architecture: &Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
        Architecture::Unknown => "unknown",
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crypto::{encode_key, generate_private_key, public_key, sha256_hex, sign};
    use uuid::Uuid;

    fn release(bytes: &[u8], version: &str) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            component: ReleaseComponent::Node,
            version: version.to_string(),
            channel: ReleaseChannel::Stable,
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            download_url: "https://releases.example.test/lattice-node.exe".to_string(),
            minimum_supported_version: Some("0.1.0".to_string()),
            issued_at_ms: 1,
        }
    }

    #[test]
    fn signed_release_rejects_tampering_and_downgrade() {
        let private_key = generate_private_key();
        let public_key_value = encode_key(&public_key(&private_key));
        let manifest = release(b"node", "0.2.0");
        let signed = SignedReleaseManifest {
            signature: sign(&private_key, &manifest).unwrap(),
            manifest: manifest.clone(),
        };

        validate_signed(
            &public_key_value,
            &signed,
            &ReleaseChannel::Stable,
            &Platform::Windows,
            &Architecture::X86_64,
            "0.1.0",
        )
        .unwrap();

        let mut tampered = signed.clone();
        tampered.manifest.size_bytes += 1;
        assert!(
            validate_signed(
                &public_key_value,
                &tampered,
                &ReleaseChannel::Stable,
                &Platform::Windows,
                &Architecture::X86_64,
                "0.1.0",
            )
            .is_err()
        );

        let downgrade_manifest = release(b"old", "0.0.9");
        let downgrade = SignedReleaseManifest {
            signature: sign(&private_key, &downgrade_manifest).unwrap(),
            manifest: downgrade_manifest,
        };
        assert!(
            validate_signed(
                &public_key_value,
                &downgrade,
                &ReleaseChannel::Stable,
                &Platform::Windows,
                &Architecture::X86_64,
                "0.1.0",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn staging_rejects_corrupted_payload() {
        let expected = b"expected-release".to_vec();
        let served = b"corrupted-release".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await.unwrap();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    served.len()
                );
                tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes()).await.unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut stream, &served).await.unwrap();
                tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
            }
        });

        let root = std::env::temp_dir().join(format!("lattice-update-{}", Uuid::new_v4()));
        let state_path = root.join("state.json");
        let mut manifest = release(&expected, "0.2.0");
        manifest.download_url = format!("http://{address}/lattice-node.exe");
        manifest.size_bytes = served.len() as u64;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        assert!(stage_payload(&client, &state_path, &manifest).await.is_err());
        server.await.unwrap();
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn staging_accepts_verified_payload() {
        let payload = b"verified-release".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                served.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes()).await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &served).await.unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut stream).await.unwrap();
        });

        let root = std::env::temp_dir().join(format!("lattice-update-{}", Uuid::new_v4()));
        let state_path = root.join("state.json");
        let mut manifest = release(&payload, "0.2.0");
        manifest.download_url = format!("http://{address}/lattice-node.exe");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let path = stage_payload(&client, &state_path, &manifest).await.unwrap();
        server.await.unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), payload);
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
