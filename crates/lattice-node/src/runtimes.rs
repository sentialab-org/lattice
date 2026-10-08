use crate::content_cache::{ContentSpec, ensure_content as ensure_content_object, verify_file};
use crate::identity::unix_time_ms;
use lattice_crypto::{valid_sha256_hex, verify};
use lattice_protocol::{
    Architecture, JobOffer, Platform, RuntimeCacheSummary, RuntimeManifest, SignedRuntimeManifest,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeCacheEntry {
    manifest: RuntimeManifest,
    verified_manifest_at_ms: u64,
    content_verified: bool,
    content_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RuntimeCacheIndex {
    entries: BTreeMap<String, RuntimeCacheEntry>,
}

pub fn cache_index_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("runtimes")
        .join("index.json")
}

pub async fn cache_summary(path: &Path) -> RuntimeCacheSummary {
    let index = match load_index(path).await {
        Ok(index) => index,
        Err(_) => return RuntimeCacheSummary::default(),
    };
    let manifests = index.entries.len() as u32;
    let content_verified = index
        .entries
        .values()
        .filter(|entry| entry.content_verified)
        .count() as u32;
    let verified_bytes = index
        .entries
        .values()
        .filter(|entry| entry.content_verified)
        .map(|entry| entry.manifest.size_bytes)
        .sum();

    RuntimeCacheSummary {
        manifests,
        content_verified,
        pending: manifests.saturating_sub(content_verified),
        verified_bytes,
    }
}

pub fn validate_signed(
    control_public_key: &str,
    signed: &SignedRuntimeManifest,
    offer: &JobOffer,
    platform: &Platform,
    architecture: &Architecture,
) -> Result<(), String> {
    verify(control_public_key, &signed.signature, &signed.manifest)
        .map_err(|error| format!("runtime manifest signature is invalid: {error}"))?;
    validate_manifest(&signed.manifest)?;

    let manifest = &signed.manifest;
    let runtime_matches = (manifest.runtime_id == offer.runtime
        && manifest.runtime_version == offer.runtime_version)
        || (offer.runtime == "lattice-miner" && manifest.runtime_id == "xmrig");
    if !runtime_matches || &manifest.platform != platform || &manifest.architecture != architecture
    {
        return Err("runtime manifest does not match the job or local platform".to_string());
    }

    Ok(())
}

pub async fn cache_verified_manifest(
    path: &Path,
    manifest: &RuntimeManifest,
) -> Result<(), String> {
    let mut index = load_index(path).await?;
    let key = cache_key(manifest);

    if let Some(existing) = index.entries.get_mut(&key) {
        if existing.manifest != *manifest {
            return Err("immutable runtime reference changed content".to_string());
        }
        existing.verified_manifest_at_ms = unix_time_ms();
    } else {
        index.entries.insert(
            key,
            RuntimeCacheEntry {
                manifest: manifest.clone(),
                verified_manifest_at_ms: unix_time_ms(),
                content_verified: false,
                content_path: None,
            },
        );
    }

    save_index(path, &index).await
}

pub async fn cached_offer_manifest(
    index_path: &Path,
    offer: &JobOffer,
    platform: &Platform,
    architecture: &Architecture,
) -> Result<RuntimeManifest, String> {
    let index = load_index(index_path).await?;
    let key = cache_key_from_parts(
        &offer.runtime,
        &offer.runtime_version,
        platform,
        architecture,
    );
    let entry = index
        .entries
        .get(&key)
        .ok_or_else(|| "runtime manifest is not cached".to_string())?;

    if entry.manifest.runtime_id != offer.runtime
        || entry.manifest.runtime_version != offer.runtime_version
        || &entry.manifest.platform != platform
        || &entry.manifest.architecture != architecture
    {
        return Err("cached runtime manifest does not match the job or local platform".to_string());
    }

    Ok(entry.manifest.clone())
}

pub async fn ensure_offer_content(
    client: &Client,
    index_path: &Path,
    offer: &JobOffer,
    platform: &Platform,
    architecture: &Architecture,
) -> Result<PathBuf, String> {
    let index = load_index(index_path).await?;
    let key = cache_key_from_parts(
        &offer.runtime,
        &offer.runtime_version,
        platform,
        architecture,
    );
    let entry = index
        .entries
        .get(&key)
        .ok_or_else(|| "runtime manifest is not cached".to_string())?;

    if entry.manifest.runtime_id != offer.runtime
        || entry.manifest.runtime_version != offer.runtime_version
        || &entry.manifest.platform != platform
        || &entry.manifest.architecture != architecture
    {
        return Err("cached runtime manifest does not match the job or local platform".to_string());
    }

    ensure_content(client, index_path, &entry.manifest).await
}

pub async fn ensure_content(
    client: &Client,
    index_path: &Path,
    manifest: &RuntimeManifest,
) -> Result<PathBuf, String> {
    validate_manifest(manifest)?;
    cache_verified_manifest(index_path, manifest).await?;

    let cache_root = index_path
        .parent()
        .ok_or_else(|| "runtime cache path has no parent directory".to_string())?;
    let final_path = cache_root.join("objects").join(&manifest.sha256);
    if cache_marks_content_verified(index_path, manifest).await?
        && tokio::fs::try_exists(&final_path)
            .await
            .map_err(|error| error.to_string())?
    {
        let metadata = tokio::fs::metadata(&final_path)
            .await
            .map_err(|error| error.to_string())?;
        if metadata.len() == manifest.size_bytes {
            return Ok(final_path);
        }
        clear_content_verified(index_path, manifest).await?;
    }

    let retries = std::env::var("LATTICE_RUNTIME_DOWNLOAD_RETRIES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(3)
        .clamp(1, 5);
    let spec = ContentSpec {
        sha256: &manifest.sha256,
        size_bytes: manifest.size_bytes,
        download_url: &manifest.download_url,
    };
    let path = ensure_content_object(client, cache_root, &spec, retries, "runtime").await?;
    mark_content_verified(index_path, &path, manifest).await?;
    Ok(path)
}

pub async fn mark_content_verified(
    index_path: &Path,
    content_path: &Path,
    manifest: &RuntimeManifest,
) -> Result<(), String> {
    let spec = ContentSpec {
        sha256: &manifest.sha256,
        size_bytes: manifest.size_bytes,
        download_url: &manifest.download_url,
    };
    verify_file(content_path, &spec).await?;
    let mut index = load_index(index_path).await?;
    let key = cache_key(manifest);
    let entry = index
        .entries
        .get_mut(&key)
        .ok_or_else(|| "runtime manifest is not cached".to_string())?;

    if entry.manifest != *manifest {
        return Err("cached runtime manifest changed unexpectedly".to_string());
    }

    entry.content_verified = true;
    entry.content_path = Some(content_path.to_string_lossy().to_string());
    save_index(index_path, &index).await
}

pub fn validate_manifest(manifest: &RuntimeManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("unsupported runtime manifest schema version".to_string());
    }

    if manifest.runtime_id.trim().is_empty() || manifest.runtime_version.trim().is_empty() {
        return Err("runtime identity fields must not be empty".to_string());
    }

    if manifest.runtime_version.eq_ignore_ascii_case("latest") {
        return Err("runtime version must be immutable and cannot be latest".to_string());
    }

    if matches!(manifest.platform, Platform::Unknown) {
        return Err("runtime platform must be explicit".to_string());
    }

    if matches!(manifest.architecture, Architecture::Unknown) {
        return Err("runtime architecture must be explicit".to_string());
    }

    if !valid_sha256_hex(&manifest.sha256) {
        return Err("runtime SHA-256 must be lowercase 64-character hexadecimal".to_string());
    }

    if manifest.size_bytes == 0 {
        return Err("runtime size must be greater than zero".to_string());
    }

    let url = manifest.download_url.trim();
    if !url.starts_with("https://")
        && !url.starts_with("http://127.0.0.1")
        && !url.starts_with("http://localhost")
        && !url.starts_with("http://[::1]")
    {
        return Err("runtime download URL must use HTTPS outside localhost".to_string());
    }

    Ok(())
}

async fn cache_marks_content_verified(
    index_path: &Path,
    manifest: &RuntimeManifest,
) -> Result<bool, String> {
    let index = load_index(index_path).await?;
    let key = cache_key(manifest);
    let Some(entry) = index.entries.get(&key) else {
        return Ok(false);
    };

    Ok(entry.manifest == *manifest && entry.content_verified)
}

async fn clear_content_verified(
    index_path: &Path,
    manifest: &RuntimeManifest,
) -> Result<(), String> {
    let mut index = load_index(index_path).await?;
    let key = cache_key(manifest);
    if let Some(entry) = index.entries.get_mut(&key) {
        if entry.manifest != *manifest {
            return Err("cached runtime manifest changed unexpectedly".to_string());
        }
        entry.content_verified = false;
        entry.content_path = None;
        save_index(index_path, &index).await?;
    }
    Ok(())
}

async fn load_index(path: &Path) -> Result<RuntimeCacheIndex, String> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str(&content).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(RuntimeCacheIndex::default())
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn save_index(path: &Path, index: &RuntimeCacheIndex) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
        secure_directory(parent)?;
    }

    let content = serde_json::to_vec_pretty(index).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
}

fn cache_key(manifest: &RuntimeManifest) -> String {
    cache_key_from_parts(
        &manifest.runtime_id,
        &manifest.runtime_version,
        &manifest.platform,
        &manifest.architecture,
    )
}

fn cache_key_from_parts(
    runtime_id: &str,
    runtime_version: &str,
    platform: &Platform,
    architecture: &Architecture,
) -> String {
    format!(
        "{}@{}#{:?}#{:?}",
        runtime_id, runtime_version, platform, architecture
    )
    .to_lowercase()
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
    use lattice_protocol::{ResourceLimits, WorkloadKind};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn manifest(bytes: &[u8]) -> RuntimeManifest {
        RuntimeManifest {
            schema_version: 1,
            runtime_id: "native".to_string(),
            runtime_version: "1".to_string(),
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            download_url: "https://runtimes.example.test/native.exe".to_string(),
            issued_at_ms: 1,
        }
    }

    fn offer() -> JobOffer {
        JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: WorkloadKind::Research,
            runtime: "native".to_string(),
            runtime_version: "1".to_string(),
            artifact_id: "artifact".to_string(),
            artifact_version: "1".to_string(),
            limits: ResourceLimits::default(),
            parameters: BTreeMap::new(),
            expires_at_ms: u64::MAX,
        }
    }

    #[test]
    fn signed_runtime_manifest_rejects_tampering_and_platform_mismatch() {
        let private_key = generate_private_key();
        let public_key_value = encode_key(&public_key(&private_key));
        let value = manifest(b"runtime");
        let signed = SignedRuntimeManifest {
            signature: sign(&private_key, &value).unwrap(),
            manifest: value.clone(),
        };

        validate_signed(
            &public_key_value,
            &signed,
            &offer(),
            &Platform::Windows,
            &Architecture::X86_64,
        )
        .unwrap();

        let mut tampered = signed.clone();
        tampered.manifest.size_bytes += 1;
        assert!(
            validate_signed(
                &public_key_value,
                &tampered,
                &offer(),
                &Platform::Windows,
                &Architecture::X86_64,
            )
            .is_err()
        );

        assert!(
            validate_signed(
                &public_key_value,
                &signed,
                &offer(),
                &Platform::Linux,
                &Architecture::X86_64,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_cache_downloads_and_reuses_verified_content() {
        let payload = b"runtime-payload".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request)
                .await
                .unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                served.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, header.as_bytes())
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &served)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut stream)
                .await
                .unwrap();
        });

        let root = std::env::temp_dir().join(format!("lattice-runtime-{}", Uuid::new_v4()));
        let index_path = root.join("index.json");
        let mut value = manifest(&payload);
        value.platform = Platform::Macos;
        value.architecture = Architecture::Aarch64;
        value.download_url = format!("http://{address}/runtime.bin");
        cache_verified_manifest(&index_path, &value).await.unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let path = ensure_content(&client, &index_path, &value).await.unwrap();
        server.await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), payload);

        let reused = ensure_content(&client, &index_path, &value).await.unwrap();
        assert_eq!(reused, path);

        let summary = cache_summary(&index_path).await;
        assert_eq!(summary.manifests, 1);
        assert_eq!(summary.content_verified, 1);
        assert_eq!(summary.pending, 0);

        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
