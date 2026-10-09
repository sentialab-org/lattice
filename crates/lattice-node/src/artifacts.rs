use crate::identity::unix_time_ms;
use lattice_crypto::{valid_sha256_hex, verify};
use lattice_protocol::{ArtifactCacheSummary, ArtifactManifest, JobOffer, SignedArtifactManifest};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactCacheEntry {
    manifest: ArtifactManifest,
    verified_manifest_at_ms: u64,
    content_verified: bool,
    content_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ArtifactCacheIndex {
    entries: BTreeMap<String, ArtifactCacheEntry>,
}

pub async fn cache_summary(path: &Path) -> ArtifactCacheSummary {
    let index = match load_index(path).await {
        Ok(index) => index,
        Err(_) => return ArtifactCacheSummary::default(),
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

    ArtifactCacheSummary {
        manifests,
        content_verified,
        pending: manifests.saturating_sub(content_verified),
        verified_bytes,
    }
}

pub fn cache_index_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("artifacts")
        .join("index.json")
}

pub fn validate_signed(
    control_public_key: &str,
    signed: &SignedArtifactManifest,
    offer: &JobOffer,
) -> Result<(), String> {
    verify(control_public_key, &signed.signature, &signed.manifest)
        .map_err(|error| format!("artifact manifest signature is invalid: {error}"))?;
    validate_manifest(&signed.manifest)?;

    let manifest = &signed.manifest;
    if manifest.artifact_id != offer.artifact_id
        || manifest.artifact_version != offer.artifact_version
        || manifest.runtime != offer.runtime
        || manifest.runtime_version != offer.runtime_version
    {
        return Err("artifact manifest does not match the job runtime reference".to_string());
    }

    Ok(())
}

pub async fn cache_verified_manifest(
    path: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), String> {
    let mut index = load_index(path).await?;
    let key = cache_key(manifest);

    if let Some(existing) = index.entries.get_mut(&key) {
        if existing.manifest != *manifest {
            return Err("immutable artifact reference changed content".to_string());
        }
        existing.verified_manifest_at_ms = unix_time_ms();
    } else {
        index.entries.insert(
            key,
            ArtifactCacheEntry {
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
) -> Result<ArtifactManifest, String> {
    let index = load_index(index_path).await?;
    let key = format!("{}@{}", offer.artifact_id, offer.artifact_version);
    let entry = index
        .entries
        .get(&key)
        .ok_or_else(|| "artifact manifest is not cached".to_string())?;

    if entry.manifest.artifact_id != offer.artifact_id
        || entry.manifest.artifact_version != offer.artifact_version
        || entry.manifest.runtime != offer.runtime
        || entry.manifest.runtime_version != offer.runtime_version
    {
        return Err(
            "cached artifact manifest does not match the job runtime reference".to_string(),
        );
    }

    Ok(entry.manifest.clone())
}

pub async fn ensure_offer_content(
    client: &Client,
    index_path: &Path,
    offer: &JobOffer,
) -> Result<PathBuf, String> {
    let index = load_index(index_path).await?;
    let key = format!("{}@{}", offer.artifact_id, offer.artifact_version);
    let entry = index
        .entries
        .get(&key)
        .ok_or_else(|| "artifact manifest is not cached".to_string())?;

    if entry.manifest.artifact_id != offer.artifact_id
        || entry.manifest.artifact_version != offer.artifact_version
        || entry.manifest.runtime != offer.runtime
        || entry.manifest.runtime_version != offer.runtime_version
    {
        return Err(
            "cached artifact manifest does not match the job runtime reference".to_string(),
        );
    }

    ensure_content(client, index_path, &entry.manifest).await
}

pub async fn ensure_content(
    client: &Client,
    index_path: &Path,
    manifest: &ArtifactManifest,
) -> Result<PathBuf, String> {
    validate_manifest(manifest)?;
    cache_verified_manifest(index_path, manifest).await?;

    let cache_root = index_path
        .parent()
        .ok_or_else(|| "artifact cache path has no parent directory".to_string())?;
    let objects_dir = cache_root.join("objects");
    let temp_dir = cache_root.join("tmp");
    tokio::fs::create_dir_all(&objects_dir)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|error| error.to_string())?;
    secure_directory(&objects_dir)?;
    secure_directory(&temp_dir)?;
    cleanup_temp_files(&temp_dir).await?;

    let final_path = objects_dir.join(&manifest.sha256);

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

    if tokio::fs::try_exists(&final_path)
        .await
        .map_err(|error| error.to_string())?
    {
        match verify_file(&final_path, manifest).await {
            Ok(()) => {
                mark_content_verified(index_path, &final_path, manifest).await?;
                return Ok(final_path);
            }
            Err(_) => {
                tokio::fs::remove_file(&final_path)
                    .await
                    .map_err(|error| error.to_string())?;
                clear_content_verified(index_path, manifest).await?;
            }
        }
    }

    let retries = std::env::var("LATTICE_ARTIFACT_DOWNLOAD_RETRIES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(3)
        .clamp(1, 5);
    let mut last_error = "artifact download failed".to_string();

    for attempt in 1..=retries {
        let temp_path = temp_dir.join(format!("{}.part", Uuid::new_v4().simple()));
        match download_once(client, manifest, &temp_path).await {
            Ok(()) => {
                if tokio::fs::try_exists(&final_path)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    if verify_file(&final_path, manifest).await.is_ok() {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        mark_content_verified(index_path, &final_path, manifest).await?;
                        return Ok(final_path);
                    }
                    tokio::fs::remove_file(&final_path)
                        .await
                        .map_err(|error| error.to_string())?;
                }

                tokio::fs::rename(&temp_path, &final_path)
                    .await
                    .map_err(|error| error.to_string())?;
                secure_file(&final_path)?;
                verify_file(&final_path, manifest).await?;
                mark_content_verified(index_path, &final_path, manifest).await?;
                return Ok(final_path);
            }
            Err(error) => {
                last_error = error;
                let _ = tokio::fs::remove_file(&temp_path).await;
                if attempt < retries {
                    tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
                }
            }
        }
    }

    Err(last_error)
}

pub async fn mark_content_verified(
    index_path: &Path,
    content_path: &Path,
    manifest: &ArtifactManifest,
) -> Result<(), String> {
    verify_file(content_path, manifest).await?;
    let mut index = load_index(index_path).await?;
    let key = cache_key(manifest);
    let entry = index
        .entries
        .get_mut(&key)
        .ok_or_else(|| "artifact manifest is not cached".to_string())?;

    if entry.manifest != *manifest {
        return Err("cached artifact manifest changed unexpectedly".to_string());
    }

    entry.content_verified = true;
    entry.content_path = Some(content_path.to_string_lossy().to_string());
    save_index(index_path, &index).await
}

pub async fn verify_file(path: &Path, manifest: &ArtifactManifest) -> Result<(), String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| error.to_string())?;

    if metadata.len() != manifest.size_bytes {
        return Err("artifact size does not match the signed manifest".to_string());
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    if digest != manifest.sha256 {
        return Err("artifact SHA-256 does not match the signed manifest".to_string());
    }

    Ok(())
}

async fn cleanup_temp_files(temp_dir: &Path) -> Result<(), String> {
    let mut entries = tokio::fs::read_dir(temp_dir)
        .await
        .map_err(|error| error.to_string())?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| error.to_string())?
    {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "part")
        {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    Ok(())
}

async fn download_once(
    client: &Client,
    manifest: &ArtifactManifest,
    temp_path: &Path,
) -> Result<(), String> {
    let mut response = client
        .get(&manifest.download_url)
        .send()
        .await
        .map_err(|error| format!("artifact request failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "artifact server returned HTTP {}",
            response.status()
        ));
    }

    if let Some(length) = response.content_length()
        && length != manifest.size_bytes
    {
        return Err("artifact Content-Length does not match the signed manifest".to_string());
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temp_path)
        .await
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("artifact download failed: {error}"))?
    {
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| "artifact size overflow".to_string())?;
        if total > manifest.size_bytes {
            return Err("artifact exceeded the signed size".to_string());
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|error| error.to_string())?;
    }

    if total != manifest.size_bytes {
        return Err("artifact size does not match the signed manifest".to_string());
    }

    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != manifest.sha256 {
        return Err("artifact SHA-256 does not match the signed manifest".to_string());
    }

    file.flush().await.map_err(|error| error.to_string())?;
    file.sync_all().await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn cache_marks_content_verified(
    index_path: &Path,
    manifest: &ArtifactManifest,
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
    manifest: &ArtifactManifest,
) -> Result<(), String> {
    let mut index = load_index(index_path).await?;
    let key = cache_key(manifest);
    if let Some(entry) = index.entries.get_mut(&key) {
        if entry.manifest != *manifest {
            return Err("cached artifact manifest changed unexpectedly".to_string());
        }
        entry.content_verified = false;
        entry.content_path = None;
        save_index(index_path, &index).await?;
    }
    Ok(())
}

pub fn validate_manifest(manifest: &ArtifactManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("unsupported artifact manifest schema version".to_string());
    }

    if manifest.artifact_id.trim().is_empty()
        || manifest.artifact_version.trim().is_empty()
        || manifest.runtime.trim().is_empty()
        || manifest.runtime_version.trim().is_empty()
    {
        return Err("artifact identity and runtime fields must not be empty".to_string());
    }

    if manifest.artifact_version.eq_ignore_ascii_case("latest") {
        return Err("artifact version must be immutable and cannot be latest".to_string());
    }

    if !valid_sha256_hex(&manifest.sha256) {
        return Err("artifact SHA-256 must be lowercase 64-character hexadecimal".to_string());
    }

    if manifest.size_bytes == 0 {
        return Err("artifact size must be greater than zero".to_string());
    }

    let url = manifest.download_url.trim();
    if !url.starts_with("https://")
        && !url.starts_with("http://127.0.0.1")
        && !url.starts_with("http://localhost")
        && !url.starts_with("http://[::1]")
    {
        return Err("artifact download URL must use HTTPS outside localhost".to_string());
    }

    Ok(())
}

async fn load_index(path: &Path) -> Result<ArtifactCacheIndex, String> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str(&content).map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(ArtifactCacheIndex::default())
        }
        Err(error) => Err(error.to_string()),
    }
}

async fn save_index(path: &Path, index: &ArtifactCacheIndex) -> Result<(), String> {
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

fn cache_key(manifest: &ArtifactManifest) -> String {
    format!("{}@{}", manifest.artifact_id, manifest.artifact_version)
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
    use lattice_crypto::sha256_hex;
    use uuid::Uuid;

    fn manifest(bytes: &[u8]) -> ArtifactManifest {
        ArtifactManifest {
            schema_version: 1,
            artifact_id: "artifact-test".to_string(),
            artifact_version: "1".to_string(),
            runtime: "native".to_string(),
            runtime_version: "1".to_string(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            download_url: "https://artifacts.example.test/file".to_string(),
            issued_at_ms: 1,
        }
    }

    #[test]
    fn signed_manifest_rejects_tampering_and_runtime_mismatch() {
        let private_key = lattice_crypto::generate_private_key();
        let public_key = lattice_crypto::encode_key(&lattice_crypto::public_key(&private_key));
        let value = manifest(b"lattice");
        let signature = lattice_crypto::sign(&private_key, &value).unwrap();
        let signed = SignedArtifactManifest {
            manifest: value.clone(),
            signature: signature.clone(),
        };
        let offer = JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: lattice_protocol::WorkloadKind::Research,
            runtime: value.runtime.clone(),
            runtime_version: value.runtime_version.clone(),
            artifact_id: value.artifact_id.clone(),
            artifact_version: value.artifact_version.clone(),
            limits: lattice_protocol::ResourceLimits::default(),
            parameters: std::collections::BTreeMap::new(),
            expires_at_ms: u64::MAX,
        };

        validate_signed(&public_key, &signed, &offer).unwrap();

        let mut tampered = signed.clone();
        tampered.manifest.size_bytes += 1;
        assert!(validate_signed(&public_key, &tampered, &offer).is_err());

        let mut mismatched_offer = offer;
        mismatched_offer.runtime_version = "2".to_string();
        assert!(validate_signed(&public_key, &signed, &mismatched_offer).is_err());
    }

    #[tokio::test]
    async fn cache_metadata_is_immutable_and_content_can_be_verified() {
        let root = std::env::temp_dir().join(format!("lattice-artifact-cache-{}", Uuid::new_v4()));
        let index_path = root.join("index.json");
        let content_path = root.join("payload.bin");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(&content_path, b"lattice").await.unwrap();

        let value = manifest(b"lattice");
        cache_verified_manifest(&index_path, &value).await.unwrap();
        mark_content_verified(&index_path, &content_path, &value)
            .await
            .unwrap();

        let index: ArtifactCacheIndex =
            serde_json::from_str(&tokio::fs::read_to_string(&index_path).await.unwrap()).unwrap();
        let entry = index.entries.get("artifact-test@1").unwrap();
        assert!(entry.content_verified);
        assert_eq!(
            entry.content_path.as_deref(),
            Some(content_path.to_string_lossy().as_ref())
        );

        cache_verified_manifest(&index_path, &value).await.unwrap();
        let index: ArtifactCacheIndex =
            serde_json::from_str(&tokio::fs::read_to_string(&index_path).await.unwrap()).unwrap();
        let entry = index.entries.get("artifact-test@1").unwrap();
        assert!(entry.content_verified);
        assert_eq!(
            entry.content_path.as_deref(),
            Some(content_path.to_string_lossy().as_ref())
        );

        let mut changed = value.clone();
        changed.sha256 = "0".repeat(64);
        assert!(
            cache_verified_manifest(&index_path, &changed)
                .await
                .is_err()
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn downloader_promotes_verified_content_and_reuses_cache() {
        let payload = b"downloaded-lattice-artifact".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let served = payload.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                served.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&served).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let root = std::env::temp_dir().join(format!("lattice-download-{}", Uuid::new_v4()));
        let index_path = root.join("index.json");
        let mut value = manifest(&payload);
        value.download_url = format!("http://{address}/artifact.bin");
        cache_verified_manifest(&index_path, &value).await.unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let content_path = ensure_content(&client, &index_path, &value).await.unwrap();
        server.await.unwrap();
        assert_eq!(tokio::fs::read(&content_path).await.unwrap(), payload);
        verify_file(&content_path, &value).await.unwrap();

        let reused = ensure_content(&client, &index_path, &value).await.unwrap();
        assert_eq!(reused, content_path);

        let index: ArtifactCacheIndex =
            serde_json::from_str(&tokio::fs::read_to_string(&index_path).await.unwrap()).unwrap();
        let entry = index.entries.get("artifact-test@1").unwrap();
        assert!(entry.content_verified);
        assert_eq!(
            entry.content_path.as_deref(),
            Some(content_path.to_string_lossy().as_ref())
        );

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn downloader_rejects_invalid_payload_and_cleans_temp_files() {
        let served = b"bad-payload".to_vec();
        let expected = b"expected-payload".to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                served.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(&served).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let root = std::env::temp_dir().join(format!("lattice-download-bad-{}", Uuid::new_v4()));
        let index_path = root.join("index.json");
        let mut value = manifest(&expected);
        value.download_url = format!("http://{address}/artifact.bin");
        cache_verified_manifest(&index_path, &value).await.unwrap();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        assert!(ensure_content(&client, &index_path, &value).await.is_err());
        server.await.unwrap();

        let temp_dir = root.join("tmp");
        let mut entries = tokio::fs::read_dir(&temp_dir).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
        assert!(!root.join("objects").join(&value.sha256).exists());

        let index: ArtifactCacheIndex =
            serde_json::from_str(&tokio::fs::read_to_string(&index_path).await.unwrap()).unwrap();
        let entry = index.entries.get("artifact-test@1").unwrap();
        assert!(!entry.content_verified);

        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn file_hash_validation_detects_tampering() {
        let path = std::env::temp_dir().join(format!("lattice-{}.bin", Uuid::new_v4()));
        tokio::fs::write(&path, b"lattice").await.unwrap();

        let expected = manifest(b"lattice");
        verify_file(&path, &expected).await.unwrap();

        tokio::fs::write(&path, b"changed").await.unwrap();
        assert!(verify_file(&path, &expected).await.is_err());

        let _ = tokio::fs::remove_file(path).await;
    }
}
