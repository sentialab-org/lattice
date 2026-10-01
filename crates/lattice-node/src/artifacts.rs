use crate::identity::unix_time_ms;
use lattice_crypto::{valid_sha256_hex, verify};
use lattice_protocol::{ArtifactManifest, JobOffer, SignedArtifactManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;

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
