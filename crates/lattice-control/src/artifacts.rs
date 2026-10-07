use crate::{ApiResponseError, ControlIdentity};
use lattice_crypto::{decode_key, sign, valid_sha256_hex};
use lattice_protocol::{ArtifactManifest, JobOffer, SignedArtifactManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactRegistry {
    pub artifacts: Vec<ArtifactManifest>,
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, ArtifactRegistry), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("artifacts.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let registry: ArtifactRegistry = serde_json::from_str(&content)?;
            validate_registry(&registry)?;
            Ok((path, registry))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let registry = ArtifactRegistry::default();
            let content = serde_json::to_vec_pretty(&registry)?;
            tokio::fs::write(&path, content).await?;
            secure_file(&path)?;
            Ok((path, registry))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn insert_immutable(
    path: &Path,
    registry: &mut ArtifactRegistry,
    manifest: ArtifactManifest,
) -> Result<ArtifactManifest, String> {
    validate_manifest(&manifest)?;

    if let Some(existing) = registry.artifacts.iter().find(|existing| {
        existing.artifact_id == manifest.artifact_id
            && existing.artifact_version == manifest.artifact_version
    }) {
        let same_content = existing.runtime == manifest.runtime
            && existing.runtime_version == manifest.runtime_version
            && existing.sha256 == manifest.sha256
            && existing.size_bytes == manifest.size_bytes
            && existing.download_url == manifest.download_url;
        if same_content {
            return Ok(existing.clone());
        }
        return Err(
            "immutable artifact reference already exists with different content".to_string(),
        );
    }

    registry.artifacts.push(manifest.clone());
    validate_registry(registry)?;
    save_path(path, registry).await?;
    Ok(manifest)
}

pub fn resolve<'a>(
    registry: &'a ArtifactRegistry,
    offer: &JobOffer,
) -> Option<&'a ArtifactManifest> {
    if let Some(m) = registry.artifacts.iter().find(|manifest| {
        manifest.artifact_id == offer.artifact_id
            && manifest.artifact_version == offer.artifact_version
            && manifest.runtime == offer.runtime
            && manifest.runtime_version == offer.runtime_version
    }) {
        return Some(m);
    }

    // Explicit immutable mapping for lattice-miner@1.0.0 (CRIT-14)
    if offer.runtime == "lattice-miner" && offer.runtime_version == "1.0.0" {
        return registry.artifacts.iter().find(|manifest| {
            manifest.artifact_id == offer.artifact_id
                && manifest.artifact_version == offer.artifact_version
                && manifest.runtime == "xmrig"
                && manifest.runtime_version == "6.22.2"
        });
    }

    None
}

pub fn sign_for_offer(
    control: &ControlIdentity,
    registry: &ArtifactRegistry,
    offer: &JobOffer,
) -> Result<SignedArtifactManifest, ApiResponseError> {
    let manifest = resolve(registry, offer).ok_or_else(|| {
        ApiResponseError::conflict(
            "unknown_artifact",
            "job references an unknown or runtime-incompatible artifact",
        )
    })?;
    let private_key = decode_key::<32>(&control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, manifest).map_err(ApiResponseError::internal)?;

    Ok(SignedArtifactManifest {
        manifest: manifest.clone(),
        signature,
    })
}

fn validate_registry(registry: &ArtifactRegistry) -> Result<(), String> {
    let mut keys = BTreeSet::new();

    for manifest in &registry.artifacts {
        validate_manifest(manifest)?;
        let key = (
            manifest.artifact_id.clone(),
            manifest.artifact_version.clone(),
        );
        if !keys.insert(key) {
            return Err(format!(
                "duplicate immutable artifact reference {}@{}",
                manifest.artifact_id, manifest.artifact_version
            ));
        }
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

    validate_download_url(&manifest.download_url)?;

    Ok(())
}

fn validate_download_url(value: &str) -> Result<(), String> {
    let value = value.trim();

    if value.starts_with("https://")
        || value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value.starts_with("http://[::1]")
    {
        return Ok(());
    }

    Err("artifact download URL must use HTTPS outside localhost".to_string())
}

async fn save_path(path: &Path, registry: &ArtifactRegistry) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(registry).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
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

    fn manifest(version: &str) -> ArtifactManifest {
        ArtifactManifest {
            schema_version: 1,
            artifact_id: "artifact-test".to_string(),
            artifact_version: version.to_string(),
            runtime: "native".to_string(),
            runtime_version: "1".to_string(),
            sha256: "0".repeat(64),
            size_bytes: 128,
            download_url: "https://artifacts.example.test/file".to_string(),
            issued_at_ms: 1,
        }
    }

    #[test]
    fn immutable_registry_rejects_duplicate_reference() {
        let registry = ArtifactRegistry {
            artifacts: vec![manifest("1"), manifest("1")],
        };
        assert!(validate_registry(&registry).is_err());
    }

    #[test]
    fn resolve_requires_exact_runtime_binding() {
        let value = manifest("1");
        let registry = ArtifactRegistry {
            artifacts: vec![value.clone()],
        };
        let mut offer = JobOffer {
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

        assert!(resolve(&registry, &offer).is_some());
        offer.runtime_version = "2".to_string();
        assert!(resolve(&registry, &offer).is_none());
        offer.runtime_version = value.runtime_version;
        offer.artifact_version = "missing".to_string();
        assert!(resolve(&registry, &offer).is_none());
    }

    #[test]
    fn manifest_rejects_mutable_version_and_invalid_hash() {
        let mut value = manifest("latest");
        assert!(validate_manifest(&value).is_err());
        value.artifact_version = "1".to_string();
        value.sha256 = "ABC".to_string();
        assert!(validate_manifest(&value).is_err());
    }
}
