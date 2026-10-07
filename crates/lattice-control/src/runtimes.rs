use crate::{ApiResponseError, ControlIdentity};
use lattice_crypto::{decode_key, sign, valid_sha256_hex};
use lattice_protocol::{Architecture, JobOffer, Platform, RuntimeManifest, SignedRuntimeManifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeRegistry {
    pub runtimes: Vec<RuntimeManifest>,
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, RuntimeRegistry), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("runtimes.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let registry: RuntimeRegistry = serde_json::from_str(&content)?;
            validate_registry(&registry)?;
            Ok((path, registry))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let registry = RuntimeRegistry::default();
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
    registry: &mut RuntimeRegistry,
    manifest: RuntimeManifest,
) -> Result<RuntimeManifest, String> {
    validate_manifest(&manifest)?;

    if let Some(existing) = registry.runtimes.iter().find(|existing| {
        existing.runtime_id == manifest.runtime_id
            && existing.runtime_version == manifest.runtime_version
            && existing.platform == manifest.platform
            && existing.architecture == manifest.architecture
    }) {
        let same_content = existing.sha256 == manifest.sha256
            && existing.size_bytes == manifest.size_bytes
            && existing.download_url == manifest.download_url;
        if same_content {
            return Ok(existing.clone());
        }
        return Err(
            "immutable runtime reference already exists with different content".to_string(),
        );
    }

    registry.runtimes.push(manifest.clone());
    validate_registry(registry)?;
    save_path(path, registry).await?;
    Ok(manifest)
}

pub fn resolve<'a>(
    registry: &'a RuntimeRegistry,
    offer: &JobOffer,
    platform: &Platform,
    architecture: &Architecture,
) -> Option<&'a RuntimeManifest> {
    if let Some(m) = registry.runtimes.iter().find(|manifest| {
        manifest.runtime_id == offer.runtime
            && manifest.runtime_version == offer.runtime_version
            && &manifest.platform == platform
            && &manifest.architecture == architecture
    }) {
        return Some(m);
    }

    // Explicit immutable logical contract mapping: lattice-miner@1.0.0 -> xmrig@6.22.2 (CRIT-13)
    if offer.runtime == "lattice-miner" && offer.runtime_version == "1.0.0" {
        return registry.runtimes.iter().find(|manifest| {
            manifest.runtime_id == "xmrig"
                && manifest.runtime_version == "6.22.2"
                && &manifest.platform == platform
                && &manifest.architecture == architecture
        });
    }

    None
}

pub fn sign_for_offer(
    control: &ControlIdentity,
    registry: &RuntimeRegistry,
    offer: &JobOffer,
    platform: &Platform,
    architecture: &Architecture,
) -> Result<SignedRuntimeManifest, ApiResponseError> {
    let manifest = resolve(registry, offer, platform, architecture).ok_or_else(|| {
        ApiResponseError::conflict(
            "unknown_runtime",
            "job references an unknown or incompatible runtime",
        )
    })?;
    let private_key = decode_key::<32>(&control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, manifest).map_err(ApiResponseError::internal)?;

    Ok(SignedRuntimeManifest {
        manifest: manifest.clone(),
        signature,
    })
}

fn validate_registry(registry: &RuntimeRegistry) -> Result<(), String> {
    let mut keys = BTreeSet::new();

    for manifest in &registry.runtimes {
        validate_manifest(manifest)?;
        let key = (
            manifest.runtime_id.clone(),
            manifest.runtime_version.clone(),
            format!("{:?}", manifest.platform),
            format!("{:?}", manifest.architecture),
        );
        if !keys.insert(key) {
            return Err(format!(
                "duplicate immutable runtime reference {}@{} for {:?}/{:?}",
                manifest.runtime_id,
                manifest.runtime_version,
                manifest.platform,
                manifest.architecture
            ));
        }
    }

    Ok(())
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

    validate_download_url(&manifest.download_url)
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

    Err("runtime download URL must use HTTPS outside localhost".to_string())
}

async fn save_path(path: &Path, registry: &RuntimeRegistry) -> Result<(), String> {
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

    fn manifest(version: &str) -> RuntimeManifest {
        RuntimeManifest {
            schema_version: 1,
            runtime_id: "native".to_string(),
            runtime_version: version.to_string(),
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            sha256: "0".repeat(64),
            size_bytes: 128,
            download_url: "https://runtimes.example.test/native.exe".to_string(),
            issued_at_ms: 1,
        }
    }

    #[test]
    fn registry_rejects_duplicate_platform_runtime() {
        let registry = RuntimeRegistry {
            runtimes: vec![manifest("1"), manifest("1")],
        };
        assert!(validate_registry(&registry).is_err());
    }

    #[test]
    fn resolve_requires_exact_platform_and_architecture() {
        let value = manifest("1");
        let registry = RuntimeRegistry {
            runtimes: vec![value],
        };
        let offer = JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: lattice_protocol::WorkloadKind::Research,
            runtime: "native".to_string(),
            runtime_version: "1".to_string(),
            artifact_id: "artifact".to_string(),
            artifact_version: "1".to_string(),
            limits: lattice_protocol::ResourceLimits::default(),
            parameters: std::collections::BTreeMap::new(),
            expires_at_ms: u64::MAX,
        };

        assert!(resolve(&registry, &offer, &Platform::Windows, &Architecture::X86_64).is_some());
        assert!(resolve(&registry, &offer, &Platform::Linux, &Architecture::X86_64).is_none());
        assert!(
            resolve(
                &registry,
                &offer,
                &Platform::Windows,
                &Architecture::Aarch64
            )
            .is_none()
        );
    }
}
