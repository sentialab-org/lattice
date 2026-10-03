use crate::{ApiResponseError, AppState, ControlIdentity};
use axum::extract::{Query, State};
use axum::Json;
use lattice_crypto::{decode_key, sign, valid_sha256_hex};
use lattice_protocol::{
    Architecture, Platform, ReleaseChannel, ReleaseComponent, ReleaseManifest, SignedReleaseManifest,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReleaseRegistry {
    pub releases: Vec<ReleaseManifest>,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseQuery {
    pub component: ReleaseComponent,
    pub channel: ReleaseChannel,
    pub platform: Platform,
    pub architecture: Architecture,
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, ReleaseRegistry), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("releases.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let registry: ReleaseRegistry = serde_json::from_str(&content)?;
            validate_registry(&registry)?;
            Ok((path, registry))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let registry = ReleaseRegistry::default();
            let content = serde_json::to_vec_pretty(&registry)?;
            tokio::fs::write(&path, content).await?;
            secure_file(&path)?;
            Ok((path, registry))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn latest(
    State(state): State<AppState>,
    Query(query): Query<ReleaseQuery>,
) -> Result<Json<Option<SignedReleaseManifest>>, ApiResponseError> {
    let release = resolve_latest(
        &state.releases,
        &query.component,
        &query.channel,
        &query.platform,
        &query.architecture,
    );

    match release {
        Some(manifest) => Ok(Json(Some(sign_manifest(&state.control, manifest)?))),
        None => Ok(Json(None)),
    }
}

pub fn resolve_latest<'a>(
    registry: &'a ReleaseRegistry,
    component: &ReleaseComponent,
    channel: &ReleaseChannel,
    platform: &Platform,
    architecture: &Architecture,
) -> Option<&'a ReleaseManifest> {
    registry
        .releases
        .iter()
        .filter(|manifest| {
            &manifest.component == component
                && &manifest.channel == channel
                && &manifest.platform == platform
                && &manifest.architecture == architecture
        })
        .max_by(|left, right| {
            let left = Version::parse(&left.version).expect("validated release version");
            let right = Version::parse(&right.version).expect("validated release version");
            left.cmp(&right)
        })
}

pub fn sign_manifest(
    control: &ControlIdentity,
    manifest: &ReleaseManifest,
) -> Result<SignedReleaseManifest, ApiResponseError> {
    let private_key = decode_key::<32>(&control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, manifest).map_err(ApiResponseError::internal)?;

    Ok(SignedReleaseManifest {
        manifest: manifest.clone(),
        signature,
    })
}

pub fn validate_registry(registry: &ReleaseRegistry) -> Result<(), String> {
    let mut keys = BTreeSet::new();

    for manifest in &registry.releases {
        validate_manifest(manifest)?;
        let key = format!(
            "{:?}:{:?}:{:?}:{:?}:{}",
            manifest.component,
            manifest.channel,
            manifest.platform,
            manifest.architecture,
            manifest.version
        );
        if !keys.insert(key) {
            return Err(format!(
                "duplicate immutable release {} {:?}/{:?}/{:?}",
                manifest.version, manifest.channel, manifest.platform, manifest.architecture
            ));
        }
    }

    Ok(())
}

pub fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), String> {
    if manifest.schema_version != 1 {
        return Err("unsupported release manifest schema version".to_string());
    }

    let version = Version::parse(&manifest.version)
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
        let minimum = Version::parse(minimum)
            .map_err(|error| format!("invalid minimum supported version: {error}"))?;
        if minimum > version {
            return Err("minimum supported version cannot exceed release version".to_string());
        }
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

    fn release(version: &str, channel: ReleaseChannel) -> ReleaseManifest {
        ReleaseManifest {
            schema_version: 1,
            component: ReleaseComponent::Node,
            version: version.to_string(),
            channel,
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            sha256: sha256_hex(b"release"),
            size_bytes: 7,
            download_url: "https://releases.example.test/lattice-node.exe".to_string(),
            minimum_supported_version: Some("0.1.0".to_string()),
            issued_at_ms: 1,
        }
    }

    #[test]
    fn registry_selects_highest_matching_release() {
        let registry = ReleaseRegistry {
            releases: vec![
                release("0.2.0", ReleaseChannel::Stable),
                release("0.3.0", ReleaseChannel::Stable),
                release("0.4.0-beta.1", ReleaseChannel::Beta),
            ],
        };

        validate_registry(&registry).unwrap();
        let latest = resolve_latest(
            &registry,
            &ReleaseComponent::Node,
            &ReleaseChannel::Stable,
            &Platform::Windows,
            &Architecture::X86_64,
        )
        .unwrap();
        assert_eq!(latest.version, "0.3.0");
    }

    #[test]
    fn manifest_rejects_insecure_remote_url() {
        let mut manifest = release("0.2.0", ReleaseChannel::Stable);
        manifest.download_url = "http://example.test/lattice-node.exe".to_string();
        assert!(validate_manifest(&manifest).is_err());
    }
}
