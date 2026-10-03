use crate::{ApiResponseError, AppState, artifacts, content, jobs, runtimes, unix_time_ms};
use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use lattice_protocol::{
    Architecture, ArtifactManifest, JobOffer, NodeHealth, NodePolicy, Platform, ResourceLimits,
    RuntimeManifest, WorkloadKind, mining_config_from_offer,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use uuid::Uuid;

const XMRIG_PROFILE_ID: &str = "xmrig-mining-profile";

#[derive(Debug, Deserialize)]
pub struct QueueMiningJobRequest {
    pub target_node_id: Option<String>,
    pub runtime_version: String,
    pub algorithm: String,
    pub pool: String,
    pub wallet: String,
    pub worker: String,
    pub password: Option<String>,
    pub threads: u16,
    pub cpu_percent: u8,
    pub memory_mb: u64,
    pub huge_pages: Option<bool>,
    pub tls: Option<bool>,
    pub keepalive: Option<bool>,
    pub donation_level: Option<u8>,
    pub restart_limit: Option<u8>,
    pub duration_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct OperatorNode {
    pub node_id: String,
    pub node_name: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub client_version: String,
    pub last_seen_ms: Option<u64>,
    pub online_until_ms: Option<u64>,
    pub health: Option<NodeHealth>,
    pub effective_policy: Option<NodePolicy>,
}

pub async fn publish_xmrig_runtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((version, platform, architecture)): Path<(String, String, String)>,
    bytes: Bytes,
) -> Result<Json<RuntimeManifest>, ApiResponseError> {
    authorize(&state, &headers)?;

    Version::parse(&version).map_err(|_| {
        ApiResponseError::bad_request(
            "invalid_runtime_version",
            "XMRig runtime version must be semantic versioning",
        )
    })?;
    let platform = parse_platform(&platform)?;
    let architecture = parse_architecture(&architecture)?;

    if matches!(platform, Platform::Unknown) || matches!(architecture, Architecture::Unknown) {
        return Err(ApiResponseError::bad_request(
            "invalid_runtime_target",
            "runtime platform and architecture must be explicit",
        ));
    }

    let (sha256, size_bytes, _) = content::store(&state.content_dir, &bytes)
        .await
        .map_err(ApiResponseError::internal)?;
    let now = unix_time_ms();
    let download_url = format!("{}/api/v1/content/{sha256}", state.public_url);

    let manifest = RuntimeManifest {
        schema_version: 1,
        runtime_id: "xmrig".to_string(),
        runtime_version: version.clone(),
        platform,
        architecture,
        sha256,
        size_bytes,
        download_url,
        issued_at_ms: now,
    };

    let manifest = {
        let mut registry = state.runtimes.write().await;
        runtimes::insert_immutable(&state.runtimes_path, &mut registry, manifest)
            .await
            .map_err(|error| ApiResponseError::conflict("runtime_publish_conflict", &error))?
    };

    ensure_xmrig_profile(&state, &version, now).await?;
    Ok(Json(manifest))
}

pub async fn queue_mining_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<QueueMiningJobRequest>,
) -> Result<Json<jobs::JobRecord>, ApiResponseError> {
    authorize(&state, &headers)?;

    Version::parse(&request.runtime_version).map_err(|_| {
        ApiResponseError::bad_request(
            "invalid_runtime_version",
            "XMRig runtime version must be semantic versioning",
        )
    })?;
    if request.cpu_percent == 0 || request.cpu_percent > 100 {
        return Err(ApiResponseError::bad_request(
            "invalid_cpu_limit",
            "CPU percentage must be between 1 and 100",
        ));
    }
    if request.memory_mb == 0 {
        return Err(ApiResponseError::bad_request(
            "invalid_memory_limit",
            "memory limit must be greater than zero",
        ));
    }
    if !(10..=604_800).contains(&request.duration_seconds) {
        return Err(ApiResponseError::bad_request(
            "invalid_duration",
            "mining job duration must be between 10 seconds and 7 days",
        ));
    }

    if let Some(node_id) = request.target_node_id.as_deref() {
        let registry = state.registry.read().await;
        if !registry.nodes.contains_key(node_id) {
            return Err(ApiResponseError::bad_request(
                "unknown_target_node",
                "target node is not enrolled",
            ));
        }
    }

    {
        let registry = state.runtimes.read().await;
        if !registry.runtimes.iter().any(|manifest| {
            manifest.runtime_id == "xmrig" && manifest.runtime_version == request.runtime_version
        }) {
            return Err(ApiResponseError::conflict(
                "unknown_runtime",
                "requested XMRig runtime version has not been published",
            ));
        }
    }
    {
        let registry = state.artifacts.read().await;
        if !registry.artifacts.iter().any(|manifest| {
            manifest.artifact_id == XMRIG_PROFILE_ID
                && manifest.artifact_version == request.runtime_version
                && manifest.runtime == "xmrig"
                && manifest.runtime_version == request.runtime_version
        }) {
            return Err(ApiResponseError::conflict(
                "unknown_mining_profile",
                "XMRig mining profile artifact is not published",
            ));
        }
    }

    let mut parameters = BTreeMap::new();
    parameters.insert("algorithm".to_string(), request.algorithm);
    parameters.insert("pool".to_string(), request.pool);
    parameters.insert("wallet".to_string(), request.wallet);
    parameters.insert("worker".to_string(), request.worker);
    parameters.insert(
        "password".to_string(),
        request.password.unwrap_or_else(|| "x".to_string()),
    );
    parameters.insert("threads".to_string(), request.threads.to_string());
    parameters.insert(
        "huge_pages".to_string(),
        request.huge_pages.unwrap_or(true).to_string(),
    );
    parameters.insert("tls".to_string(), request.tls.unwrap_or(false).to_string());
    parameters.insert(
        "keepalive".to_string(),
        request.keepalive.unwrap_or(true).to_string(),
    );
    parameters.insert(
        "donation_level".to_string(),
        request.donation_level.unwrap_or(1).to_string(),
    );
    parameters.insert(
        "restart_limit".to_string(),
        request.restart_limit.unwrap_or(3).to_string(),
    );

    let now = unix_time_ms();
    let offer = JobOffer {
        job_id: format!("job_{}", Uuid::new_v4().simple()),
        workload_kind: WorkloadKind::Mining,
        runtime: "xmrig".to_string(),
        runtime_version: request.runtime_version.clone(),
        artifact_id: XMRIG_PROFILE_ID.to_string(),
        artifact_version: request.runtime_version,
        limits: ResourceLimits {
            cpu_percent: request.cpu_percent,
            memory_mb: request.memory_mb,
            gpu_percent: None,
            gpu_memory_mb: None,
        },
        parameters,
        expires_at_ms: now.saturating_add(request.duration_seconds.saturating_mul(1000)),
    };

    mining_config_from_offer(&offer)
        .map_err(|error| ApiResponseError::bad_request("invalid_mining_config", &error))?;

    let record = {
        let mut queue = state.jobs.write().await;
        jobs::enqueue(
            &state.jobs_path,
            &mut queue,
            offer,
            request.target_node_id,
        )
        .await
        .map_err(ApiResponseError::internal)?
    };

    Ok(Json(record))
}

pub async fn list_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<jobs::JobRecord>>, ApiResponseError> {
    authorize(&state, &headers)?;
    Ok(Json(state.jobs.read().await.jobs.clone()))
}

pub async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorNode>>, ApiResponseError> {
    authorize(&state, &headers)?;
    let registry = state.registry.read().await;
    let nodes = registry
        .nodes
        .values()
        .map(|node| OperatorNode {
            node_id: node.node_id.clone(),
            node_name: node.node_name.clone(),
            platform: node.platform.clone(),
            architecture: node.architecture.clone(),
            client_version: node.client_version.clone(),
            last_seen_ms: node.last_seen_ms,
            online_until_ms: node.online_until_ms,
            health: node.health.clone(),
            effective_policy: node.effective_policy.clone(),
        })
        .collect();
    Ok(Json(nodes))
}

async fn ensure_xmrig_profile(
    state: &AppState,
    version: &str,
    issued_at_ms: u64,
) -> Result<(), ApiResponseError> {
    let profile = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "workload": "xmrig",
        "runtime_version": version
    }))
    .map_err(ApiResponseError::internal)?;
    let profile = Bytes::from(profile);
    let (sha256, size_bytes, _) = content::store(&state.content_dir, &profile)
        .await
        .map_err(ApiResponseError::internal)?;
    let manifest = ArtifactManifest {
        schema_version: 1,
        artifact_id: XMRIG_PROFILE_ID.to_string(),
        artifact_version: version.to_string(),
        runtime: "xmrig".to_string(),
        runtime_version: version.to_string(),
        sha256: sha256.clone(),
        size_bytes,
        download_url: format!("{}/api/v1/content/{sha256}", state.public_url),
        issued_at_ms,
    };

    let mut registry = state.artifacts.write().await;
    artifacts::insert_immutable(&state.artifacts_path, &mut registry, manifest)
        .await
        .map_err(|error| ApiResponseError::conflict("artifact_publish_conflict", &error))?;
    Ok(())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiResponseError> {
    let Some(expected) = state.operator_token.as_deref() else {
        return Err(ApiResponseError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "operator_api_disabled",
            "operator API requires LATTICE_OPERATOR_TOKEN",
        ));
    };
    let provided = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();

    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    if provided.len() != expected.len() || !bool::from(provided.ct_eq(expected)) {
        return Err(ApiResponseError::unauthorized(
            "invalid_operator_token",
            "operator token is invalid",
        ));
    }
    Ok(())
}

fn parse_platform(value: &str) -> Result<Platform, ApiResponseError> {
    match value {
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "macos" => Ok(Platform::Macos),
        _ => Err(ApiResponseError::bad_request(
            "invalid_platform",
            "platform must be windows, linux, or macos",
        )),
    }
}

fn parse_architecture(value: &str) -> Result<Architecture, ApiResponseError> {
    match value {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Aarch64),
        _ => Err(ApiResponseError::bad_request(
            "invalid_architecture",
            "architecture must be x86_64 or aarch64",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_accepts_supported_runtime_targets() {
        assert_eq!(parse_platform("windows").unwrap(), Platform::Windows);
        assert_eq!(parse_platform("linux").unwrap(), Platform::Linux);
        assert_eq!(
            parse_architecture("x86_64").unwrap(),
            Architecture::X86_64
        );
        assert!(parse_platform("unknown").is_err());
        assert!(parse_architecture("armv7").is_err());
    }
}
