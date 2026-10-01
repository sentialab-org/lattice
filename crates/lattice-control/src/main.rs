mod artifacts;
mod jobs;
mod releases;
mod runtimes;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use lattice_crypto::{
    decode_key, encode_key, fingerprint, generate_private_key, public_key, sign, verify,
};
use lattice_protocol::{
    ApiError, Architecture, EnrollmentReceipt, EnrollmentRequest, EnrollmentResponse,
    HeartbeatReceipt, HeartbeatRequest, HeartbeatResponse, NodeCapabilities, NodeHealth,
    NodePolicy, PROTOCOL_VERSION, Platform, PolicySnapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    control: Arc<ControlIdentity>,
    enrollment_token: Arc<String>,
    registry: Arc<RwLock<NodeRegistry>>,
    registry_path: Arc<PathBuf>,
    policy: Arc<PolicySnapshot>,
    jobs: Arc<RwLock<jobs::JobQueue>>,
    jobs_path: Arc<PathBuf>,
    artifacts: Arc<artifacts::ArtifactRegistry>,
    releases: Arc<releases::ReleaseRegistry>,
    runtimes: Arc<runtimes::RuntimeRegistry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControlIdentity {
    control_id: String,
    private_key: String,
    public_key: String,
    created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct NodeRegistry {
    nodes: BTreeMap<String, EnrolledNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrolledNode {
    node_id: String,
    node_name: String,
    public_key: String,
    platform: Platform,
    architecture: Architecture,
    client_version: String,
    enrolled_at_ms: u64,
    #[serde(default)]
    last_seen_ms: Option<u64>,
    #[serde(default)]
    online_until_ms: Option<u64>,
    #[serde(default)]
    last_sequence: u64,
    #[serde(default)]
    capabilities: Option<NodeCapabilities>,
    #[serde(default)]
    health: Option<NodeHealth>,
    #[serde(default)]
    effective_policy: Option<NodePolicy>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    control_id: String,
    fingerprint: String,
    protocol_version: u32,
    policy_revision: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_dir = std::env::var_os("LATTICE_CONTROL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./data"));
    let enrollment_token = std::env::var("LATTICE_ENROLLMENT_TOKEN")
        .map_err(|_| "LATTICE_ENROLLMENT_TOKEN is required")?;
    let bind =
        std::env::var("LATTICE_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:7443".to_string());

    let control = Arc::new(load_or_create_control_identity(&data_dir).await?);
    let policy = Arc::new(load_or_create_policy(&data_dir).await?);
    let registry_path = data_dir.join("nodes.json");
    let registry = Arc::new(RwLock::new(load_registry(&registry_path).await?));
    let (jobs_path, jobs) = jobs::load_or_create(&data_dir).await?;
    let (_, artifacts) = artifacts::load_or_create(&data_dir).await?;
    let (_, releases) = releases::load_or_create(&data_dir).await?;
    let (_, runtimes) = runtimes::load_or_create(&data_dir).await?;
    let state = AppState {
        control,
        enrollment_token: Arc::new(enrollment_token),
        registry,
        registry_path: Arc::new(registry_path),
        policy,
        jobs: Arc::new(RwLock::new(jobs)),
        jobs_path: Arc::new(jobs_path),
        artifacts: Arc::new(artifacts),
        releases: Arc::new(releases),
        runtimes: Arc::new(runtimes),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/enroll", post(enroll))
        .route("/api/v1/heartbeat", post(heartbeat))
        .route("/api/v1/releases/latest", get(releases::latest))
        .route("/api/v1/jobs/decision", post(jobs::decision))
        .route("/api/v1/jobs/status", post(jobs::status))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    println!("Lattice Control");
    println!("Listening on {bind}");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiResponseError> {
    let control_fingerprint =
        fingerprint(&state.control.public_key).map_err(ApiResponseError::internal)?;

    Ok(Json(HealthResponse {
        status: "ok",
        control_id: state.control.control_id.clone(),
        fingerprint: control_fingerprint,
        protocol_version: PROTOCOL_VERSION,
        policy_revision: state.policy.revision,
    }))
}

async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, ApiResponseError> {
    if !constant_time_token_match(&request.enrollment_token, &state.enrollment_token) {
        return Err(ApiResponseError::unauthorized(
            "invalid_enrollment_token",
            "enrollment token is invalid",
        ));
    }

    if request.claim.protocol_version != PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 300_000 {
        return Err(ApiResponseError::bad_request(
            "stale_enrollment_request",
            "enrollment request timestamp is outside the allowed window",
        ));
    }

    decode_key::<32>(&request.claim.public_key).map_err(|_| {
        ApiResponseError::bad_request("invalid_public_key", "node public key is invalid")
    })?;

    verify(
        &request.claim.public_key,
        &request.signature,
        &request.claim,
    )
    .map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "node enrollment signature is invalid",
        )
    })?;

    let previous = {
        let registry = state.registry.read().await;
        if let Some(existing) = registry.nodes.get(&request.claim.node_id)
            && existing.public_key != request.claim.public_key
        {
            return Err(ApiResponseError::conflict(
                "node_identity_conflict",
                "node ID is already registered with a different public key",
            ));
        }
        registry.nodes.get(&request.claim.node_id).cloned()
    };

    let receipt = EnrollmentReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.claim.request_id.clone(),
        node_id: request.claim.node_id.clone(),
        control_id: state.control.control_id.clone(),
        control_public_key: state.control.public_key.clone(),
        policy_revision: state.policy.revision,
        issued_at_ms: now,
    };
    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    {
        let mut registry = state.registry.write().await;
        registry.nodes.insert(
            request.claim.node_id.clone(),
            EnrolledNode {
                node_id: request.claim.node_id,
                node_name: request.claim.node_name,
                public_key: request.claim.public_key,
                platform: request.claim.platform,
                architecture: request.claim.architecture,
                client_version: request.claim.client_version,
                enrolled_at_ms: now,
                last_seen_ms: previous.as_ref().and_then(|node| node.last_seen_ms),
                online_until_ms: previous.as_ref().and_then(|node| node.online_until_ms),
                last_sequence: previous.as_ref().map_or(0, |node| node.last_sequence),
                capabilities: previous.as_ref().and_then(|node| node.capabilities.clone()),
                health: previous.as_ref().and_then(|node| node.health.clone()),
                effective_policy: previous
                    .as_ref()
                    .and_then(|node| node.effective_policy.clone()),
            },
        );
        save_registry(&state.registry_path, &registry)
            .await
            .map_err(ApiResponseError::internal)?;
    }

    Ok(Json(EnrollmentResponse { receipt, signature }))
}

async fn heartbeat(
    State(state): State<AppState>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiResponseError> {
    if request.claim.protocol_version != PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_heartbeat",
            "heartbeat timestamp is outside the allowed window",
        ));
    }

    let (public_key, last_sequence) = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        (node.public_key.clone(), node.last_sequence)
    };

    ensure_fresh_sequence(request.claim.sequence, last_sequence)?;

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized("invalid_node_signature", "heartbeat signature is invalid")
    })?;

    {
        let mut registry = state.registry.write().await;
        let node = registry
            .nodes
            .get_mut(&request.claim.node_id)
            .ok_or_else(|| {
                ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
            })?;

        ensure_fresh_sequence(request.claim.sequence, node.last_sequence)?;

        node.last_sequence = request.claim.sequence;
        node.last_seen_ms = Some(now);
        node.online_until_ms = Some(now.saturating_add(45_000));
        node.client_version = request.claim.client_version.clone();
        node.capabilities = Some(request.claim.capabilities.clone());
        node.health = Some(request.claim.health.clone());
        node.effective_policy = Some(request.claim.effective_policy.clone());

        save_registry(&state.registry_path, &registry)
            .await
            .map_err(ApiResponseError::internal)?;
    }

    let job_lease = jobs::offer_for_node(&state, &request.claim.node_id, now).await?;

    let receipt = HeartbeatReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.claim.request_id,
        node_id: request.claim.node_id,
        control_id: state.control.control_id.clone(),
        policy: (*state.policy).clone(),
        issued_at_ms: now,
    };
    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(HeartbeatResponse {
        receipt,
        signature,
        job_lease,
    }))
}

async fn load_or_create_control_identity(
    data_dir: &Path,
) -> Result<ControlIdentity, Box<dyn std::error::Error + Send + Sync>> {
    tokio::fs::create_dir_all(data_dir).await?;
    secure_directory(data_dir)?;
    let path = data_dir.join("control-identity.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let identity: ControlIdentity = serde_json::from_str(&content)?;
            let private_key = decode_key::<32>(&identity.private_key)?;
            let expected_public_key = encode_key(&public_key(&private_key));
            if expected_public_key != identity.public_key {
                return Err("control identity public key does not match private key".into());
            }
            Ok(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let private_key = generate_private_key();
            let identity = ControlIdentity {
                control_id: format!("control_{}", Uuid::new_v4().simple()),
                private_key: encode_key(&private_key),
                public_key: encode_key(&public_key(&private_key)),
                created_at_ms: unix_time_ms(),
            };
            let content = serde_json::to_vec_pretty(&identity)?;
            tokio::fs::write(&path, content).await?;
            secure_file(&path)?;
            Ok(identity)
        }
        Err(error) => Err(error.into()),
    }
}

async fn load_or_create_policy(
    data_dir: &Path,
) -> Result<PolicySnapshot, Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("policy.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let policy: PolicySnapshot = serde_json::from_str(&content)?;
            validate_policy(&policy)?;
            Ok(policy)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let policy = PolicySnapshot::default();
            let content = serde_json::to_vec_pretty(&policy)?;
            tokio::fs::write(&path, content).await?;
            secure_file(&path)?;
            Ok(policy)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_policy(policy: &PolicySnapshot) -> Result<(), String> {
    if policy.revision == 0 {
        return Err("policy revision must be greater than zero".to_string());
    }

    if policy.constraints.max_cpu_percent > 100 {
        return Err("policy CPU limit must be between 0 and 100".to_string());
    }

    if policy
        .constraints
        .max_gpu_percent
        .is_some_and(|value| value > 100)
    {
        return Err("policy GPU limit must be between 0 and 100".to_string());
    }

    if policy.constraints.max_memory_mb == Some(0) {
        return Err("policy memory limit must be greater than zero".to_string());
    }

    if policy.constraints.max_gpu_memory_mb == Some(0) {
        return Err("policy GPU memory limit must be greater than zero".to_string());
    }

    Ok(())
}

async fn load_registry(
    path: &Path,
) -> Result<NodeRegistry, Box<dyn std::error::Error + Send + Sync>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(serde_json::from_str(&content)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(NodeRegistry::default()),
        Err(error) => Err(error.into()),
    }
}

async fn save_registry(path: &Path, registry: &NodeRegistry) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(registry).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
}

fn ensure_fresh_sequence(sequence: u64, last_sequence: u64) -> Result<(), ApiResponseError> {
    if sequence <= last_sequence {
        return Err(ApiResponseError::conflict(
            "replayed_heartbeat",
            "heartbeat sequence was already observed",
        ));
    }

    Ok(())
}

fn constant_time_token_match(provided: &str, expected: &str) -> bool {
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    provided.len() == expected.len() && provided.ct_eq(expected).into()
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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

struct ApiResponseError {
    status: StatusCode,
    body: ApiError,
}

impl ApiResponseError {
    fn bad_request(code: &str, message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unauthorized(code: &str, message: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    fn conflict(code: &str, message: &str) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    fn internal(error: impl ToString) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        )
    }

    fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            body: ApiError {
                code: code.to_string(),
                message: message.to_string(),
            },
        }
    }
}

impl axum::response::IntoResponse for ApiResponseError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_token_comparison_rejects_mismatch() {
        assert!(constant_time_token_match("same-token", "same-token"));
        assert!(!constant_time_token_match("same-token", "other-token"));
        assert!(!constant_time_token_match("short", "longer-token"));
    }

    #[test]
    fn heartbeat_sequence_rejects_replay() {
        assert!(ensure_fresh_sequence(11, 10).is_ok());
        assert!(ensure_fresh_sequence(10, 10).is_err());
        assert!(ensure_fresh_sequence(9, 10).is_err());
    }
}
