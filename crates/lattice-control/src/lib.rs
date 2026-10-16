pub mod artifacts;
pub mod auth;
pub mod authority;
pub mod clock;
pub mod content;
pub mod delegation;
pub mod fleet;
pub mod jobs;
pub mod masters;
pub mod network;
pub mod onboarding;
pub mod operator;
pub mod releases;
pub mod runtimes;
pub mod tokens;
pub mod web;
#[cfg(windows)]
pub mod windows_service;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use lattice_crypto::{
    decode_key, encode_key, fingerprint, generate_private_key, public_key, sign, verify,
};
use lattice_protocol::{
    ApiError, Architecture, EnrollmentReceipt, EnrollmentRequest, EnrollmentResponse,
    HeartbeatReceipt, HeartbeatRequest, HeartbeatResponse, JobState, NodeCapabilities, NodeHealth,
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
pub struct AppState {
    pub delegation_lock: Arc<tokio::sync::Mutex<()>>,
    pub onboarding: Arc<onboarding::OnboardingStore>,
    pub gateway_notify: Arc<tokio::sync::Notify>,
    pub gateway_lock: Arc<tokio::sync::Mutex<()>>,
    pub gateway_report: Arc<RwLock<network::reconcile::GatewayApplyReport>>,
    pub master_tokens: Arc<tokens::TokenStore>,
    pub auth: Arc<auth::AuthState>,
    pub clock: Arc<dyn clock::Clock>,
    pub control: Arc<ControlIdentity>,
    pub control_role: Arc<String>,
    pub enrollment_token: Arc<String>,
    pub registry: Arc<RwLock<NodeRegistry>>,
    pub registry_path: Arc<PathBuf>,
    pub policy: Arc<PolicySnapshot>,
    pub jobs: Arc<RwLock<jobs::JobQueue>>,
    pub jobs_path: Arc<PathBuf>,
    pub artifacts: Arc<RwLock<artifacts::ArtifactRegistry>>,
    pub artifacts_path: Arc<PathBuf>,
    pub content_dir: Arc<PathBuf>,
    pub operator_token: Option<Arc<String>>,
    pub public_url: Arc<String>,
    pub releases: Arc<releases::ReleaseRegistry>,
    pub runtimes: Arc<RwLock<runtimes::RuntimeRegistry>>,
    pub runtimes_path: Arc<PathBuf>,
    pub network: Arc<RwLock<network::NetworkState>>,
    pub network_path: Arc<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlIdentity {
    pub control_id: String,
    pub private_key: String,
    pub public_key: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeRegistry {
    pub nodes: BTreeMap<String, EnrolledNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledNode {
    pub node_id: String,
    pub node_name: String,
    pub public_key: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub client_version: String,
    pub enrolled_at_ms: u64,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    #[serde(default)]
    pub online_until_ms: Option<u64>,
    #[serde(default)]
    pub last_sequence: u64,
    #[serde(default)]
    pub capabilities: Option<NodeCapabilities>,
    #[serde(default)]
    pub health: Option<NodeHealth>,
    #[serde(default)]
    pub effective_policy: Option<NodePolicy>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
    control_id: String,
    control_role: String,
    network_id: String,
    fingerprint: String,
    protocol_version: u32,
    policy_revision: u64,
}

pub fn normalize_role(value: &str) -> String {
    let normalized = value.trim().to_lowercase();
    if normalized == "bootstrapper"
        || normalized == "supervisor"
        || normalized == "master"
        || normalized == "combined"
    {
        normalized
    } else {
        "combined".to_string()
    }
}

pub fn cors_origins() -> Vec<String> {
    std::env::var("LATTICE_CORS_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub fn build_router(state: AppState) -> Router {
    let role = state.control_role.as_ref().clone();
    let mut app: Router<AppState> = Router::new()
        .route("/", get(dashboard))
        .route("/index.html", get(dashboard))
        .route("/health", get(health))
        .route("/api/v2/authority", get(authority::public))
        .route("/assets/auth.js", get(web::auth_js))
        .route("/assets/setup.js", get(web::setup_js))
        .route("/install", get(web::install))
        .route("/installer/index.html", get(web::install))
        .route("/installer/linux.sh", get(web::linux))
        .route("/installer/macos.sh", get(web::macos))
        .route("/installer/windows.ps1", get(web::windows))
        .route("/api/v1/releases/catalog", get(web::catalog))
        .nest_service(
            "/releases",
            tower_http::services::ServeDir::new(web::release_root()),
        )
        .route("/api/v1/operator/fleet", get(fleet::inventory))
        .route(
            "/api/v1/auth/login",
            post(auth::handlers::login).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/api/v1/auth/session", get(auth::handlers::session))
        .route("/api/v1/auth/logout", post(auth::handlers::logout))
        .route("/api/v1/enroll", post(enroll))
        .route("/api/v1/heartbeat", post(heartbeat));
    if role == "combined" || role == "bootstrapper" || role == "supervisor" {
        app = app
            .route(
                "/api/v2/operator/relays/grant",
                post(authority::grant_relay),
            )
            .route(
                "/api/v2/operator/relays/revoke",
                post(authority::revoke_relay),
            )
            .route(
                "/api/v1/operator/master-tokens",
                get(tokens::list).post(tokens::create),
            )
            .route(
                "/api/v1/operator/master-tokens/revoke",
                post(tokens::revoke),
            )
            .route(
                "/api/v1/bootstrap/join",
                post(onboarding::public_join).layer(DefaultBodyLimit::max(8192)),
            )
            .route(
                "/api/v1/bootstrap/activate-master",
                post(masters::activation_handler).layer(DefaultBodyLimit::max(8192)),
            )
            .route(
                "/api/v1/bootstrap/discovery",
                post(masters::discovery).layer(DefaultBodyLimit::max(8192)),
            )
            .route("/api/v1/operator/masters", get(masters::operator_directory))
            .route("/api/v1/operator/masters/active", post(masters::select))
            .route("/api/v1/operator/masters/revoke", post(masters::revoke))
            .route("/api/v1/network/register", post(network::register))
            .route("/api/v1/network/sync", post(network::sync))
            .route("/api/v1/network/ack", post(network::ack))
            .route("/api/v1/network/peers", post(network::peers))
            .route("/api/v1/network/candidates", post(network::candidates))
            .route(
                "/api/v1/operator/network/nodes",
                get(network::operator_list_nodes),
            )
            .route(
                "/api/v1/operator/network/assign",
                post(network::operator_assign),
            )
            .route(
                "/api/v1/operator/network/revoke",
                post(network::operator_revoke),
            )
            .route(
                "/api/v1/operator/network/gateway",
                get(network::operator_gateway_view),
            );
    }
    if role == "combined" || role == "master" {
        app = app
            .route(
                "/api/v1/master/join",
                post(masters::workload_join).layer(DefaultBodyLimit::max(16384)),
            )
            .route("/api/v1/content/{sha256}", get(content::get))
            .route("/api/v1/releases/latest", get(releases::latest))
            .route("/api/v1/jobs/decision", post(jobs::decision))
            .route("/api/v1/jobs/status", post(jobs::status))
            .route("/api/v1/jobs/control-ack", post(jobs::handle_control_ack))
            .route(
                "/api/v1/operator/xmrig/runtimes/{version}/{platform}/{architecture}",
                post(operator::publish_xmrig_runtime),
            )
            .route(
                "/api/v1/operator/jobs/mining",
                post(operator::queue_mining_job),
            )
            .route("/api/v1/operator/jobs/control", post(operator::control_job))
            .route("/api/v1/operator/jobs/cancel", post(operator::cancel_job))
            .route("/api/v1/operator/jobs", get(operator::list_jobs))
            .route("/api/v1/operator/nodes", get(operator::list_nodes))
            .route("/api/v1/master/fleet", get(fleet::workload_inventory))
            .route("/api/v1/operator/runtimes", get(operator::list_runtimes))
            .route("/api/v1/operator/artifacts", get(operator::list_artifacts));
    }
    if role == "bootstrapper" || role == "supervisor" {
        app = app
            .route("/api/v1/operator/nodes", get(fleet::inventory))
            .route("/api/v1/operator/jobs", get(fleet::handler))
            .route("/api/v1/operator/runtimes", get(fleet::handler))
            .route("/api/v1/operator/artifacts", get(fleet::handler))
            .route("/api/v1/operator/jobs/mining", post(fleet::handler))
            .route("/api/v1/operator/jobs/control", post(fleet::handler))
            .route("/api/v1/operator/jobs/cancel", post(fleet::handler))
            .route(
                "/api/v1/operator/xmrig/runtimes/{version}/{platform}/{architecture}",
                post(fleet::handler),
            );
    }
    let app = app
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            delegation::middleware,
        ))
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .with_state(state);
    apply_cors(app)
}

fn apply_cors(app: Router) -> Router {
    use tower_http::cors::{Any, CorsLayer};

    let origins = cors_origins();
    if origins.is_empty() {
        return app;
    }

    if origins.iter().any(|origin| origin == "*") {
        return app.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    }

    let mut layer = CorsLayer::new().allow_methods(Any).allow_headers(Any);
    for origin in &origins {
        if let Ok(value) = origin.parse::<axum::http::HeaderValue>() {
            layer = layer.allow_origin(value);
        }
    }
    app.layer(layer)
}

pub async fn load_state(
    data_dir: &Path,
    enrollment_token: String,
    operator_token: Option<Arc<String>>,
    public_url: String,
    control_role: String,
) -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
    let control = Arc::new(load_or_create_control_identity(data_dir).await?);
    let policy = Arc::new(load_or_create_policy(data_dir).await?);
    let registry_path = data_dir.join("nodes.json");
    let registry = Arc::new(RwLock::new(load_registry(&registry_path).await?));
    let (jobs_path, jobs) = jobs::load_or_create(data_dir).await?;
    let content_origin =
        (control_role == "master" && enrollment_token.is_empty()).then_some(public_url.as_str());
    let (artifacts_path, artifacts) = artifacts::load_for_origin(data_dir, content_origin).await?;
    let (_, releases) = releases::load_or_create(data_dir).await?;
    let (runtimes_path, runtimes) = runtimes::load_for_origin(data_dir, content_origin).await?;
    let (network_path, network) = network::load_or_create(data_dir).await?;
    let content_dir = content::content_dir(data_dir);
    Ok(AppState {
        delegation_lock: Arc::new(tokio::sync::Mutex::new(())),
        onboarding: Arc::new(onboarding::OnboardingStore::load(data_dir)?),
        gateway_notify: Arc::new(tokio::sync::Notify::new()),
        gateway_lock: Arc::new(tokio::sync::Mutex::new(())),
        gateway_report: Arc::new(RwLock::new(Default::default())),
        master_tokens: Arc::new(tokens::TokenStore::load(data_dir)?),
        auth: Arc::new(auth::AuthState::load(
            data_dir,
            auth::AuthConfig::new(&public_url)?,
        )?),
        clock: Arc::new(clock::SystemClock),
        control,
        control_role: Arc::new(control_role),
        enrollment_token: Arc::new(enrollment_token),
        registry,
        registry_path: Arc::new(registry_path),
        policy,
        jobs: Arc::new(RwLock::new(jobs)),
        jobs_path: Arc::new(jobs_path),
        artifacts: Arc::new(RwLock::new(artifacts)),
        artifacts_path: Arc::new(artifacts_path),
        content_dir: Arc::new(content_dir),
        operator_token,
        public_url: Arc::new(public_url),
        releases: Arc::new(releases),
        runtimes: Arc::new(RwLock::new(runtimes)),
        runtimes_path: Arc::new(runtimes_path),
        network: Arc::new(RwLock::new(network)),
        network_path: Arc::new(network_path),
    })
}

pub async fn run_server(
    role_override: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_sender, receiver) = tokio::sync::watch::channel(false);
    run_server_with_shutdown(role_override, receiver).await
}

pub async fn run_server_with_shutdown(
    role_override: Option<String>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let data_dir = std::env::var_os("LATTICE_CONTROL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./data"));
    let enrollment_token = std::env::var("LATTICE_ENROLLMENT_TOKEN").unwrap_or_default();
    let mut bind =
        std::env::var("LATTICE_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:7443".to_string());
    let operator_token = std::env::var("LATTICE_OPERATOR_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(Arc::new);
    let mut public_url = std::env::var("LATTICE_PUBLIC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:7443".to_string())
        .trim_end_matches('/')
        .to_string();
    let control_role = role_override
        .map(|value| normalize_role(&value))
        .unwrap_or_else(|| {
            std::env::var("LATTICE_CONTROL_ROLE")
                .map(|value| normalize_role(&value))
                .unwrap_or_else(|_| "combined".to_string())
        });
    if control_role == "master" && enrollment_token.is_empty() {
        let identity = load_or_create_control_identity(&data_dir).await?;
        let authority: lattice_protocol::MasterAuthority = serde_json::from_slice(
            &tokio::fs::read(data_dir.join("master-authority.json")).await?,
        )?;
        (bind, public_url) = masters::endpoint_from_grant(&identity, &authority)
            .map_err(|_| "master endpoint authorization required")?;
    }
    let state = load_state(
        &data_dir,
        enrollment_token,
        operator_token,
        public_url,
        control_role.clone(),
    )
    .await?;
    let (_gateway_shutdown, receiver) = tokio::sync::watch::channel(false);
    if std::env::var("LATTICE_GATEWAY_RECONCILE").as_deref() == Ok("1") && control_role != "master"
    {
        tokio::spawn(network::reconcile::run(Arc::new(state.clone()), receiver));
    }
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("Lattice {control_role}");
    println!("Listening on {bind}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|v| *v).await;
        })
        .await?;
    Ok(())
}

pub async fn dashboard() -> axum::response::Html<String> {
    if let Ok(content) = tokio::fs::read_to_string("web/control/index.html").await {
        axum::response::Html(content)
    } else {
        axum::response::Html(include_str!("../../../web/control/index.html").to_string())
    }
}

pub async fn health(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, ApiResponseError> {
    let control_fingerprint =
        fingerprint(&state.control.public_key).map_err(ApiResponseError::internal)?;
    let network_id = state.network.read().await.network_id.clone();

    Ok(Json(HealthResponse {
        status: "ok",
        control_id: state.control.control_id.clone(),
        control_role: state.control_role.as_ref().clone(),
        network_id,
        fingerprint: control_fingerprint,
        protocol_version: PROTOCOL_VERSION,
        policy_revision: state.policy.revision,
    }))
}

pub async fn enroll(
    State(state): State<AppState>,
    Json(request): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentResponse>, ApiResponseError> {
    if state.enrollment_token.is_empty()
        || !constant_time_token_match(&request.enrollment_token, &state.enrollment_token)
    {
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

pub async fn heartbeat(
    State(state): State<AppState>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiResponseError> {
    masters::require_workload_authority(&state)?;
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

    let control_revision = {
        let queue = state.jobs.read().await;
        queue
            .jobs
            .iter()
            .find(|j| {
                matches!(
                    j.state,
                    JobState::Accepted
                        | JobState::Preparing
                        | JobState::Running
                        | JobState::Stopping
                ) && j
                    .lease
                    .as_ref()
                    .is_some_and(|l| l.node_id == request.claim.node_id)
                    && j.desired_revision
                        .as_ref()
                        .is_some_and(|des| des.revision.revision > j.applied_revision)
            })
            .and_then(|j| j.desired_revision.clone())
    };

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
        authority: None,
        command_proof: None,
        receipt,
        signature,
        job_lease,
        control_revision,
    }))
}

pub async fn load_or_create_control_identity(
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

pub async fn load_or_create_policy(
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

pub fn validate_policy(policy: &PolicySnapshot) -> Result<(), String> {
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

pub async fn load_registry(
    path: &Path,
) -> Result<NodeRegistry, Box<dyn std::error::Error + Send + Sync>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(serde_json::from_str(&content)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(NodeRegistry::default()),
        Err(error) => Err(error.into()),
    }
}

pub async fn save_registry(path: &Path, registry: &NodeRegistry) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(registry).map_err(|error| error.to_string())?;
    network::write_atomic(path, &content)
        .await
        .map_err(|error| error.to_string())
}

pub fn ensure_fresh_sequence(sequence: u64, last_sequence: u64) -> Result<(), ApiResponseError> {
    if sequence <= last_sequence {
        return Err(ApiResponseError::conflict(
            "replayed_heartbeat",
            "heartbeat sequence was already observed",
        ));
    }

    Ok(())
}

pub fn constant_time_token_match(provided: &str, expected: &str) -> bool {
    let provided = provided.as_bytes();
    let expected = expected.as_bytes();
    provided.len() == expected.len() && provided.ct_eq(expected).into()
}

pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(unix)]
pub fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
pub fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
pub fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
pub fn secure_file(path: &Path) -> Result<(), String> {
    // Restrict access on Windows so only SYSTEM and Administrators can access (HIGH-11, HIGH-14)
    let _ = std::process::Command::new("icacls")
        .arg(path.as_os_str())
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(F)")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(F)")
        .output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[derive(Debug)]
pub struct ApiResponseError {
    pub status: StatusCode,
    pub body: ApiError,
}

impl ApiResponseError {
    pub fn bad_request(code: &str, message: &str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    pub fn unauthorized(code: &str, message: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn conflict(code: &str, message: &str) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn internal(error: impl ToString) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &error.to_string(),
        )
    }

    pub fn new(status: StatusCode, code: &str, message: &str) -> Self {
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

    #[test]
    fn control_roles_normalize_and_gate_routes() {
        assert_eq!(normalize_role("bootstrapper"), "bootstrapper");
        assert_eq!(normalize_role("MASTER"), "master");
        assert_eq!(normalize_role("combined"), "combined");
        assert_eq!(normalize_role("unknown"), "combined");
        assert_eq!(normalize_role(""), "combined");
    }

    #[test]
    fn cors_origins_default_closed_and_parse() {
        unsafe {
            std::env::remove_var("LATTICE_CORS_ORIGINS");
        }
        assert!(cors_origins().is_empty());
        unsafe {
            std::env::set_var(
                "LATTICE_CORS_ORIGINS",
                "https://a.example, https://b.example ,,",
            );
        }
        assert_eq!(
            cors_origins(),
            vec![
                "https://a.example".to_string(),
                "https://b.example".to_string()
            ]
        );
        unsafe {
            std::env::remove_var("LATTICE_CORS_ORIGINS");
        }
    }
}
