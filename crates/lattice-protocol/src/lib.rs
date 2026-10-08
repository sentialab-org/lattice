use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    Macos,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Beta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseComponent {
    Node,
    Worker,
    Desktop,
    UpdateHelper,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Available,
    Downloading,
    Staged,
    Applying,
    Restarting,
    Verifying,
    RollingBack,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    Ai,
    Rendering,
    Media,
    Mining,
    Research,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MiningConfig {
    pub algorithm: String,
    pub pool: String,
    pub wallet: String,
    pub worker: String,
    pub password: String,
    pub threads: u16,
    pub huge_pages: bool,
    pub tls: bool,
    pub keepalive: bool,
    pub donation_level: u8,
    pub restart_limit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MiningTelemetry {
    pub job_id: String,
    pub algorithm: String,
    pub pool: String,
    pub worker: String,
    pub hashrate_hs: Option<f64>,
    pub average_hashrate_hs: Option<f64>,
    pub accepted_shares: u64,
    pub rejected_shares: u64,
    pub uptime_seconds: u64,
    pub cpu_threads: u16,
    pub restart_count: u8,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Offered,
    Accepted,
    Preparing,
    Running,
    Stopping,
    Completed,
    Failed,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRuntimeState {
    Idle,
    Running,
    Paused,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    Unenrolled,
    Enrolled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_percent: u8,
    pub memory_mb: u64,
    pub gpu_percent: Option<u8>,
    pub gpu_memory_mb: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_percent: 70,
            memory_mb: 8192,
            gpu_percent: Some(80),
            gpu_memory_mb: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodePolicy {
    pub enabled: bool,
    pub allow_ai: bool,
    pub allow_rendering: bool,
    pub allow_media: bool,
    pub allow_mining: bool,
    pub allow_research: bool,
    pub allow_generic: bool,
    pub limits: ResourceLimits,
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_ai: true,
            allow_rendering: true,
            allow_media: true,
            allow_mining: false,
            allow_research: true,
            allow_generic: false,
            limits: ResourceLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConstraints {
    pub enabled: bool,
    pub allow_ai: bool,
    pub allow_rendering: bool,
    pub allow_media: bool,
    pub allow_mining: bool,
    pub allow_research: bool,
    pub allow_generic: bool,
    pub max_cpu_percent: u8,
    pub max_memory_mb: Option<u64>,
    pub max_gpu_percent: Option<u8>,
    pub max_gpu_memory_mb: Option<u64>,
}

impl Default for PolicyConstraints {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_ai: true,
            allow_rendering: true,
            allow_media: true,
            allow_mining: true,
            allow_research: true,
            allow_generic: true,
            max_cpu_percent: 100,
            max_memory_mb: None,
            max_gpu_percent: None,
            max_gpu_memory_mb: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub revision: u64,
    pub constraints: PolicyConstraints,
}

impl Default for PolicySnapshot {
    fn default() -> Self {
        Self {
            revision: 1,
            constraints: PolicyConstraints::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NodeConfig {
    pub control_url: Option<String>,
    #[serde(default)]
    pub release_channel: ReleaseChannel,
    pub policy: NodePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub node_name: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub public_key: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlTrust {
    pub control_url: String,
    pub control_id: String,
    pub control_public_key: String,
    pub control_fingerprint: String,
    pub policy_revision: u64,
    pub enrolled_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentStatus {
    pub state: EnrollmentState,
    pub identity: NodeIdentity,
    pub trust: Option<ControlTrust>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentClaim {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub node_name: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub public_key: String,
    pub client_version: String,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub claim: EnrollmentClaim,
    pub enrollment_token: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentReceipt {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub control_id: String,
    pub control_public_key: String,
    pub policy_revision: u64,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollmentResponse {
    pub receipt: EnrollmentReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuCapability {
    pub name: String,
    pub memory_total_mb: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCapabilities {
    pub os: String,
    pub kernel: String,
    pub architecture: String,
    pub cpu_model: String,
    pub logical_cores: usize,
    pub physical_cores: Option<usize>,
    pub memory_total_mb: u64,
    pub gpus: Vec<GpuCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeHealth {
    pub runtime_state: NodeRuntimeState,
    pub cpu_usage_percent: f32,
    pub memory_used_mb: u64,
    pub active_jobs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatClaim {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub client_version: String,
    pub capabilities: NodeCapabilities,
    pub effective_policy: NodePolicy,
    pub health: NodeHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeartbeatRequest {
    pub claim: HeartbeatClaim,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatReceipt {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub control_id: String,
    pub policy: PolicySnapshot,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatResponse {
    pub receipt: HeartbeatReceipt,
    pub signature: String,
    pub job_lease: Option<SignedJobLease>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_revision: Option<SignedJobControlRevision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobOffer {
    pub job_id: String,
    pub workload_kind: WorkloadKind,
    pub runtime: String,
    pub runtime_version: String,
    pub artifact_id: String,
    pub artifact_version: String,
    pub limits: ResourceLimits,
    pub parameters: BTreeMap<String, String>,
    pub expires_at_ms: u64,
}

pub fn mining_config_from_offer(offer: &JobOffer) -> Result<MiningConfig, String> {
    if offer.workload_kind != WorkloadKind::Mining {
        return Err("job is not a mining workload".to_string());
    }

    if offer.runtime != "xmrig" && offer.runtime != "lattice-miner" {
        return Err("mining workload runtime must be xmrig or lattice-miner".to_string());
    }

    const ALLOWED: [&str; 10] = [
        "algorithm",
        "pool",
        "wallet",
        "worker",
        "password",
        "threads",
        "huge_pages",
        "tls",
        "keepalive",
        "donation_level",
    ];

    for key in offer.parameters.keys() {
        if !ALLOWED.contains(&key.as_str()) && key != "restart_limit" {
            return Err(format!("unsupported mining parameter: {key}"));
        }
    }

    let required = |key: &str| {
        offer
            .parameters
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing mining parameter: {key}"))
    };
    let parse_bool = |key: &str, default: bool| -> Result<bool, String> {
        match offer.parameters.get(key).map(|value| value.trim()) {
            None => Ok(default),
            Some("true") | Some("1") => Ok(true),
            Some("false") | Some("0") => Ok(false),
            Some(_) => Err(format!("invalid boolean mining parameter: {key}")),
        }
    };

    let algorithm = required("algorithm")?.to_string();
    if algorithm.len() > 64
        || !algorithm
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-'))
    {
        return Err("invalid mining algorithm".to_string());
    }

    let pool = required("pool")?.to_string();
    if pool.len() > 512 || pool.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err("invalid mining pool".to_string());
    }

    let wallet = required("wallet")?.to_string();
    if wallet.len() > 512 || wallet.chars().any(char::is_control) {
        return Err("invalid mining wallet".to_string());
    }

    let worker = required("worker")?.to_string();
    if worker.len() > 128
        || !worker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("invalid mining worker".to_string());
    }

    let password = offer
        .parameters
        .get("password")
        .cloned()
        .unwrap_or_else(|| "x".to_string());
    if password.len() > 256 || password.chars().any(char::is_control) {
        return Err("invalid mining password".to_string());
    }

    let threads = required("threads")?
        .parse::<u16>()
        .map_err(|_| "invalid mining thread count".to_string())?;
    if threads == 0 || threads > 1024 {
        return Err("mining thread count must be between 1 and 1024".to_string());
    }

    let donation_level = offer
        .parameters
        .get("donation_level")
        .map(|value| value.trim().parse::<u8>())
        .transpose()
        .map_err(|_| "invalid mining donation level".to_string())?
        .unwrap_or(1);
    if donation_level > 100 {
        return Err("mining donation level must be between 0 and 100".to_string());
    }

    let restart_limit = offer
        .parameters
        .get("restart_limit")
        .map(|value| value.trim().parse::<u8>())
        .transpose()
        .map_err(|_| "invalid mining restart limit".to_string())?
        .unwrap_or(3);
    if restart_limit > 5 {
        return Err("mining restart limit must be between 0 and 5".to_string());
    }

    Ok(MiningConfig {
        algorithm,
        pool,
        wallet,
        worker,
        password,
        threads,
        huge_pages: parse_bool("huge_pages", true)?,
        tls: parse_bool("tls", false)?,
        keepalive: parse_bool("keepalive", true)?,
        donation_level,
        restart_limit,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobLease {
    pub lease_id: String,
    pub node_id: String,
    pub offer: JobOffer,
    pub issued_at_ms: u64,
    pub decision_deadline_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub schema_version: u32,
    pub artifact_id: String,
    pub artifact_version: String,
    pub runtime: String,
    pub runtime_version: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub download_url: String,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedArtifactManifest {
    pub manifest: ArtifactManifest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeManifest {
    pub schema_version: u32,
    pub runtime_id: String,
    pub runtime_version: String,
    pub platform: Platform,
    pub architecture: Architecture,
    pub sha256: String,
    pub size_bytes: u64,
    pub download_url: String,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRuntimeManifest {
    pub manifest: RuntimeManifest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub component: ReleaseComponent,
    pub version: String,
    pub channel: ReleaseChannel,
    pub platform: Platform,
    pub architecture: Architecture,
    pub sha256: String,
    pub size_bytes: u64,
    pub download_url: String,
    pub minimum_supported_version: Option<String>,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedReleaseManifest {
    pub manifest: ReleaseManifest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedJobLease {
    pub lease: JobLease,
    pub signature: String,
    pub artifact: SignedArtifactManifest,
    pub runtime: SignedRuntimeManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobLeaseStatus {
    pub lease: JobLease,
    pub state: JobState,
    pub reason: Option<String>,
    #[serde(default)]
    pub events: Vec<JobStatusEvent>,
    #[serde(default)]
    pub pending_event: Option<JobStatusEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusEvent {
    pub event_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub state: JobState,
    pub sequence: u64,
    pub detail: Option<String>,
    pub exit_code: Option<i32>,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusClaim {
    pub protocol_version: u32,
    pub node_id: String,
    pub event: JobStatusEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusRequest {
    pub claim: JobStatusClaim,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusReceipt {
    pub protocol_version: u32,
    pub event_id: String,
    pub node_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub state: JobState,
    pub control_id: String,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobStatusResponse {
    pub receipt: JobStatusReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobDecisionClaim {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobDecisionRequest {
    pub claim: JobDecisionClaim,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobDecisionReceipt {
    pub protocol_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub state: JobState,
    pub control_id: String,
    pub issued_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobDecisionResponse {
    pub receipt: JobDecisionReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CpuInfo {
    pub model: String,
    pub logical_cores: usize,
    pub physical_cores: Option<usize>,
    pub usage_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuInfo {
    pub name: String,
    pub memory_total_mb: Option<u64>,
    pub utilization_percent: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HardwareSnapshot {
    pub os: String,
    pub kernel: String,
    pub architecture: String,
    pub uptime_seconds: u64,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub gpus: Vec<GpuInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeCacheSummary {
    pub manifests: u32,
    pub content_verified: u32,
    pub pending: u32,
    pub verified_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ArtifactCacheSummary {
    pub manifests: u32,
    pub content_verified: u32,
    pub pending: u32,
    pub verified_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateApplyPlan {
    pub staged_path: String,
    pub target_path: String,
    pub backup_path: String,
    pub state_path: String,
    pub expected_version: String,
    pub previous_version: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateStatus {
    pub installed_version: String,
    pub release_channel: ReleaseChannel,
    pub available_version: Option<String>,
    pub minimum_supported_version: Option<String>,
    pub state: UpdateState,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub staged_version: Option<String>,
    pub staged_path: Option<String>,
    pub previous_version: Option<String>,
    pub backup_path: Option<String>,
    pub last_error: Option<String>,
    pub retry_count: u32,
    pub checked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeStatus {
    pub node_id: String,
    pub node_name: String,
    pub runtime_state: NodeRuntimeState,
    pub control_url: Option<String>,
    pub control_connected: bool,
    pub hardware: HardwareSnapshot,
    pub policy: NodePolicy,
    pub remote_policy: Option<PolicySnapshot>,
    pub effective_policy: NodePolicy,
    pub active_lease: Option<JobLeaseStatus>,
    #[serde(default)]
    pub mining: Option<MiningTelemetry>,
    pub artifact_cache: ArtifactCacheSummary,
    pub runtime_cache: RuntimeCacheSummary,
    pub update: UpdateStatus,
    pub enrollment: EnrollmentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    GetStatus,
    GetConfig,
    SetConfig {
        config: NodeConfig,
    },
    GetEnrollmentStatus,
    Enroll {
        control_url: String,
        enrollment_token: String,
    },
    ResetEnrollment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum IpcResponse {
    Pong,
    Status(NodeStatus),
    Config(NodeConfig),
    ConfigUpdated(NodeConfig),
    EnrollmentStatus(EnrollmentStatus),
    EnrollmentUpdated(EnrollmentStatus),
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ResourceLimitPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_percent: Option<Option<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_memory_mb: Option<Option<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MiningControlPatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum JobControlPatch {
    Mining(MiningControlPatch),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobControlAction {
    UpdateLimits,
    Pause,
    Resume,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobControlRevision {
    pub protocol_version: u32,
    pub node_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub action: JobControlAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_patch: Option<ResourceLimitPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_patch: Option<JobControlPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedJobControlRevision {
    pub revision: JobControlRevision,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobControlAck {
    pub protocol_version: u32,
    pub node_id: String,
    pub lease_id: String,
    pub job_id: String,
    pub revision: u64,
    pub applied: bool,
    pub effective_limits: ResourceLimits,
    pub runtime_state: JobState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub acknowledged_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedJobControlAck {
    pub ack: JobControlAck,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WorkerJobDescriptor {
    pub protocol_version: u32,
    pub job_id: String,
    pub lease_id: String,
    pub workload_kind: WorkloadKind,
    pub runtime_id: String,
    pub runtime_version: String,
    pub runtime_path: String,
    pub runtime_sha256: String,
    pub runtime_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_size: Option<u64>,
    pub effective_limits: ResourceLimits,
    pub original_lease_limits: ResourceLimits,
    pub parameters: BTreeMap<String, String>,
    pub work_dir: String,
    pub log_dir: String,
    pub ipc_socket_path: String,
    pub ipc_auth_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "msg_type", content = "payload", rename_all = "snake_case")]
pub enum WorkerIpcMessage {
    Auth {
        token: String,
        job_id: String,
    },
    AuthResult {
        success: bool,
        error: Option<String>,
    },
    Start,
    ApplyControl {
        revision_seq: u64,
        action: JobControlAction,
        limits: ResourceLimits,
        runtime_patch: Option<JobControlPatch>,
    },
    Stop {
        grace_ms: u64,
    },
    ControlAck {
        revision_seq: u64,
        applied: bool,
        detail: Option<String>,
        effective_limits: ResourceLimits,
    },
    StateChange {
        state: JobState,
        detail: Option<String>,
        exit_code: Option<i32>,
    },
    Telemetry(MiningTelemetry),
    Error {
        message: String,
    },
    Ping,
    Pong,
}

pub fn compute_effective_limits(
    current: &ResourceLimits,
    patch: &Option<ResourceLimitPatch>,
    lease_limits: &ResourceLimits,
    policy: &NodePolicy,
) -> Result<ResourceLimits, String> {
    let mut effective = current.clone();

    if let Some(patch) = patch {
        if let Some(cpu) = patch.cpu_percent {
            let cpu_ceiling = lease_limits.cpu_percent.min(policy.limits.cpu_percent);
            effective.cpu_percent = cpu.min(cpu_ceiling);
        }
        if let Some(mem) = patch.memory_mb {
            let mem_ceiling = lease_limits.memory_mb.min(policy.limits.memory_mb);
            effective.memory_mb = mem.min(mem_ceiling);
        }
        if let Some(gpu_opt) = patch.gpu_percent {
            match (gpu_opt, lease_limits.gpu_percent, policy.limits.gpu_percent) {
                (Some(req_gpu), Some(lease_gpu), Some(policy_gpu)) => {
                    effective.gpu_percent = Some(req_gpu.min(lease_gpu).min(policy_gpu));
                }
                _ => {
                    effective.gpu_percent = None;
                }
            }
        }
        if let Some(vram_opt) = patch.gpu_memory_mb {
            match (
                vram_opt,
                lease_limits.gpu_memory_mb,
                policy.limits.gpu_memory_mb,
            ) {
                (Some(req_vram), Some(lease_vram), Some(policy_vram)) => {
                    effective.gpu_memory_mb = Some(req_vram.min(lease_vram).min(policy_vram));
                }
                _ => {
                    effective.gpu_memory_mb = None;
                }
            }
        }
    }

    effective.cpu_percent = effective
        .cpu_percent
        .min(lease_limits.cpu_percent)
        .min(policy.limits.cpu_percent);
    effective.memory_mb = effective
        .memory_mb
        .min(lease_limits.memory_mb)
        .min(policy.limits.memory_mb);

    Ok(effective)
}

pub fn validate_control_revision_monotonicity(
    current_applied: u64,
    incoming_revision: u64,
) -> Result<(), String> {
    if incoming_revision <= current_applied {
        return Err(format!(
            "stale_revision: incoming revision {incoming_revision} is less than or equal to current applied revision {current_applied}"
        ));
    }
    Ok(())
}

pub fn workload_allowed(policy: &NodePolicy, workload: &WorkloadKind) -> bool {
    if !policy.enabled {
        return false;
    }

    match workload {
        WorkloadKind::Ai => policy.allow_ai,
        WorkloadKind::Rendering => policy.allow_rendering,
        WorkloadKind::Media => policy.allow_media,
        WorkloadKind::Mining => policy.allow_mining,
        WorkloadKind::Research => policy.allow_research,
        WorkloadKind::Generic => policy.allow_generic,
    }
}

pub fn job_allowed_by_policy(policy: &NodePolicy, offer: &JobOffer) -> bool {
    if !workload_allowed(policy, &offer.workload_kind) {
        return false;
    }

    if offer.limits.cpu_percent > policy.limits.cpu_percent {
        return false;
    }

    if offer.limits.memory_mb > policy.limits.memory_mb {
        return false;
    }

    if let Some(required_gpu) = offer.limits.gpu_percent {
        let Some(allowed_gpu) = policy.limits.gpu_percent else {
            return false;
        };
        if required_gpu > allowed_gpu {
            return false;
        }
    }

    if let (Some(required_vram), Some(allowed_vram)) =
        (offer.limits.gpu_memory_mb, policy.limits.gpu_memory_mb)
        && required_vram > allowed_vram
    {
        return false;
    }

    true
}

pub fn job_status_transition_allowed(current: &JobState, next: &JobState) -> bool {
    matches!(
        (current, next),
        (JobState::Accepted, JobState::Preparing)
            | (JobState::Accepted, JobState::Failed)
            | (JobState::Preparing, JobState::Running)
            | (JobState::Preparing, JobState::Stopping)
            | (JobState::Preparing, JobState::Failed)
            | (JobState::Running, JobState::Stopping)
            | (JobState::Running, JobState::Completed)
            | (JobState::Running, JobState::Failed)
            | (JobState::Stopping, JobState::Completed)
            | (JobState::Stopping, JobState::Failed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: WorkloadKind, cpu: u8, memory: u64) -> JobOffer {
        JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: kind,
            runtime: "runtime".to_string(),
            runtime_version: "1".to_string(),
            artifact_id: "artifact".to_string(),
            artifact_version: "1".to_string(),
            limits: ResourceLimits {
                cpu_percent: cpu,
                memory_mb: memory,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            parameters: BTreeMap::new(),
            expires_at_ms: u64::MAX,
        }
    }

    #[test]
    fn job_policy_rejects_disabled_workload() {
        let policy = NodePolicy {
            allow_research: false,
            ..Default::default()
        };
        assert!(!job_allowed_by_policy(
            &policy,
            &job(WorkloadKind::Research, 10, 512)
        ));
    }

    #[test]
    fn job_policy_rejects_resource_overage() {
        let policy = NodePolicy::default();
        assert!(!job_allowed_by_policy(
            &policy,
            &job(WorkloadKind::Ai, 90, 512)
        ));
        assert!(!job_allowed_by_policy(
            &policy,
            &job(WorkloadKind::Ai, 10, 16384)
        ));
    }

    #[test]
    fn mining_config_rejects_raw_or_unknown_parameters() {
        let mut offer = job(WorkloadKind::Mining, 50, 1024);
        offer.runtime = "xmrig".to_string();
        offer
            .parameters
            .insert("algorithm".to_string(), "rx/0".to_string());
        offer
            .parameters
            .insert("pool".to_string(), "pool.example.test:443".to_string());
        offer
            .parameters
            .insert("wallet".to_string(), "wallet".to_string());
        offer
            .parameters
            .insert("worker".to_string(), "worker-1".to_string());
        offer
            .parameters
            .insert("threads".to_string(), "4".to_string());
        assert!(mining_config_from_offer(&offer).is_ok());

        offer
            .parameters
            .insert("args".to_string(), "--config evil.json".to_string());
        assert!(mining_config_from_offer(&offer).is_err());
    }

    #[test]
    fn job_status_transitions_are_strict() {
        assert!(job_status_transition_allowed(
            &JobState::Accepted,
            &JobState::Preparing
        ));
        assert!(job_status_transition_allowed(
            &JobState::Preparing,
            &JobState::Running
        ));
        assert!(job_status_transition_allowed(
            &JobState::Running,
            &JobState::Completed
        ));
        assert!(!job_status_transition_allowed(
            &JobState::Accepted,
            &JobState::Running
        ));
        assert!(!job_status_transition_allowed(
            &JobState::Completed,
            &JobState::Running
        ));
    }

    #[test]
    fn control_revision_monotonicity_is_enforced() {
        assert!(validate_control_revision_monotonicity(0, 1).is_ok());
        assert!(validate_control_revision_monotonicity(1, 2).is_ok());
        assert!(validate_control_revision_monotonicity(5, 10).is_ok());

        assert!(validate_control_revision_monotonicity(1, 1).is_err());
        assert!(validate_control_revision_monotonicity(2, 1).is_err());
        assert!(validate_control_revision_monotonicity(10, 5).is_err());
    }

    #[test]
    fn effective_limits_cannot_exceed_original_lease_or_policy() {
        let policy = NodePolicy {
            enabled: true,
            allow_mining: true,
            limits: ResourceLimits {
                cpu_percent: 80,
                memory_mb: 8192,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            ..Default::default()
        };

        let lease_limits = ResourceLimits {
            cpu_percent: 20,
            memory_mb: 2048,
            gpu_percent: None,
            gpu_memory_mb: None,
        };

        let current = lease_limits.clone();

        // Attempting to elevate CPU to 60% when lease is 20% must be clamped to 20% (CRIT-11)
        let patch = Some(ResourceLimitPatch {
            cpu_percent: Some(60),
            memory_mb: None,
            gpu_percent: None,
            gpu_memory_mb: None,
        });

        let effective = compute_effective_limits(&current, &patch, &lease_limits, &policy).unwrap();
        assert_eq!(effective.cpu_percent, 20);

        // Lowering CPU to 10% is within lease maximum and policy
        let lower_patch = Some(ResourceLimitPatch {
            cpu_percent: Some(10),
            memory_mb: None,
            gpu_percent: None,
            gpu_memory_mb: None,
        });
        let lower_effective =
            compute_effective_limits(&current, &lower_patch, &lease_limits, &policy).unwrap();
        assert_eq!(lower_effective.cpu_percent, 10);
        // Memory remains unchanged at 2048 (HIGH-10)
        assert_eq!(lower_effective.memory_mb, 2048);

        // GPU cannot be introduced when lease/policy disallows it (CRIT-12)
        let gpu_patch = Some(ResourceLimitPatch {
            cpu_percent: None,
            memory_mb: None,
            gpu_percent: Some(Some(50)),
            gpu_memory_mb: None,
        });
        let gpu_effective =
            compute_effective_limits(&current, &gpu_patch, &lease_limits, &policy).unwrap();
        assert_eq!(gpu_effective.gpu_percent, None);
    }
}
