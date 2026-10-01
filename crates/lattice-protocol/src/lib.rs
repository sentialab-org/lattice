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
pub struct SignedJobLease {
    pub lease: JobLease,
    pub signature: String,
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
pub enum IpcResponse {
    Pong,
    Status(NodeStatus),
    Config(NodeConfig),
    ConfigUpdated(NodeConfig),
    EnrollmentStatus(EnrollmentStatus),
    EnrollmentUpdated(EnrollmentStatus),
    Error { message: String },
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
        let mut policy = NodePolicy::default();
        policy.allow_research = false;
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
}
