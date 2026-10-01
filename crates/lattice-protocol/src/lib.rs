use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    Ping,
    GetStatus,
    GetConfig,
    SetConfig { config: NodeConfig },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Pong,
    Status(NodeStatus),
    Config(NodeConfig),
    ConfigUpdated(NodeConfig),
    Error { message: String },
}
