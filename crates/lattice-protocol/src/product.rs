use serde::{Deserialize, Serialize};
pub const PRODUCT_SCHEMA_VERSION: u32 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSession {
    pub username: String,
    pub csrf_token: String,
    pub idle_expires_at_ms: u64,
    pub absolute_expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasterGrant {
    pub schema_version: u32,
    pub network_id: String,
    pub node_id: String,
    pub node_public_key: String,
    pub control_id: String,
    pub control_public_key: String,
    pub overlay_ipv4: String,
    pub revision: u64,
    pub issued_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedMasterGrant {
    pub grant: MasterGrant,
    pub signature: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct CreatedMasterToken {
    pub token_id: String,
    pub label: String,
    pub activation_token: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}
impl std::fmt::Debug for CreatedMasterToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedMasterToken")
            .field("token_id", &self.token_id)
            .field("activation_token", &"[REDACTED]")
            .finish()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterTokenSummary {
    pub token_id: String,
    pub label: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
    pub activated_node_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJoinClaim {
    pub schema_version: u32,
    pub enrollment: crate::EnrollmentClaim,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJoinRequest {
    pub claim: PublicJoinClaim,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub schema_version: u32,
    pub network_id: String,
    pub node_id: String,
    pub node_public_key: String,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedMembership {
    pub membership: Membership,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicJoinResponse {
    pub receipt: crate::EnrollmentReceipt,
    pub signature: String,
    pub membership: SignedMembership,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterActivationClaim {
    pub schema_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub control_id: String,
    pub control_public_key: String,
    pub issued_at_ms: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterActivationRequest {
    pub claim: MasterActivationClaim,
    pub node_signature: String,
    pub control_signature: String,
    pub activation_token: String,
}
impl std::fmt::Debug for MasterActivationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterActivationRequest")
            .field("claim", &self.claim)
            .field("activation_token", &"[REDACTED]")
            .finish()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterDirectory {
    pub schema_version: u32,
    pub network_id: String,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub active_master_id: Option<String>,
    pub masters: Vec<SignedMasterGrant>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMasterDirectory {
    pub directory: MasterDirectory,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryClaim {
    pub schema_version: u32,
    pub request_id: String,
    pub node_id: String,
    pub issued_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub claim: DiscoveryClaim,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResponse {
    pub membership: SignedMembership,
    pub directory: SignedMasterDirectory,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterAuthority {
    pub bootstrap_url: String,
    pub coordinator_key: String,
    pub network_id: String,
    pub grant: SignedMasterGrant,
    pub directory: SignedMasterDirectory,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadJoinClaim {
    pub schema_version: u32,
    pub enrollment: crate::EnrollmentClaim,
    pub membership: SignedMembership,
    pub master_control_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadJoinRequest {
    pub claim: WorkloadJoinClaim,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadOperation {
    ListJobs,
    ListRuntimes,
    ListArtifacts,
    PublishRuntime {
        version: String,
        platform: crate::Platform,
        architecture: crate::Architecture,
    },
    QueueMining,
    ControlJob,
    CancelJob,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorDelegation {
    pub schema_version: u32,
    pub request_id: String,
    pub network_id: String,
    pub master_control_id: String,
    pub operation: WorkloadOperation,
    pub request_sha256: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperatorDelegation {
    pub delegation: OperatorDelegation,
    pub signature: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Node,
    Master,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupOptions {
    pub role: NodeRole,
    pub bootstrap_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_token: Option<String>,
}
impl std::fmt::Debug for SetupOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupOptions")
            .field("role", &self.role)
            .field("bootstrap_url", &self.bootstrap_url)
            .field(
                "master_token",
                &self.master_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupStage {
    Preflight,
    Joining,
    Allocating,
    ApplyingNetwork,
    VerifyingNetwork,
    ActivatingMaster,
    AttachingWorkload,
    Ready,
    WaitingForMaster,
    Degraded,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupReport {
    pub stage: SetupStage,
    pub node_id: String,
    pub virtual_ipv4: Option<String>,
    pub role: NodeRole,
    pub network_ready: bool,
    pub workload_ready: bool,
    pub error_code: Option<String>,
}
impl SetupReport {
    pub fn initial(role: NodeRole) -> Self {
        Self {
            stage: SetupStage::Preflight,
            node_id: String::new(),
            virtual_ipv4: None,
            role,
            network_ready: false,
            workload_ready: false,
            error_code: None,
        }
    }
}
