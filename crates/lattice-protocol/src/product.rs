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
