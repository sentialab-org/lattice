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
