//! Optional roles extend a persistent Base Node; no module owns another interface.
use serde::{Deserialize, Serialize};
pub const LOCAL_HOST_DOMAIN: &str = "lattice/local-supervisor-host/v2";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalHostProvisionClaim {
    pub schema_version: u32,
    pub join: crate::PublicJoinRequest,
    pub wireguard_public_key: String,
    pub interface_name: String,
    pub adopt_gateway: bool,
    pub forwarding_limit_bps: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalHostProvisionRequest {
    pub claim: LocalHostProvisionClaim,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalHostProvisionResponse {
    pub join: crate::PublicJoinResponse,
    pub gateway_intent: Option<SignedGatewayIntent>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Master,
    Relay,
    Supervisor,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Disabled,
    Verifying,
    Starting,
    Active,
    Suspended,
    Revoked,
    Failed,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleStatus {
    pub kind: ModuleKind,
    pub enabled: bool,
    pub state: ModuleState,
    pub process_id: Option<u32>,
    pub certificate_id: Option<String>,
    pub error_code: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleActivation {
    pub kind: ModuleKind,
    pub certificate: Option<crate::SignedCertificate>,
    pub authority_data_dir: Option<String>,
    #[serde(default)]
    pub adopt_gateway: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding_limit_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_token: Option<String>,
}
impl std::fmt::Debug for ModuleActivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleActivation")
            .field("kind", &self.kind)
            .field("certificate", &self.certificate)
            .field("authority_data_dir", &self.authority_data_dir)
            .field("adopt_gateway", &self.adopt_gateway)
            .field("forwarding_limit_bps", &self.forwarding_limit_bps)
            .field(
                "activation_token",
                &self.activation_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalMasterRequest {
    pub operation: crate::WorkloadOperation,
    #[serde(default)]
    pub body_base64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalMasterReply {
    pub status: u16,
    pub content_type: String,
    pub body_base64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPeerIntent {
    pub node_id: String,
    pub public_key: String,
    pub allowed_ipv4: String,
    pub endpoint: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayIntent {
    pub schema_version: u32,
    pub network_id: String,
    pub target_node_id: String,
    pub revision: u64,
    pub interface_name: String,
    pub address: String,
    pub overlay_cidr: String,
    pub listen_port: u16,
    pub transport_public_key: String,
    pub peers: Vec<NetworkPeerIntent>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedGatewayIntent {
    pub intent: GatewayIntent,
    pub certificate: crate::SignedCertificate,
    pub signature: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkManagerStatus {
    pub owner_process_id: u32,
    pub desired_revision: u64,
    pub applied_revision: Option<u64>,
    pub interface_name: Option<String>,
    pub error_code: Option<String>,
}
