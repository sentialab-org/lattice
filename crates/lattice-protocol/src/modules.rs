//! Optional roles extend a persistent Base Node; no module owns another interface.
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleActivation {
    pub kind: ModuleKind,
    pub certificate: Option<crate::SignedCertificate>,
    pub authority_data_dir: Option<String>,
    #[serde(default)]
    pub adopt_gateway: bool,
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
