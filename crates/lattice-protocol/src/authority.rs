//! Versioned, independently verifiable authority. Directory age is not a grant lifetime.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const AUTHORITY_VERSION: u32 = 2;
pub const CERTIFICATE_DOMAIN: &str = "lattice/certificate/v1";
pub const SNAPSHOT_DOMAIN: &str = "lattice/authority-snapshot/v1";
pub const COMMAND_DOMAIN: &str = "lattice/workload-command/v1";
pub const ADMISSION_DOMAIN: &str = "lattice/workload-admission/v1";
pub const NETWORK_INTENT_DOMAIN: &str = "lattice/network-intent/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CommandScope {
    Workloads,
    ResourceControl,
    Inventory,
    Content,
    Updates,
    NetworkForwarding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CertificateSubject {
    Membership {
        node_id: String,
        node_public_key: String,
        terms_version: String,
        terms_sha256: String,
    },
    Master {
        node_id: String,
        node_public_key: String,
        control_id: String,
        control_public_key: String,
        overlay_ipv4: String,
    },
    Relay {
        node_id: String,
        node_public_key: String,
        transport_public_key: String,
        overlay_ipv4: String,
        endpoint: String,
        bandwidth_limit_bps: u64,
    },
}
impl CertificateSubject {
    pub fn node_id(&self) -> &str {
        match self {
            Self::Membership { node_id, .. }
            | Self::Master { node_id, .. }
            | Self::Relay { node_id, .. } => node_id,
        }
    }
    pub fn node_public_key(&self) -> &str {
        match self {
            Self::Membership {
                node_public_key, ..
            }
            | Self::Master {
                node_public_key, ..
            }
            | Self::Relay {
                node_public_key, ..
            } => node_public_key,
        }
    }
    pub fn revocation_key(&self) -> String {
        match self {
            Self::Membership { node_id, .. } => format!("node/{node_id}"),
            Self::Master { control_id, .. } => format!("master/{control_id}"),
            Self::Relay { node_id, .. } => format!("relay/{node_id}"),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCertificate {
    pub schema_version: u32,
    pub network_id: String,
    pub issuer_key_id: String,
    pub authority_epoch: u64,
    pub certificate_id: String,
    pub subject: CertificateSubject,
    pub scopes: BTreeSet<CommandScope>,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub not_before_ms: u64,
    pub expires_at_ms: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCertificate {
    pub certificate: CapabilityCertificate,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySnapshot {
    pub schema_version: u32,
    pub network_id: String,
    pub issuer_key_id: String,
    pub authority_epoch: u64,
    pub revision: u64,
    pub issued_at_ms: u64,
    pub certificates: Vec<SignedCertificate>,
    pub revocations: BTreeMap<String, u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthoritySnapshot {
    pub snapshot: AuthoritySnapshot,
    pub signature: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SignedAuthoritySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_certificate: Option<SignedCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_certificate: Option<SignedCertificate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_certificate: Option<SignedCertificate>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandContext {
    pub schema_version: u32,
    pub network_id: String,
    pub control_id: String,
    pub target_node_id: String,
    pub request_id: String,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub payload_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCommandProof {
    pub context: CommandContext,
    pub certificate: SignedCertificate,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedWorkloadJoin {
    pub schema_version: u32,
    pub enrollment: crate::EnrollmentClaim,
    pub membership_certificate: SignedCertificate,
    pub master_control_id: String,
    pub owner_choice: crate::MasterChoice,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedWorkloadJoinRequest {
    pub claim: CertifiedWorkloadJoin,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertifiedEnrollmentResponse {
    pub enrollment: crate::EnrollmentResponse,
    pub authority: AuthorityContext,
}
