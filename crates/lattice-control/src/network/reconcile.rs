//! Compatibility status for signed intent publication. OS application belongs to Base Node.
pub use super::intent::intent_for;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayApplyReport {
    pub desired_revision: u64,
    pub applied_revision: Option<u64>,
    pub error_code: Option<String>,
}
