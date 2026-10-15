use serde::{Deserialize, Serialize};
pub const PRODUCT_SCHEMA_VERSION: u32 = 1;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSession {
    pub username: String,
    pub csrf_token: String,
    pub idle_expires_at_ms: u64,
    pub absolute_expires_at_ms: u64,
}
