use crate::NodeRole;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub executable: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundleManifest {
    pub source_revision: String,
    pub schema_version: u32,
    pub version: String,
    pub target: String,
    pub role: NodeRole,
    pub files: Vec<BundleFile>,
}
