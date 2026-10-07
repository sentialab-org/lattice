#![allow(dead_code)]

use lattice_protocol::{JobState, ResourceLimits, WorkerJobDescriptor};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct RuntimeContext {
    pub descriptor: WorkerJobDescriptor,
    pub current_limits: ResourceLimits,
    pub job_dir: PathBuf,
    pub log_dir: PathBuf,
    pub active_state: JobState,
}

impl RuntimeContext {
    pub fn new(descriptor: WorkerJobDescriptor) -> Self {
        let current_limits = descriptor.effective_limits.clone();
        let job_dir = PathBuf::from(&descriptor.work_dir);
        let log_dir = PathBuf::from(&descriptor.log_dir);

        Self {
            descriptor,
            current_limits,
            job_dir,
            log_dir,
            active_state: JobState::Accepted,
        }
    }

    pub fn job_id(&self) -> &str {
        &self.descriptor.job_id
    }

    pub fn lease_id(&self) -> &str {
        &self.descriptor.lease_id
    }

    pub fn runtime_path(&self) -> PathBuf {
        PathBuf::from(&self.descriptor.runtime_path)
    }

    pub fn artifact_path(&self) -> Option<PathBuf> {
        self.descriptor.artifact_path.as_ref().map(PathBuf::from)
    }

    /// Re-verifies runtime payload and artifact content immediately before backend execution.
    /// This enforces the immutable content-binding invariant (CRIT-03).
    pub async fn verify_content(&self) -> Result<(), String> {
        let runtime_path = self.runtime_path();
        verify_file_digest(
            &runtime_path,
            &self.descriptor.runtime_sha256,
            self.descriptor.runtime_size,
            "runtime",
        )
        .await?;

        if let (Some(path), Some(sha256)) = (self.artifact_path(), &self.descriptor.artifact_sha256)
        {
            let size = self.descriptor.artifact_size.unwrap_or(0);
            verify_file_digest(&path, sha256, size, "artifact").await?;
        }

        Ok(())
    }
}

async fn verify_file_digest(
    path: &Path,
    expected_sha256: &str,
    expected_size: u64,
    label: &str,
) -> Result<(), String> {
    if !path.exists() {
        return Err(format!(
            "{label}_content_missing: path does not exist: {}",
            path.display()
        ));
    }

    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|err| format!("{label}_metadata_failed: {err}"))?;

    if expected_size > 0 && metadata.len() != expected_size {
        return Err(format!(
            "{label}_size_mismatch: expected {expected_size} bytes, got {} bytes",
            metadata.len()
        ));
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|err| format!("{label}_read_failed: {err}"))?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = format!("{:x}", hasher.finalize());

    if digest != expected_sha256 {
        return Err(format!(
            "{label}_sha256_mismatch: expected {expected_sha256}, got {digest}"
        ));
    }

    Ok(())
}
