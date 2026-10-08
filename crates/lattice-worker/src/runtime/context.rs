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

        match (
            &self.descriptor.artifact_path,
            &self.descriptor.artifact_sha256,
            self.descriptor.artifact_size,
        ) {
            (Some(path_str), Some(sha256), Some(size)) => {
                let path = PathBuf::from(path_str);
                verify_file_digest(&path, sha256, size, "artifact").await?;
            }
            (None, None, None) => {}
            _ => {
                return Err(
                    "inconsistent artifact descriptor: artifact_path, artifact_sha256, and artifact_size must all be specified together"
                        .to_string(),
                );
            }
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

    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|err| format!("{label}_open_failed: {err}"))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .await
            .map_err(|err| format!("{label}_read_failed: {err}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let digest = format!("{:x}", hasher.finalize());

    if digest != expected_sha256 {
        return Err(format!(
            "{label}_sha256_mismatch: expected {expected_sha256}, got {digest}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::{ResourceLimits, WorkloadKind};
    use std::collections::BTreeMap;

    fn sample_descriptor(
        runtime_path: &Path,
        runtime_hash: &str,
        runtime_size: u64,
    ) -> WorkerJobDescriptor {
        WorkerJobDescriptor {
            protocol_version: lattice_protocol::PROTOCOL_VERSION,
            job_id: "test-job-1".to_string(),
            lease_id: "test-lease-1".to_string(),
            workload_kind: WorkloadKind::Mining,
            runtime_id: "xmrig".to_string(),
            runtime_version: "6.22.2".to_string(),
            runtime_path: runtime_path.to_string_lossy().to_string(),
            runtime_sha256: runtime_hash.to_string(),
            runtime_size,
            artifact_path: None,
            artifact_sha256: None,
            artifact_size: None,
            effective_limits: ResourceLimits {
                cpu_percent: 50,
                memory_mb: 1024,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            original_lease_limits: ResourceLimits {
                cpu_percent: 100,
                memory_mb: 2048,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            parameters: BTreeMap::new(),
            work_dir: "/tmp".to_string(),
            log_dir: "/tmp".to_string(),
            ipc_socket_path: "/tmp/sock".to_string(),
            ipc_auth_token: "token".to_string(),
        }
    }

    #[tokio::test]
    async fn test_verify_content_success() {
        let temp_dir = std::env::temp_dir().join(format!("lat-test-ctx-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("runtime_bin");
        let content = b"fake runtime binary content for testing";
        tokio::fs::write(&file_path, content).await.unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = format!("{:x}", hasher.finalize());

        let desc = sample_descriptor(&file_path, &hash, content.len() as u64);
        let ctx = RuntimeContext::new(desc);
        assert!(ctx.verify_content().await.is_ok());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_verify_content_mismatch_fails() {
        let temp_dir = std::env::temp_dir().join(format!("lat-test-ctx-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("runtime_bin");
        tokio::fs::write(&file_path, b"content").await.unwrap();

        let desc = sample_descriptor(
            &file_path,
            "0000000000000000000000000000000000000000000000000000000000000000",
            7,
        );
        let ctx = RuntimeContext::new(desc);
        let err = ctx.verify_content().await.unwrap_err();
        assert!(err.contains("sha256_mismatch"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_verify_content_inconsistent_artifact_fails() {
        let temp_dir = std::env::temp_dir().join(format!("lat-test-ctx-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("runtime_bin");
        let content = b"content";
        tokio::fs::write(&file_path, content).await.unwrap();

        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = format!("{:x}", hasher.finalize());

        let mut desc = sample_descriptor(&file_path, &hash, content.len() as u64);
        desc.artifact_path = Some("/tmp/artifact.json".to_string());
        desc.artifact_sha256 = None;

        let ctx = RuntimeContext::new(desc);
        let err = ctx.verify_content().await.unwrap_err();
        assert!(err.contains("inconsistent artifact descriptor"));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
