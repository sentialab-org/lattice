use crate::AppState;
use crate::identity::unix_time_ms;
use lattice_crypto::{sign, verify};
use lattice_protocol::{
    ApiError, JobDecisionClaim, JobDecisionRequest, JobDecisionResponse, JobLeaseStatus, JobState,
    PROTOCOL_VERSION, SignedJobLease, job_allowed_by_policy,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

pub fn active_lease_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("active-lease.json")
}

pub async fn load(path: &Path) -> Result<Option<JobLeaseStatus>, String> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };

    let status: JobLeaseStatus =
        serde_json::from_str(&content).map_err(|error| error.to_string())?;
    let now = unix_time_ms();

    if status.lease.expires_at_ms <= now || status.lease.offer.expires_at_ms <= now {
        clear(path).await?;
        return Ok(None);
    }

    Ok(Some(status))
}

pub async fn clear(path: &Path) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub async fn expire_local(state: &Arc<AppState>) -> Result<(), String> {
    let expired = state
        .active_lease
        .read()
        .await
        .as_ref()
        .is_some_and(|status| {
            let now = unix_time_ms();
            status.lease.expires_at_ms <= now || status.lease.offer.expires_at_ms <= now
        });

    if !expired {
        return Ok(());
    }

    clear(&state.active_lease_path).await?;
    *state.active_lease.write().await = None;
    Ok(())
}

pub async fn handle(state: &Arc<AppState>, signed: SignedJobLease) -> Result<(), String> {
    let (identity, private_key, trust) = {
        let identity = state.identity.read().await;
        let trust = identity
            .trust()
            .cloned()
            .ok_or_else(|| "node is not enrolled".to_string())?;
        (identity.identity().clone(), *identity.private_key(), trust)
    };

    verify(&trust.control_public_key, &signed.signature, &signed.lease)
        .map_err(|error| format!("invalid job lease signature: {error}"))?;

    if signed.lease.node_id != identity.node_id {
        return Err("job lease node ID mismatch".to_string());
    }

    if let Some(current) = state.active_lease.read().await.as_ref()
        && current.lease.lease_id == signed.lease.lease_id
        && matches!(
            current.state,
            JobState::Accepted
                | JobState::Rejected
                | JobState::Preparing
                | JobState::Running
                | JobState::Stopping
                | JobState::Completed
                | JobState::Failed
        )
    {
        return Ok(());
    }

    let rejection = validate(state, &signed).await;
    let accepted = rejection.is_none();
    let reason = rejection.clone();

    let offered = JobLeaseStatus {
        lease: signed.lease.clone(),
        state: JobState::Offered,
        reason: None,
    };
    persist_status(state, offered).await?;

    let claim = JobDecisionClaim {
        protocol_version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: identity.node_id.clone(),
        lease_id: signed.lease.lease_id.clone(),
        job_id: signed.lease.offer.job_id.clone(),
        accepted,
        reason: reason.clone(),
        issued_at_ms: unix_time_ms(),
    };
    let request = JobDecisionRequest {
        signature: sign(&private_key, &claim)?,
        claim: claim.clone(),
    };
    let response = state
        .http
        .post(format!("{}/api/v1/jobs/decision", trust.control_url))
        .json(&request)
        .send()
        .await
        .map_err(|error| format!("job decision request failed: {error}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Ok(error) = serde_json::from_str::<ApiError>(&body) {
            return Err(format!("{}: {}", error.code, error.message));
        }
        return Err(format!("control server returned HTTP {status}"));
    }

    let decision: JobDecisionResponse = response.json().await.map_err(|error| error.to_string())?;

    if decision.receipt.protocol_version != PROTOCOL_VERSION {
        return Err("job decision protocol version mismatch".to_string());
    }

    if decision.receipt.request_id != claim.request_id
        || decision.receipt.node_id != identity.node_id
        || decision.receipt.lease_id != signed.lease.lease_id
        || decision.receipt.job_id != signed.lease.offer.job_id
    {
        return Err("job decision receipt does not match the lease".to_string());
    }

    if decision.receipt.control_id != trust.control_id {
        return Err("job decision control identity mismatch".to_string());
    }

    let expected_state = if accepted {
        JobState::Accepted
    } else {
        JobState::Rejected
    };

    if decision.receipt.state != expected_state {
        return Err("job decision state mismatch".to_string());
    }

    verify(
        &trust.control_public_key,
        &decision.signature,
        &decision.receipt,
    )
    .map_err(|error| format!("invalid job decision receipt signature: {error}"))?;

    persist_status(
        state,
        JobLeaseStatus {
            lease: signed.lease,
            state: expected_state,
            reason,
        },
    )
    .await
}

async fn validate(state: &Arc<AppState>, signed: &SignedJobLease) -> Option<String> {
    let now = unix_time_ms();

    if signed.lease.decision_deadline_ms <= now {
        return Some("lease_decision_deadline_expired".to_string());
    }

    if signed.lease.expires_at_ms <= now {
        return Some("lease_expired".to_string());
    }

    if signed.lease.offer.expires_at_ms <= now {
        return Some("job_expired".to_string());
    }

    if let Some(current) = state.active_lease.read().await.as_ref()
        && current.lease.lease_id != signed.lease.lease_id
        && matches!(
            current.state,
            JobState::Accepted | JobState::Preparing | JobState::Running | JobState::Stopping
        )
    {
        return Some("node_already_has_active_lease".to_string());
    }

    let local = state.config.read().await.policy.clone();
    let remote = state.remote_policy.read().await.clone();
    let effective = crate::policy::effective(&local, remote.as_ref());

    if !job_allowed_by_policy(&effective, &signed.lease.offer) {
        return Some("job_exceeds_effective_policy".to_string());
    }

    let hardware = crate::hardware_snapshot(state).await;

    if signed.lease.offer.limits.memory_mb > hardware.memory.total_mb {
        return Some("insufficient_memory".to_string());
    }

    if signed.lease.offer.limits.gpu_percent.is_some() && hardware.gpus.is_empty() {
        return Some("gpu_not_available".to_string());
    }

    if let Some(required_vram) = signed.lease.offer.limits.gpu_memory_mb
        && !hardware.gpus.iter().any(|gpu| {
            gpu.memory_total_mb
                .is_some_and(|total| total >= required_vram)
        })
    {
        return Some("insufficient_gpu_memory".to_string());
    }

    None
}

async fn persist_status(state: &Arc<AppState>, status: JobLeaseStatus) -> Result<(), String> {
    if let Some(parent) = state.active_lease_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
    }

    let content = serde_json::to_vec_pretty(&status).map_err(|error| error.to_string())?;
    tokio::fs::write(&state.active_lease_path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(&state.active_lease_path)?;
    *state.active_lease.write().await = Some(status);
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}
