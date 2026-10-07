use crate::{ApiResponseError, AppState, unix_time_ms};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use lattice_crypto::{decode_key, sign, verify};
use lattice_protocol::{
    Architecture, JobDecisionReceipt, JobDecisionRequest, JobDecisionResponse, JobLease, JobOffer,
    JobState, JobStatusEvent, JobStatusReceipt, JobStatusRequest, JobStatusResponse,
    NodeCapabilities, NodePolicy, PROTOCOL_VERSION, Platform, ResourceLimits, SignedJobControlAck,
    SignedJobControlRevision, SignedJobLease, WorkloadKind, job_allowed_by_policy,
    job_status_transition_allowed, mining_config_from_offer,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JobQueue {
    pub jobs: Vec<JobRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    pub offer: JobOffer,
    #[serde(default)]
    pub target_node_id: Option<String>,
    #[serde(default = "queued_state")]
    pub state: JobState,
    #[serde(default)]
    pub lease: Option<JobLease>,
    #[serde(default)]
    pub decision_reason: Option<String>,
    #[serde(default)]
    pub events: Vec<JobStatusEvent>,
    #[serde(default)]
    pub last_event_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_revision: Option<SignedJobControlRevision>,
    #[serde(default)]
    pub applied_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_limits: Option<ResourceLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_control_error: Option<String>,
}

fn queued_state() -> JobState {
    JobState::Queued
}

pub async fn enqueue(
    path: &Path,
    queue: &mut JobQueue,
    offer: JobOffer,
    target_node_id: Option<String>,
) -> Result<JobRecord, String> {
    if queue
        .jobs
        .iter()
        .any(|record| record.offer.job_id == offer.job_id)
    {
        return Err("job ID already exists".to_string());
    }
    let record = JobRecord {
        offer,
        target_node_id,
        state: JobState::Queued,
        lease: None,
        decision_reason: None,
        events: vec![],
        last_event_sequence: 0,
        desired_revision: None,
        applied_revision: 0,
        applied_limits: None,
        last_control_error: None,
    };
    queue.jobs.push(record.clone());
    save_path(path, queue).await?;
    Ok(record)
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, JobQueue), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("jobs.json");

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let queue: JobQueue = serde_json::from_str(&content)?;
            Ok((path, queue))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let queue = JobQueue::default();
            save_path(&path, &queue).await?;
            Ok((path, queue))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn offer_for_node(
    state: &AppState,
    node_id: &str,
    now: u64,
) -> Result<Option<SignedJobLease>, ApiResponseError> {
    let (effective_policy, capabilities, platform, architecture) = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        (
            node.effective_policy.clone(),
            node.capabilities.clone(),
            node.platform.clone(),
            node.architecture.clone(),
        )
    };

    let Some(effective_policy) = effective_policy else {
        return Ok(None);
    };
    let Some(capabilities) = capabilities else {
        return Ok(None);
    };

    let artifacts = state.artifacts.read().await.clone();
    let runtimes = state.runtimes.read().await.clone();
    let mut queue = state.jobs.write().await;
    let mut changed = expire_stale_leases(&mut queue, now);

    if let Some(existing) = queue.jobs.iter().find_map(|record| {
        let lease = record.lease.as_ref()?;
        let decision_window_valid =
            record.state == JobState::Accepted || lease.decision_deadline_ms > now;
        if matches!(record.state, JobState::Offered | JobState::Accepted)
            && lease.node_id == node_id
            && decision_window_valid
            && lease.expires_at_ms > now
            && record.offer.expires_at_ms > now
        {
            Some(lease.clone())
        } else {
            None
        }
    }) {
        if changed {
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
        }
        return sign_lease(state, existing, &platform, &architecture)
            .await
            .map(Some);
    }

    if queue.jobs.iter().any(|record| {
        record.lease.as_ref().is_some_and(|lease| {
            lease.node_id == node_id
                && matches!(
                    record.state,
                    JobState::Preparing | JobState::Running | JobState::Stopping
                )
        })
    }) {
        if changed {
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
        }
        return Ok(None);
    }

    let selected = queue.jobs.iter_mut().find(|record| {
        record.state == JobState::Queued
            && record.offer.expires_at_ms > now
            && record
                .target_node_id
                .as_deref()
                .is_none_or(|target| target == node_id)
            && crate::artifacts::resolve(&artifacts, &record.offer).is_some()
            && crate::runtimes::resolve(&runtimes, &record.offer, &platform, &architecture)
                .is_some()
            && eligible(&record.offer, &effective_policy, &capabilities)
    });

    let Some(record) = selected else {
        if changed {
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
        }
        return Ok(None);
    };

    let lease = JobLease {
        lease_id: format!("lease_{}", Uuid::new_v4().simple()),
        node_id: node_id.to_string(),
        offer: record.offer.clone(),
        issued_at_ms: now,
        decision_deadline_ms: now.saturating_add(30_000).min(record.offer.expires_at_ms),
        expires_at_ms: record.offer.expires_at_ms,
    };
    record.state = JobState::Offered;
    record.lease = Some(lease.clone());
    record.decision_reason = None;
    changed = true;

    if changed {
        save_path(&state.jobs_path, &queue)
            .await
            .map_err(ApiResponseError::internal)?;
    }

    sign_lease(state, lease, &platform, &architecture)
        .await
        .map(Some)
}

pub async fn status(
    State(state): State<AppState>,
    Json(request): Json<JobStatusRequest>,
) -> Result<Json<JobStatusResponse>, ApiResponseError> {
    if request.claim.protocol_version != PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.event.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_job_status",
            "job status timestamp is outside the allowed window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        registry
            .nodes
            .get(&request.claim.node_id)
            .map(|node| node.public_key.clone())
            .ok_or_else(|| ApiResponseError::unauthorized("unknown_node", "node is not enrolled"))?
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized("invalid_node_signature", "job status signature is invalid")
    })?;

    {
        let mut queue = state.jobs.write().await;
        let record = queue
            .jobs
            .iter_mut()
            .find(|record| {
                record.offer.job_id == request.claim.event.job_id
                    && record
                        .lease
                        .as_ref()
                        .is_some_and(|lease| lease.lease_id == request.claim.event.lease_id)
            })
            .ok_or_else(|| {
                ApiResponseError::conflict("unknown_lease", "job lease does not exist")
            })?;
        let lease = record.lease.as_ref().ok_or_else(|| {
            ApiResponseError::conflict("unknown_lease", "job lease does not exist")
        })?;

        if lease.node_id != request.claim.node_id {
            return Err(ApiResponseError::unauthorized(
                "lease_node_mismatch",
                "job lease belongs to another node",
            ));
        }

        if lease.expires_at_ms <= now || record.offer.expires_at_ms <= now {
            record.state = JobState::Expired;
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
            return Err(ApiResponseError::conflict(
                "lease_expired",
                "job lease has expired",
            ));
        }

        if let Some(existing) = record
            .events
            .iter()
            .find(|event| event.event_id == request.claim.event.event_id)
        {
            if existing != &request.claim.event {
                return Err(ApiResponseError::conflict(
                    "event_id_conflict",
                    "job status event ID was reused with different content",
                ));
            }
        } else {
            if request.claim.event.sequence <= record.last_event_sequence {
                return Err(ApiResponseError::conflict(
                    "replayed_job_status",
                    "job status sequence was already observed",
                ));
            }

            let initial_accepted = record.state == JobState::Accepted
                && record.events.is_empty()
                && request.claim.event.state == JobState::Accepted;
            if !initial_accepted
                && !job_status_transition_allowed(&record.state, &request.claim.event.state)
            {
                return Err(ApiResponseError::conflict(
                    "invalid_job_transition",
                    "job status transition is not allowed",
                ));
            }

            record.state = request.claim.event.state.clone();
            record.last_event_sequence = request.claim.event.sequence;
            record.events.push(request.claim.event.clone());
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
        }
    }

    let receipt = JobStatusReceipt {
        protocol_version: PROTOCOL_VERSION,
        event_id: request.claim.event.event_id,
        node_id: request.claim.node_id,
        lease_id: request.claim.event.lease_id,
        job_id: request.claim.event.job_id,
        state: request.claim.event.state,
        control_id: state.control.control_id.clone(),
        issued_at_ms: now,
    };
    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(JobStatusResponse { receipt, signature }))
}

pub async fn decision(
    State(state): State<AppState>,
    Json(request): Json<JobDecisionRequest>,
) -> Result<Json<JobDecisionResponse>, ApiResponseError> {
    if request.claim.protocol_version != PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_job_decision",
            "job decision timestamp is outside the allowed window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        registry
            .nodes
            .get(&request.claim.node_id)
            .map(|node| node.public_key.clone())
            .ok_or_else(|| ApiResponseError::unauthorized("unknown_node", "node is not enrolled"))?
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "job decision signature is invalid",
        )
    })?;

    let target_state = if request.claim.accepted {
        JobState::Accepted
    } else {
        JobState::Rejected
    };

    {
        let mut queue = state.jobs.write().await;
        let record = queue
            .jobs
            .iter_mut()
            .find(|record| {
                record.offer.job_id == request.claim.job_id
                    && record
                        .lease
                        .as_ref()
                        .is_some_and(|lease| lease.lease_id == request.claim.lease_id)
            })
            .ok_or_else(|| {
                ApiResponseError::conflict("unknown_lease", "job lease does not exist")
            })?;
        let lease = record.lease.as_ref().ok_or_else(|| {
            ApiResponseError::conflict("unknown_lease", "job lease does not exist")
        })?;

        if lease.node_id != request.claim.node_id {
            return Err(ApiResponseError::unauthorized(
                "lease_node_mismatch",
                "job lease belongs to another node",
            ));
        }

        if lease.decision_deadline_ms <= now
            || lease.expires_at_ms <= now
            || record.offer.expires_at_ms <= now
        {
            record.state = JobState::Expired;
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
            return Err(ApiResponseError::conflict(
                "lease_expired",
                "job lease has expired",
            ));
        }

        if record.state == JobState::Offered {
            record.state = target_state.clone();
            record.decision_reason = request.claim.reason.clone();
            save_path(&state.jobs_path, &queue)
                .await
                .map_err(ApiResponseError::internal)?;
        } else if record.state != target_state {
            return Err(ApiResponseError::conflict(
                "invalid_job_state",
                "job is no longer awaiting this decision",
            ));
        }
    }

    let receipt = JobDecisionReceipt {
        protocol_version: PROTOCOL_VERSION,
        request_id: request.claim.request_id,
        node_id: request.claim.node_id,
        lease_id: request.claim.lease_id,
        job_id: request.claim.job_id,
        state: target_state,
        control_id: state.control.control_id.clone(),
        issued_at_ms: now,
    };
    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(JobDecisionResponse { receipt, signature }))
}

pub async fn handle_control_ack(
    State(state): State<AppState>,
    Json(signed_ack): Json<SignedJobControlAck>,
) -> Result<StatusCode, ApiResponseError> {
    let ack = &signed_ack.ack;

    if ack.protocol_version != PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "invalid_protocol_version",
            "unsupported protocol version",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&ack.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &signed_ack.signature, ack)
        .map_err(|e| ApiResponseError::unauthorized("invalid_ack_signature", &e))?;

    let mut queue = state.jobs.write().await;
    let Some(record) = queue.jobs.iter_mut().find(|j| j.offer.job_id == ack.job_id) else {
        return Err(ApiResponseError::bad_request(
            "job_not_found",
            "job does not exist",
        ));
    };

    if ack.applied {
        record.applied_revision = ack.revision;
        record.applied_limits = Some(ack.effective_limits.clone());
        record.last_control_error = None;
    } else {
        record.last_control_error = ack.reason.clone();
        // Do NOT advance record.applied_revision when applied is false! (CRIT-07)
    }

    save_path(&state.jobs_path, &queue)
        .await
        .map_err(ApiResponseError::internal)?;

    Ok(StatusCode::OK)
}

fn eligible(offer: &JobOffer, policy: &NodePolicy, capabilities: &NodeCapabilities) -> bool {
    if !job_allowed_by_policy(policy, offer) {
        return false;
    }

    if offer.workload_kind == WorkloadKind::Mining {
        let Ok(config) = mining_config_from_offer(offer) else {
            return false;
        };
        if offer.limits.cpu_percent == 0
            || offer.limits.gpu_percent.is_some()
            || offer.limits.gpu_memory_mb.is_some()
        {
            return false;
        }
        let maximum_threads = (capabilities
            .logical_cores
            .saturating_mul(offer.limits.cpu_percent as usize)
            / 100)
            .max(1);
        if config.threads as usize > maximum_threads {
            return false;
        }
    }

    if offer.limits.memory_mb > capabilities.memory_total_mb {
        return false;
    }

    if offer.limits.gpu_percent.is_some() && capabilities.gpus.is_empty() {
        return false;
    }

    if let Some(required_vram) = offer.limits.gpu_memory_mb
        && !capabilities.gpus.iter().any(|gpu| {
            gpu.memory_total_mb
                .is_some_and(|total| total >= required_vram)
        })
    {
        return false;
    }

    true
}

fn expire_stale_leases(queue: &mut JobQueue, now: u64) -> bool {
    let mut changed = false;

    for record in &mut queue.jobs {
        if record.offer.expires_at_ms <= now
            && !matches!(
                record.state,
                JobState::Completed | JobState::Failed | JobState::Rejected | JobState::Expired
            )
        {
            record.state = JobState::Expired;
            record.lease = None;
            changed = true;
            continue;
        }

        if record.state == JobState::Offered
            && record
                .lease
                .as_ref()
                .is_some_and(|lease| lease.decision_deadline_ms <= now)
        {
            record.state = JobState::Queued;
            record.lease = None;
            record.decision_reason = None;
            changed = true;
        }
    }

    changed
}

async fn sign_lease(
    state: &AppState,
    lease: JobLease,
    platform: &Platform,
    architecture: &Architecture,
) -> Result<SignedJobLease, ApiResponseError> {
    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &lease).map_err(ApiResponseError::internal)?;
    let artifact = {
        let registry = state.artifacts.read().await;
        crate::artifacts::sign_for_offer(&state.control, &registry, &lease.offer)?
    };
    let runtime = {
        let registry = state.runtimes.read().await;
        crate::runtimes::sign_for_offer(
            &state.control,
            &registry,
            &lease.offer,
            platform,
            architecture,
        )?
    };
    Ok(SignedJobLease {
        lease,
        signature,
        artifact,
        runtime,
    })
}

pub async fn save_path(path: &Path, queue: &JobQueue) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(queue).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::{NodePolicy, ResourceLimits, WorkloadKind};
    use std::collections::BTreeMap;

    #[test]
    fn eligibility_respects_effective_policy() {
        let offer = JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: WorkloadKind::Rendering,
            runtime: "blender".to_string(),
            runtime_version: "1".to_string(),
            artifact_id: "scene".to_string(),
            artifact_version: "1".to_string(),
            limits: ResourceLimits {
                cpu_percent: 50,
                memory_mb: 4096,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            parameters: BTreeMap::new(),
            expires_at_ms: u64::MAX,
        };
        let policy = NodePolicy {
            allow_rendering: false,
            ..Default::default()
        };
        let capabilities = NodeCapabilities {
            os: "test".to_string(),
            kernel: "test".to_string(),
            architecture: "x86_64".to_string(),
            cpu_model: "test".to_string(),
            logical_cores: 8,
            physical_cores: Some(4),
            memory_total_mb: 16384,
            gpus: vec![],
        };

        assert!(!eligible(&offer, &policy, &capabilities));
    }

    #[test]
    fn stale_offered_lease_returns_to_queue() {
        let offer = JobOffer {
            job_id: "job-test".to_string(),
            workload_kind: WorkloadKind::Research,
            runtime: "native".to_string(),
            runtime_version: "1".to_string(),
            artifact_id: "artifact".to_string(),
            artifact_version: "1".to_string(),
            limits: ResourceLimits::default(),
            parameters: BTreeMap::new(),
            expires_at_ms: 1000,
        };
        let mut queue = JobQueue {
            jobs: vec![JobRecord {
                offer: offer.clone(),
                target_node_id: None,
                state: JobState::Offered,
                lease: Some(JobLease {
                    lease_id: "lease-test".to_string(),
                    node_id: "node-test".to_string(),
                    offer,
                    issued_at_ms: 100,
                    decision_deadline_ms: 200,
                    expires_at_ms: 1000,
                }),
                decision_reason: None,
                events: vec![],
                last_event_sequence: 0,
                desired_revision: None,
                applied_revision: 0,
                applied_limits: None,
                last_control_error: None,
            }],
        };

        assert!(expire_stale_leases(&mut queue, 300));
        assert_eq!(queue.jobs[0].state, JobState::Queued);
        assert!(queue.jobs[0].lease.is_none());
    }
}
