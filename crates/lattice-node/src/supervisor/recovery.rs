//! Protected control checkpoints preserve execution policy across daemon restarts.
use super::*;
use lattice_protocol::*;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionCheckpoint {
    node_id: String,
    lease_id: String,
    job_id: String,
    control_id: String,
    control_public_key: String,
    pub limits: ResourceLimits,
    pub paused: bool,
    pub stopped: bool,
    runtime_patch: Option<JobControlPatch>,
}
impl ExecutionCheckpoint {
    pub fn apply(&mut self, revision: &JobControlRevision) {
        match revision.action {
            JobControlAction::Pause => self.paused = true,
            JobControlAction::Resume => self.paused = false,
            JobControlAction::Stop => self.stopped = true,
            JobControlAction::UpdateLimits => {}
        }
        if let Some(JobControlPatch::Mining(next)) = &revision.runtime_patch {
            let mut patch = match self.runtime_patch.take() {
                Some(JobControlPatch::Mining(patch)) => patch,
                None => MiningControlPatch::default(),
            };
            if next.threads.is_some() {
                patch.threads = next.threads;
            }
            if next.pool.is_some() {
                patch.pool = next.pool.clone();
            }
            if next.worker.is_some() {
                patch.worker = next.worker.clone();
            }
            if next.password.is_some() {
                patch.password = next.password.clone();
            }
            self.runtime_patch = Some(JobControlPatch::Mining(patch));
        }
    }
}
pub(super) async fn validate_checkpoint(
    state: &AppState,
    active: &JobLeaseStatus,
    checkpoint: &ExecutionCheckpoint,
) -> Result<(), String> {
    let identity = state.identity.read().await;
    let trust = identity
        .trust()
        .ok_or("control checkpoint requires the retained Master identity")?;
    if checkpoint.node_id != active.lease.node_id
        || checkpoint.node_id != identity.identity().node_id
        || checkpoint.lease_id != active.lease.lease_id
        || checkpoint.job_id != active.lease.offer.job_id
        || checkpoint.control_id != trust.control_id
        || checkpoint.control_public_key != trust.control_public_key
    {
        return Err("control checkpoint identity binding mismatch".into());
    }
    Ok(())
}
pub(super) async fn checkpoint_for(
    state: &AppState,
    active: &JobLeaseStatus,
    policy: &NodePolicy,
) -> Result<ExecutionCheckpoint, String> {
    let trust = state
        .identity
        .read()
        .await
        .trust()
        .cloned()
        .ok_or("retained Master identity required")?;
    Ok(ExecutionCheckpoint {
        node_id: active.lease.node_id.clone(),
        lease_id: active.lease.lease_id.clone(),
        job_id: active.lease.offer.job_id.clone(),
        control_id: trust.control_id,
        control_public_key: trust.control_public_key,
        limits: compute_effective_limits(
            &active.lease.offer.limits,
            &None,
            &active.lease.offer.limits,
            policy,
        )?,
        paused: false,
        stopped: false,
        runtime_patch: None,
    })
}
pub(super) async fn load_control_state(
    config: &Path,
    lease_id: &str,
    required: bool,
) -> Result<NodeLeaseControlState, String> {
    validate_lease_id(lease_id)?;
    use std::io::Read;
    let path = control_state_path(config, lease_id);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return Ok(NodeLeaseControlState {
                latest_seen_revision: 0,
                latest_seen_revision_digest: String::new(),
                latest_applied_revision: 0,
                latest_applied_result: None,
                last_successful: None,
                pending: None,
            });
        }
        Err(_) => return Err("required control checkpoint unavailable".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "control checkpoint metadata unavailable")?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err("control checkpoint rejected".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("control checkpoint requires private ownership".into());
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "control checkpoint unreadable")?;
    serde_json::from_slice(&bytes).map_err(|_| "control checkpoint corrupt".into())
}
pub(super) async fn save_control_state(
    state: &AppState,
    lease_id: &str,
    checkpoint: &NodeLeaseControlState,
) -> Result<(), String> {
    validate_lease_id(lease_id)?;
    if serde_json::to_vec(checkpoint)
        .map_err(|_| "control checkpoint encoding failed")?
        .len()
        > 65536
    {
        return Err("control checkpoint exceeds the supported size".into());
    }
    crate::job::require_control_checkpoint(state, lease_id).await?;
    let path = control_state_path(&state.config_path, lease_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "control checkpoint directory unavailable")?;
        secure_directory(parent)?;
    }
    lattice_network::write_atomic_private(&path, checkpoint)
}
pub(super) async fn apply_dormant_control(
    state: &Arc<AppState>,
    active: &JobLeaseStatus,
    signed: SignedJobControlRevision,
    mut checkpoint: NodeLeaseControlState,
    policy: &NodePolicy,
) -> Result<SignedJobControlAck, String> {
    let revision = &signed.revision;
    if revision.action != JobControlAction::UpdateLimits
        && (revision.resource_patch.is_some() || revision.runtime_patch.is_some())
    {
        return Err("Pause, Resume and Stop cannot contain execution patches".into());
    }
    if revision.runtime_patch.is_some() && active.lease.offer.workload_kind != WorkloadKind::Mining
    {
        return Err("Mining patch requires a Mining assignment".into());
    }
    let mut execution = checkpoint
        .last_successful
        .clone()
        .unwrap_or(checkpoint_for(state, active, policy).await?);
    execution.limits = compute_effective_limits(
        &execution.limits,
        &revision.resource_patch,
        &active.lease.offer.limits,
        policy,
    )?;
    if revision.action == JobControlAction::Resume
        && (execution.stopped
            || matches!(
                active.state,
                JobState::Completed | JobState::Failed | JobState::Rejected
            ))
    {
        return Err("a terminal assignment cannot be resumed".into());
    }
    // Persist the paused baseline and exact intent before any executor side effect.
    execution.paused = true;
    checkpoint.last_successful = Some(execution.clone());
    checkpoint.latest_seen_revision = revision.revision;
    checkpoint.latest_seen_revision_digest =
        sha256_hex(&serde_json::to_vec(revision).map_err(|_| "control encoding failed")?);
    checkpoint.latest_applied_result = None;
    checkpoint.pending = Some(signed.clone());
    save_control_state(state, &revision.lease_id, &checkpoint).await?;
    if revision.action == JobControlAction::Stop {
        suspend_active(state, "authorized cancellation").await?;
    }
    if revision.action == JobControlAction::Resume {
        let result = async {
            let content = crate::job::prepare_active_content(state)
                .await?
                .ok_or("content preparation failed")?;
            start_prepared_job(state, &active.lease.offer, content, Some(&signed)).await?;
            let trust = state
                .identity
                .read()
                .await
                .trust()
                .cloned()
                .ok_or("execution authority unavailable")?;
            crate::authorization::require_scope(state, &trust, CommandScope::ResourceControl)
                .await?;
            if unix_time_ms() >= revision.expires_at_ms {
                return Err("Resume expired during startup".into());
            }
            Ok::<(), String>(())
        }
        .await;
        if let Err(error) = result {
            suspend_active(state, "resume_startup_failed").await?;
            return Err(error);
        }
    }
    execution.apply(revision);
    let ack = JobControlAck {
        protocol_version: PROTOCOL_VERSION,
        node_id: active.lease.node_id.clone(),
        lease_id: active.lease.lease_id.clone(),
        job_id: active.lease.offer.job_id.clone(),
        revision: revision.revision,
        applied: true,
        effective_limits: execution.limits.clone(),
        runtime_state: if execution.stopped {
            JobState::Completed
        } else if revision.action == JobControlAction::Resume {
            JobState::Running
        } else {
            active.state.clone()
        },
        reason: Some(
            if revision.action == JobControlAction::Resume {
                "verified worker backend started"
            } else {
                "applied to the retained dormant assignment"
            }
            .into(),
        ),
        acknowledged_at_ms: unix_time_ms(),
    };
    checkpoint.latest_seen_revision = revision.revision;
    checkpoint.latest_seen_revision_digest =
        sha256_hex(&serde_json::to_vec(revision).map_err(|_| "control encoding failed")?);
    checkpoint.latest_applied_revision = revision.revision;
    checkpoint.latest_applied_result = Some(ack.clone());
    checkpoint.last_successful = Some(execution);
    checkpoint.pending = None;
    if let Err(error) = save_control_state(state, &revision.lease_id, &checkpoint).await {
        suspend_active(state, "control_checkpoint_commit_failed").await?;
        return Err(error);
    }
    if revision.action == JobControlAction::Stop {
        stop_active(state, "control_action_stop").await?;
    }
    let signature = sign(state.identity.read().await.private_key(), &ack)?;
    Ok(SignedJobControlAck { ack, signature })
}

pub(super) struct RecoveredExecution {
    pub limits: ResourceLimits,
    pub parameters: std::collections::BTreeMap<String, String>,
    pub paused: bool,
    pub stopped: bool,
}
pub(super) async fn recovered_execution(
    state: &AppState,
    active: &JobLeaseStatus,
    policy: &NodePolicy,
    resume: Option<&SignedJobControlRevision>,
) -> Result<RecoveredExecution, String> {
    let checkpoint = load_control_state(
        &state.config_path,
        &active.lease.lease_id,
        active.control_state_required,
    )
    .await?;
    if let Some(pending) = &checkpoint.pending {
        if resume != Some(pending) || pending.revision.action != JobControlAction::Resume {
            return Err("control checkpoint has an interrupted operation".into());
        }
    }
    let execution = match checkpoint.last_successful {
        Some(execution) => {
            validate_checkpoint(state, active, &execution).await?;
            execution
        }
        None if checkpoint.latest_seen_revision == 0 => {
            checkpoint_for(state, active, policy).await?
        }
        None => {
            return Err(
                "legacy control checkpoint requires explicit cancellation and reassignment".into(),
            );
        }
    };
    let limits =
        compute_effective_limits(&execution.limits, &None, &active.lease.offer.limits, policy)?;
    let mut parameters = active.lease.offer.parameters.clone();
    if let Some(JobControlPatch::Mining(patch)) = execution.runtime_patch {
        if active.lease.offer.workload_kind != WorkloadKind::Mining {
            return Err("control checkpoint runtime binding mismatch".into());
        }
        if let Some(threads) = patch.threads {
            parameters.insert("threads".into(), threads.to_string());
        }
        for (name, value) in [
            ("pool", patch.pool),
            ("worker", patch.worker),
            ("password", patch.password),
        ] {
            if let Some(value) = value {
                parameters.insert(name.into(), value);
            }
        }
    }
    Ok(RecoveredExecution {
        limits,
        parameters,
        paused: execution.paused && resume.is_none(),
        stopped: execution.stopped,
    })
}

/// Replay only a previously persisted receipt; a retry never reapplies effects to another lease.
pub(super) async fn replay_control_receipt(
    state: &AppState,
    signed: &SignedJobControlRevision,
) -> Result<Option<SignedJobControlAck>, String> {
    let revision = &signed.revision;
    let stored = load_control_state(&state.config_path, &revision.lease_id, false).await?;
    if stored.latest_seen_revision != revision.revision
        || stored.latest_seen_revision_digest
            != sha256_hex(&serde_json::to_vec(revision).map_err(|_| "control encoding failed")?)
    {
        return Ok(None);
    }
    let Some(ack) = stored.latest_applied_result else {
        return Ok(None);
    };
    let Some(binding) = stored.last_successful else {
        return Ok(None);
    };
    let identity = state.identity.read().await;
    let trust = identity
        .trust()
        .ok_or("retained Master identity required")?;
    if binding.node_id != identity.identity().node_id
        || binding.node_id != revision.node_id
        || binding.lease_id != revision.lease_id
        || binding.job_id != revision.job_id
        || binding.control_id != trust.control_id
        || binding.control_public_key != trust.control_public_key
        || ack.node_id != revision.node_id
        || ack.lease_id != revision.lease_id
        || ack.job_id != revision.job_id
        || ack.revision != revision.revision
    {
        return Err("control receipt identity binding mismatch".into());
    }
    Ok(Some(SignedJobControlAck {
        signature: sign(identity.private_key(), &ack)?,
        ack,
    }))
}
