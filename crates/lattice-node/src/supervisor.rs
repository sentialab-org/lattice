use crate::AppState;
use crate::identity::unix_time_ms;
use crate::resource_containment::OsResourceBoundary;
use lattice_crypto::{sha256_hex, sign, verify};
use lattice_protocol::{
    JobControlAck, JobOffer, JobState, PROTOCOL_VERSION, ResourceLimits, SignedJobControlAck,
    SignedJobControlRevision, WorkerIpcMessage, WorkerJobDescriptor, compute_effective_limits,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

static RUNTIME_TRANSITION: Mutex<()> = Mutex::const_new(());
static RUNNING_JOB: Mutex<Option<RunningJobHandle>> = Mutex::const_new(None);

mod recovery;
use recovery::*;
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeLeaseControlState {
    pub latest_seen_revision: u64,
    pub latest_seen_revision_digest: String,
    pub latest_applied_revision: u64,
    pub latest_applied_result: Option<JobControlAck>,
    #[serde(default)]
    last_successful: Option<ExecutionCheckpoint>,
    #[serde(default)]
    pending: Option<SignedJobControlRevision>,
}

struct RunningJobHandle {
    job_id: String,
    #[allow(dead_code)]
    lease_id: String,
    effective_limits: ResourceLimits,
    original_lease_limits: ResourceLimits,
    cmd_tx: mpsc::Sender<WorkerIpcMessage>,
    ack_waiters: Arc<Mutex<std::collections::HashMap<u64, oneshot::Sender<WorkerIpcMessage>>>>,
    boundary: Arc<Mutex<Option<OsResourceBoundary>>>,
    stop_tx: Option<oneshot::Sender<()>>,
    quiescing: Arc<std::sync::atomic::AtomicBool>,
    worker_done: oneshot::Receiver<()>,
}

pub(crate) fn validate_lease_id(lease_id: &str) -> Result<(), String> {
    if lease_id.is_empty()
        || lease_id.len() > 128
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("invalid lease identifier".into());
    }
    Ok(())
}

pub fn job_work_dir(config_path: &Path, lease_id: &str) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("jobs")
        .join(lease_id)
}

fn control_state_path(config_path: &Path, lease_id: &str) -> PathBuf {
    job_work_dir(config_path, lease_id).join("control_state.json")
}

fn find_worker_binary() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        let candidate = parent.join(if cfg!(windows) {
            "lattice-worker.exe"
        } else {
            "lattice-worker"
        });
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    #[cfg(test)]
    {
        let candidate =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/lattice-worker");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    // Relative targets from build
    for rel in &[
        "./target/debug/lattice-worker",
        "../target/debug/lattice-worker",
        "./target/release/lattice-worker",
    ] {
        let p = PathBuf::from(rel);
        if p.exists() {
            return Ok(p);
        }
    }

    Err("lattice-worker binary not found in installation or build directory".to_string())
}

pub(crate) async fn check_and_run(state: &Arc<AppState>) -> Result<(), String> {
    let Ok(_mutation) = state.workload_mutation.try_lock() else {
        return Ok(());
    };
    let lease = state.active_lease.read().await.clone();
    let Some(current) = lease else {
        return Ok(());
    };

    if current.pending_event.as_ref().is_some_and(|event| {
        matches!(
            event.state,
            JobState::Completed | JobState::Failed | JobState::Rejected | JobState::Expired
        )
    }) {
        suspend_active(state, "terminal_event_pending").await?;
        return Ok(());
    }
    let checkpoint = match load_control_state(
        &state.config_path,
        &current.lease.lease_id,
        current.control_state_required,
    )
    .await
    {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            suspend_active(state, "control_checkpoint_unavailable").await?;
            return Err(error);
        }
    };
    if checkpoint.pending.is_some() {
        suspend_active(state, "control_application_pending").await?;
        return Err("control checkpoint has an interrupted operation".into());
    }
    if let Some(execution) = &checkpoint.last_successful {
        if let Err(error) = validate_checkpoint(state, &current, execution).await {
            suspend_active(state, "control_checkpoint_binding_invalid").await?;
            return Err(error);
        }
        if execution.stopped {
            if current.pending_event.is_none()
                && !matches!(
                    current.state,
                    JobState::Completed | JobState::Failed | JobState::Rejected
                )
            {
                stop_active(state, "retained_control_stop").await?;
            } else {
                suspend_active(state, "retained_control_stop").await?;
            }
            return Ok(());
        }
        if execution.paused {
            suspend_active(state, "retained_execution_suspended").await?;
            return Ok(());
        }
    } else if checkpoint.latest_seen_revision > 0 {
        return Err(
            "legacy control checkpoint requires explicit cancellation and reassignment".into(),
        );
    }
    let now = unix_time_ms();
    if current.lease.expires_at_ms <= now || current.lease.offer.expires_at_ms <= now {
        crate::job::expire_local(state).await?;
        return Ok(());
    }
    let trust = state.identity.read().await.trust().cloned();
    if let Some(trust) = trust {
        if let Err(error) = crate::authorization::require(state, &trust).await {
            suspend_active(state, "execution_authority_unavailable").await?;
            return Err(error);
        }
    } else {
        suspend_active(state, "execution_authority_unavailable").await?;
        return Ok(());
    }
    // Continuously reconcile active workload against effective policy (CRIT-04)
    let local = state.config.read().await.policy.clone();
    let remote = state.remote_policy.read().await.clone();
    let effective = crate::policy::effective(&local, remote.as_ref());

    if matches!(
        current.state,
        JobState::Accepted | JobState::Preparing | JobState::Running
    ) {
        let recovered = recovered_execution(state, &current, &effective, None).await?;
        let mut effective_offer = current.lease.offer.clone();
        effective_offer.limits = recovered.limits;
        if !effective.enabled
            || !lattice_protocol::job_allowed_by_policy(&effective, &effective_offer)
        {
            suspend_active(state, "policy_revoked").await?;
            return Ok(());
        }

        // Check if effective limits ceiling tightened below current running limits
        let mut guard = RUNNING_JOB.lock().await;
        if let Some(handle) = guard.as_mut() {
            let max_cpu = effective
                .limits
                .cpu_percent
                .min(handle.original_lease_limits.cpu_percent);
            let max_mem = effective
                .limits
                .memory_mb
                .min(handle.original_lease_limits.memory_mb);
            let mut needs_tightening = false;
            let mut tighter_limits = handle.effective_limits.clone();
            if tighter_limits.cpu_percent > max_cpu {
                tighter_limits.cpu_percent = max_cpu;
                needs_tightening = true;
            }
            if tighter_limits.memory_mb > max_mem {
                tighter_limits.memory_mb = max_mem;
                needs_tightening = true;
            }
            if needs_tightening {
                let b_guard = handle.boundary.clone();
                let cmd_tx = handle.cmd_tx.clone();
                handle.effective_limits = tighter_limits.clone();
                drop(guard);

                let mut b = b_guard.lock().await;
                if let Some(boundary) = b.as_mut() {
                    let _ = boundary.update_limits(tighter_limits.clone());
                }
                drop(b);

                let _ = cmd_tx
                    .send(WorkerIpcMessage::ApplyControl {
                        revision_seq: 0,
                        action: lattice_protocol::JobControlAction::UpdateLimits,
                        limits: tighter_limits,
                        runtime_patch: None,
                    })
                    .await;
            } else {
                drop(guard);
            }
        } else {
            drop(guard);
        }
    }

    match current.state {
        JobState::Accepted | JobState::Preparing => {
            drop(_mutation);
            start_job(state, &current.lease.offer).await?;
        }
        JobState::Running => {
            let guard = RUNNING_JOB.lock().await;
            if guard.is_none() {
                drop(guard);
                drop(_mutation);
                start_job(state, &current.lease.offer).await?;
            }
        }
        JobState::Stopping => {
            stop_active(state, "cleaning up stopping job").await?;
        }
        _ => {}
    }

    Ok(())
}

pub(crate) async fn start_job(state: &Arc<AppState>, offer: &JobOffer) -> Result<(), String> {
    // Downloads do not hold the owner-policy mutation lock or the runtime transition lock.
    let content = crate::job::prepare_active_content(state)
        .await?
        .ok_or("content preparation failed")?;
    let _mutation = state.workload_mutation.lock().await;
    start_prepared_job(state, offer, content, None).await
}

async fn start_prepared_job(
    state: &Arc<AppState>,
    offer: &JobOffer,
    content: (PathBuf, PathBuf),
    resume: Option<&SignedJobControlRevision>,
) -> Result<(), String> {
    let _transition = RUNTIME_TRANSITION.lock().await;
    let guard = RUNNING_JOB.lock().await;
    if let Some(existing) = guard.as_ref() {
        let active = state.active_lease.read().await;
        if existing.job_id == offer.job_id
            && active
                .as_ref()
                .is_some_and(|a| a.lease.lease_id == existing.lease_id)
        {
            return Ok(());
        }
        return Err("another executor must be fully reaped before starting an assignment".into());
    }
    drop(guard);
    let (artifact_path, runtime_path) = content;

    let (platform, architecture) = {
        let identity = state.identity.read().await;
        (
            identity.identity().platform.clone(),
            identity.identity().architecture.clone(),
        )
    };

    let runtime_manifest = crate::runtimes::cached_offer_manifest(
        &state.runtime_cache_path,
        offer,
        &platform,
        &architecture,
    )
    .await?;

    let artifact_manifest =
        crate::artifacts::cached_offer_manifest(&state.artifact_cache_path, offer).await?;

    let lease_id = {
        let active = state.active_lease.read().await;
        active
            .as_ref()
            .map(|s| s.lease.lease_id.clone())
            .unwrap_or_else(|| offer.job_id.clone())
    };

    let (config_policy, remote_policy) = {
        let config = state.config.read().await;
        let remote = state.remote_policy.read().await;
        (config.policy.clone(), remote.clone())
    };
    let effective_policy = crate::policy::effective(&config_policy, remote_policy.as_ref());
    let retained = state
        .active_lease
        .read()
        .await
        .clone()
        .filter(|active| active.lease.offer.job_id == offer.job_id)
        .ok_or("assignment changed during runtime preparation")?;
    let restored = recovered_execution(state, &retained, &effective_policy, resume).await?;
    if restored.paused || restored.stopped {
        return Err("retained assignment is suspended".into());
    }
    let trust = state
        .identity
        .read()
        .await
        .trust()
        .cloned()
        .ok_or("execution authority unavailable")?;
    crate::authorization::require_scope(state, &trust, lattice_protocol::CommandScope::Content)
        .await?;
    let now = unix_time_ms();
    if retained.lease.expires_at_ms <= now
        || retained.lease.offer.expires_at_ms <= now
        || resume.is_some_and(|command| command.revision.expires_at_ms <= now)
    {
        return Err("execution or Resume command expired during preparation".into());
    }
    let mut effective_offer = offer.clone();
    effective_offer.limits = restored.limits.clone();
    if !effective_policy.enabled
        || !lattice_protocol::job_allowed_by_policy(&effective_policy, &effective_offer)
    {
        return Err("job exceeds current effective policy".into());
    }
    let effective_limits = restored.limits;

    let job_dir = job_work_dir(&state.config_path, &lease_id);
    tokio::fs::create_dir_all(&job_dir)
        .await
        .map_err(|e| e.to_string())?;
    secure_directory(&job_dir)?;

    let ipc_uuid = Uuid::new_v4().to_string();
    #[cfg(unix)]
    let endpoint = format!("/tmp/lat-work-{ipc_uuid}.sock");
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\lat-work-{ipc_uuid}");

    let auth_token = format!("{}-{}", Uuid::new_v4(), Uuid::new_v4());

    let descriptor = WorkerJobDescriptor {
        protocol_version: PROTOCOL_VERSION,
        job_id: offer.job_id.clone(),
        lease_id: lease_id.clone(),
        workload_kind: offer.workload_kind.clone(),
        runtime_id: offer.runtime.clone(),
        runtime_version: offer.runtime_version.clone(),
        runtime_path: runtime_path.to_string_lossy().to_string(),
        runtime_sha256: runtime_manifest.sha256.clone(),
        runtime_size: runtime_manifest.size_bytes,
        artifact_path: Some(artifact_path.to_string_lossy().to_string()),
        artifact_sha256: Some(artifact_manifest.sha256.clone()),
        artifact_size: Some(artifact_manifest.size_bytes),
        effective_limits: effective_limits.clone(),
        original_lease_limits: offer.limits.clone(),
        parameters: restored.parameters,
        work_dir: job_dir.to_string_lossy().to_string(),
        log_dir: job_dir.to_string_lossy().to_string(),
        ipc_socket_path: endpoint.clone(),
        ipc_auth_token: auth_token.clone(),
    };

    let descriptor_path = job_dir.join("descriptor.json");
    let desc_bytes = serde_json::to_vec_pretty(&descriptor).map_err(|e| e.to_string())?;
    tokio::fs::write(&descriptor_path, desc_bytes)
        .await
        .map_err(|e| e.to_string())?;
    secure_file(&descriptor_path)?;

    #[cfg(unix)]
    let listener = {
        let _ = tokio::fs::remove_file(&endpoint).await;
        let l = tokio::net::UnixListener::bind(&endpoint)
            .map_err(|e| format!("failed to bind local IPC socket: {e}"))?;
        secure_file(Path::new(&endpoint))?;
        l
    };

    #[cfg(windows)]
    let server = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&endpoint)
        .map_err(|e| format!("failed to create named pipe: {e}"))?;

    let worker_bin = find_worker_binary()?;
    let mut boundary = OsResourceBoundary::new(effective_limits.clone());

    let mut cmd = Command::new(&worker_bin);
    cmd.arg("--descriptor")
        .arg(&descriptor_path)
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("--job-id")
        .arg(&offer.job_id);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .env_clear();

    copy_allowed_environment(&mut cmd);
    boundary.prepare_command(&mut cmd);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn worker '{}': {e}", worker_bin.display()))?;
    let child_pid = child.id().unwrap_or(0);
    if let Err(error) = boundary.attach_process(child_pid) {
        let _ = boundary.terminate().await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(format!("failed to attach OS boundary: {error}"));
    }

    let startup = async {
        // Accept IPC connection with 6s timeout
        #[cfg(unix)]
        let stream = match tokio::time::timeout(Duration::from_secs(6), listener.accept()).await {
            Ok(Ok((s, _))) => s,
            _ => return Err("worker IPC connection timed out".to_string()),
        };

        #[cfg(windows)]
        let stream = match tokio::time::timeout(Duration::from_secs(6), server.connect()).await {
            Ok(Ok(())) => server,
            _ => return Err("worker IPC connection timed out".to_string()),
        };

        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);

        // Perform authenticated handshake (CRIT-16)
        let mut auth_line = String::new();
        reader
            .read_line(&mut auth_line)
            .await
            .map_err(|e| e.to_string())?;
        let auth_msg: WorkerIpcMessage =
            serde_json::from_str(&auth_line).map_err(|e| e.to_string())?;

        match auth_msg {
            WorkerIpcMessage::Auth { token, job_id } => {
                if token != auth_token || job_id != offer.job_id {
                    let reject = WorkerIpcMessage::AuthResult {
                        success: false,
                        error: Some("unauthorized_token_or_job".to_string()),
                    };
                    let mut b = serde_json::to_vec(&reject).map_err(|e| e.to_string())?;
                    b.push(b'\n');
                    let _ = write_half.write_all(&b).await;
                    return Err("worker authentication rejected".to_string());
                }
            }
            _ => return Err("worker failed to send auth handshake".to_string()),
        }

        let auth_ok = WorkerIpcMessage::AuthResult {
            success: true,
            error: None,
        };
        let mut b = serde_json::to_vec(&auth_ok).map_err(|e| e.to_string())?;
        b.push(b'\n');
        write_half.write_all(&b).await.map_err(|e| e.to_string())?;
        write_half.flush().await.map_err(|e| e.to_string())?;

        // Send Start command
        let start_msg = WorkerIpcMessage::Start;
        let mut b = serde_json::to_vec(&start_msg).map_err(|e| e.to_string())?;
        b.push(b'\n');
        write_half.write_all(&b).await.map_err(|e| e.to_string())?;
        write_half.flush().await.map_err(|e| e.to_string())?;

        // A successful authenticated IPC connection alone does not prove backend startup.
        let mut started = String::new();
        reader
            .read_line(&mut started)
            .await
            .map_err(|error| error.to_string())?;
        match serde_json::from_str::<WorkerIpcMessage>(&started)
            .map_err(|_| "invalid worker startup response")?
        {
            WorkerIpcMessage::StateChange {
                state: JobState::Running,
                ..
            } => {}
            WorkerIpcMessage::StateChange { detail, .. } => {
                return Err(detail.unwrap_or_else(|| "worker backend startup failed".into()));
            }
            _ => return Err("worker did not confirm backend startup".into()),
        }
        Ok((reader, write_half))
    };
    let (mut reader, mut write_half) =
        match tokio::time::timeout(Duration::from_secs(12), startup).await {
            Ok(Ok(io)) => io,
            failure => {
                let _ = boundary.terminate().await;
                let _ = child.kill().await;
                let _ = child.wait().await;
                #[cfg(unix)]
                let _ = tokio::fs::remove_file(&endpoint).await;
                let _ = tokio::fs::remove_file(&descriptor_path).await;
                return Err(match failure {
                    Ok(Err(error)) => error,
                    _ => "worker backend startup timed out".into(),
                });
            }
        };

    if let Err(error) =
        crate::authorization::require_scope(state, &trust, lattice_protocol::CommandScope::Content)
            .await
    {
        let _ = boundary.terminate().await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(error);
    }
    if unix_time_ms() >= retained.lease.expires_at_ms
        || unix_time_ms() >= retained.lease.offer.expires_at_ms
        || resume.is_some_and(|command| unix_time_ms() >= command.revision.expires_at_ms)
    {
        let _ = boundary.terminate().await;
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err("execution authorization expired during startup".into());
    }

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerIpcMessage>(16);
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let ack_waiters = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let ack_waiters_clone = ack_waiters.clone();
    let boundary_arc = Arc::new(Mutex::new(Some(boundary)));
    let quiescing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (worker_done_tx, worker_done) = oneshot::channel();

    let mut guard = RUNNING_JOB.lock().await;
    *guard = Some(RunningJobHandle {
        job_id: offer.job_id.clone(),
        lease_id: lease_id.clone(),
        effective_limits: effective_limits.clone(),
        original_lease_limits: offer.limits.clone(),
        cmd_tx,
        ack_waiters,
        boundary: boundary_arc.clone(),
        stop_tx: Some(stop_tx),
        quiescing: quiescing.clone(),
        worker_done,
    });
    drop(guard);

    let state_clone = state.clone();
    let (status_tx, mut status_rx) = mpsc::channel::<(JobState, Option<String>, Option<i32>)>(8);
    let report_state = state.clone();
    let report_lease = lease_id.clone();
    tokio::spawn(async move {
        while let Some((next, detail, exit_code)) = status_rx.recv().await {
            let _ = crate::job::report_status_for_lease(
                &report_state,
                &report_lease,
                next,
                detail,
                exit_code,
            )
            .await;
        }
    });
    let _ = status_tx.try_send((
        JobState::Running,
        Some("verified worker backend started".into()),
        None,
    ));

    // Event loop for worker IPC and child process supervision (CRIT-02, HIGH-17)
    tokio::spawn(async move {
        let mut child = child;
        let mut line = String::new();
        loop {
            tokio::select! {
                status_res = child.wait() => {
                    let exit_code = match status_res {
                        Ok(s) => s.code(),
                        Err(_) => None,
                    };
                    let current_lease = state_clone.active_lease.read().await.clone();
                    if !quiescing.load(std::sync::atomic::Ordering::SeqCst)
                        && let Some(c) = current_lease
                        && matches!(c.state, JobState::Running | JobState::Preparing)
                    {
                        let _ = status_tx.try_send((JobState::Failed, Some("worker_process_exited_unexpectedly".into()), exit_code));
                    }
                    break;
                }
                cmd_opt = cmd_rx.recv() => {
                    if let Some(cmd) = cmd_opt
                        && let Ok(mut payload) = serde_json::to_vec(&cmd)
                    {
                        payload.push(b'\n');
                        let _ = write_half.write_all(&payload).await;
                        let _ = write_half.flush().await;
                    }
                }
                _ = &mut stop_rx => {
                    let stop_cmd = WorkerIpcMessage::Stop { grace_ms: 1500 };
                    if let Ok(mut payload) = serde_json::to_vec(&stop_cmd) {
                        payload.push(b'\n');
                        let _ = write_half.write_all(&payload).await;
                        let _ = write_half.flush().await;
                    }
                    let _ = tokio::time::timeout(Duration::from_millis(1500), child.wait()).await;
                    let mut b_guard = boundary_arc.lock().await;
                    if let Some(mut b) = b_guard.take() {
                        let _ = b.terminate().await;
                    }
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    break;
                }
                res = reader.read_line(&mut line) => {
                    match res {
                        Ok(0) => {
                            let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
                            break;
                        }
                        Ok(_) => {
                            let trimmed = line.trim();
                            if !trimmed.is_empty()
                                && let Ok(event) = serde_json::from_str::<WorkerIpcMessage>(trimmed)
                            {
                                match event {
                                    WorkerIpcMessage::StateChange { state: new_state, detail, exit_code } => {
                                        if !quiescing.load(std::sync::atomic::Ordering::SeqCst) {
                                        let _ = status_tx.try_send((new_state, detail, exit_code));
                                        }
                                    }
                                    WorkerIpcMessage::ControlAck { revision_seq, .. } => {
                                        let mut waiters = ack_waiters_clone.lock().await;
                                        if let Some(tx) = waiters.remove(&revision_seq) {
                                            let _ = tx.send(event);
                                        }
                                    }
                                    WorkerIpcMessage::Telemetry(mining_telem) => {
                                        *state_clone.mining_telemetry.write().await = Some(mining_telem);
                                    }
                                    _ => {}
                                }
                            }
                            line.clear();
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        let mut b_guard = boundary_arc.lock().await;
        let _ = if let Some(mut b) = b_guard.take() {
            b.terminate().await
        } else {
            Ok(())
        };
        let _ = child.kill().await;
        let _ = child.wait().await;

        #[cfg(unix)]
        let _ = tokio::fs::remove_file(&endpoint).await;

        // Clean up sensitive files containing ephemeral secrets upon termination (HIGH-13)
        let _ = tokio::fs::remove_file(job_dir.join("descriptor.json")).await;
        let _ = tokio::fs::remove_file(job_dir.join("config.json")).await;

        let mut guard = RUNNING_JOB.lock().await;
        *guard = None;
        let _ = worker_done_tx.send(());
    });

    Ok(())
}

pub async fn apply_control(
    state: &Arc<AppState>,
    signed_rev: SignedJobControlRevision,
) -> Result<SignedJobControlAck, String> {
    let _mutation = state.workload_mutation.lock().await;
    let authority_trust = state
        .identity
        .read()
        .await
        .trust()
        .cloned()
        .ok_or("node is not enrolled")?;
    crate::authorization::require(state, &authority_trust).await?;
    if signed_rev.revision.action != lattice_protocol::JobControlAction::Stop {
        crate::authorization::require_scope(
            state,
            &authority_trust,
            lattice_protocol::CommandScope::ResourceControl,
        )
        .await?;
    }
    let trust = {
        let id_guard = state.identity.read().await;
        id_guard
            .trust()
            .cloned()
            .ok_or_else(|| "node not enrolled".to_string())?
    };

    // Verify control signature
    verify(
        &trust.control_public_key,
        &signed_rev.signature,
        &signed_rev.revision,
    )
    .map_err(|e| format!("invalid control revision signature: {e}"))?;

    let rev = &signed_rev.revision;
    if rev.protocol_version != PROTOCOL_VERSION {
        return Err(format!(
            "protocol_version_mismatch: revision protocol {} != node {}",
            rev.protocol_version, PROTOCOL_VERSION
        ));
    }
    let node_id = state.identity.read().await.identity().node_id.clone();
    if rev.node_id != node_id {
        return Err("revision node_id mismatch".to_string());
    }

    validate_lease_id(&rev.lease_id)?;
    if let Some(receipt) = replay_control_receipt(state, &signed_rev).await? {
        return Ok(receipt);
    }

    let active_lease = state.active_lease.read().await.clone();
    let Some(active) = active_lease else {
        return Err("no active lease on node".to_string());
    };

    if rev.lease_id != active.lease.lease_id || rev.job_id != active.lease.offer.job_id {
        return Err("revision lease_id or job_id mismatch".to_string());
    }

    if rev.action != lattice_protocol::JobControlAction::UpdateLimits
        && (rev.resource_patch.is_some() || rev.runtime_patch.is_some())
    {
        return Err("only UpdateLimits may contain execution patches".into());
    }
    if rev.runtime_patch.is_some()
        && active.lease.offer.workload_kind != lattice_protocol::WorkloadKind::Mining
    {
        return Err("Mining patch requires a Mining assignment".into());
    }
    let now = unix_time_ms();
    let stopping = rev.action == lattice_protocol::JobControlAction::Stop;
    if now >= rev.expires_at_ms
        || (!stopping
            && (rev.expires_at_ms > active.lease.expires_at_ms
                || active.lease.offer.expires_at_ms <= now))
    {
        return Err("control revision expired".to_string());
    }
    if stopping
        && (rev.resource_patch.is_some()
            || rev.runtime_patch.is_some()
            || rev.issued_at_ms > now.saturating_add(30_000)
            || rev.expires_at_ms <= rev.issued_at_ms
            || rev.expires_at_ms.saturating_sub(rev.issued_at_ms) > 60_000)
    {
        return Err("Stop requires a bounded fresh cancellation with no execution patches".into());
    }

    let revision_bytes = serde_json::to_vec(rev).map_err(|e| e.to_string())?;
    let rev_digest = sha256_hex(&revision_bytes);

    let mut control_state = load_control_state(
        &state.config_path,
        &rev.lease_id,
        active.control_state_required,
    )
    .await?;

    // Check replay and idempotency (CRIT-08, HIGH-02)
    if rev.revision < control_state.latest_seen_revision {
        return Err(format!(
            "stale_revision: incoming {} < latest {}",
            rev.revision, control_state.latest_seen_revision
        ));
    }

    if rev.revision == control_state.latest_seen_revision {
        if rev_digest == control_state.latest_seen_revision_digest {
            if let Some(prev_ack) = control_state.latest_applied_result {
                let priv_key = *state.identity.read().await.private_key();
                let sig = sign(&priv_key, &prev_ack)?;
                return Ok(SignedJobControlAck {
                    ack: prev_ack,
                    signature: sig,
                });
            }
        } else {
            return Err("conflict: revision payload changed under same sequence".to_string());
        }
    }

    // Clamp effective limits against original signed lease ceiling and current node policy (CRIT-11, CRIT-12)
    let (policy, remote) = {
        let cfg = state.config.read().await;
        let rem = state.remote_policy.read().await;
        (cfg.policy.clone(), rem.clone())
    };
    let effective_policy = crate::policy::effective(&policy, remote.as_ref());

    if let Some(checkpoint) = &control_state.last_successful {
        validate_checkpoint(state, &active, checkpoint).await?;
    } else if control_state.latest_seen_revision > 0
        && rev.action != lattice_protocol::JobControlAction::Stop
    {
        return Err(
            "legacy control checkpoint requires explicit cancellation and reassignment".into(),
        );
    }
    let mut guard = RUNNING_JOB.lock().await;
    if guard.is_none() || rev.action == lattice_protocol::JobControlAction::Stop {
        drop(guard);
        return apply_dormant_control(state, &active, signed_rev, control_state, &effective_policy)
            .await;
    }
    let handle = guard.as_mut().unwrap();

    let old_limits = handle.effective_limits.clone();
    let mut baseline = match control_state.last_successful.clone() {
        Some(checkpoint) => checkpoint,
        None => checkpoint_for(state, &active, &effective_policy).await?,
    };
    baseline.limits = old_limits.clone();
    control_state.last_successful = Some(baseline);
    control_state.latest_seen_revision = rev.revision;
    control_state.latest_seen_revision_digest = rev_digest.clone();
    control_state.latest_applied_result = None;
    control_state.pending = Some(signed_rev.clone());
    save_control_state(state, &rev.lease_id, &control_state).await?;
    let new_effective_limits = compute_effective_limits(
        &handle.effective_limits,
        &rev.resource_patch,
        &handle.original_lease_limits,
        &effective_policy,
    )?;

    // Update authoritative OS resource limits (CRIT-10)
    let mut b_guard = handle.boundary.lock().await;
    if let Some(boundary) = b_guard.as_mut() {
        boundary.update_limits(new_effective_limits.clone())?;
    }
    drop(b_guard);

    // Forward control to worker and wait for backend confirmation (CRIT-06, HIGH-04)
    let (ack_tx, ack_rx) = oneshot::channel();
    {
        let mut waiters = handle.ack_waiters.lock().await;
        waiters.insert(rev.revision, ack_tx);
    }

    let control_cmd = WorkerIpcMessage::ApplyControl {
        revision_seq: rev.revision,
        action: rev.action.clone(),
        limits: new_effective_limits.clone(),
        runtime_patch: rev.runtime_patch.clone(),
    };
    handle
        .cmd_tx
        .send(control_cmd)
        .await
        .map_err(|e| format!("failed to send control to worker: {e}"))?;

    drop(guard);

    // Wait up to 5s for worker/backend confirmation
    let ack_result = match tokio::time::timeout(Duration::from_secs(5), ack_rx).await {
        Ok(Ok(WorkerIpcMessage::ControlAck {
            revision_seq,
            applied,
            detail,
            effective_limits,
        })) if revision_seq == rev.revision => Ok((applied, detail, effective_limits)),
        _ => Err("worker timed out or failed to acknowledge control revision".to_string()),
    };

    let (mut applied, mut detail, final_limits) = match ack_result {
        Ok((applied, detail, limits)) => (applied, detail, limits),
        Err(err) => (false, Some(err), new_effective_limits.clone()),
    };

    // Re-check effective policy to prevent racing with concurrent policy updates (HIGH-20)
    let current_effective_policy = {
        let cfg = state.config.read().await;
        let rem = state.remote_policy.read().await;
        crate::policy::effective(&cfg.policy, rem.as_ref())
    };
    let mut controlled_offer = active.lease.offer.clone();
    controlled_offer.limits = final_limits.clone();
    let policy_allows = current_effective_policy.enabled
        && lattice_protocol::job_allowed_by_policy(&current_effective_policy, &controlled_offer)
        && final_limits.cpu_percent <= current_effective_policy.limits.cpu_percent
        && final_limits.memory_mb <= current_effective_policy.limits.memory_mb;

    if applied && final_limits != new_effective_limits {
        applied = false;
        detail = Some("rejected: worker limits do not match the enforced configuration".into());
    }
    if applied && !policy_allows {
        applied = false;
        detail = Some("rejected: concurrent policy tightening violates limits".to_string());
    }

    let mut guard = RUNNING_JOB.lock().await;
    if let Some(handle) = guard.as_mut() {
        if applied {
            handle.effective_limits = final_limits.clone();
        } else {
            // Rollback OS limits if worker failed, rejected, or policy tightened (HIGH-01, HIGH-20)
            let mut b_guard = handle.boundary.lock().await;
            if let Some(boundary) = b_guard.as_mut() {
                let _ = boundary.update_limits(old_limits.clone());
            }
        }
    }
    drop(guard);
    if !applied {
        suspend_active(state, "control_application_failed").await?;
        if let Some(checkpoint) = control_state.last_successful.as_mut() {
            checkpoint.paused = true;
        }
    }

    let ack_runtime_state = if applied {
        match rev.action {
            lattice_protocol::JobControlAction::Stop => JobState::Completed,
            lattice_protocol::JobControlAction::Pause
            | lattice_protocol::JobControlAction::Resume
            | lattice_protocol::JobControlAction::UpdateLimits => active.state.clone(),
        }
    } else {
        active.state.clone()
    };

    let ack = JobControlAck {
        protocol_version: PROTOCOL_VERSION,
        node_id: node_id.clone(),
        lease_id: rev.lease_id.clone(),
        job_id: rev.job_id.clone(),
        revision: rev.revision,
        applied,
        effective_limits: final_limits,
        runtime_state: ack_runtime_state,
        reason: detail,
        acknowledged_at_ms: unix_time_ms(),
    };

    // Update persisted control state for all processed revisions (HIGH-02)
    control_state.latest_seen_revision = rev.revision;
    control_state.latest_seen_revision_digest = rev_digest;
    if applied {
        control_state.latest_applied_revision = rev.revision;
    }
    control_state.latest_applied_result = Some(ack.clone());
    if applied {
        let mut execution = control_state
            .last_successful
            .clone()
            .unwrap_or(checkpoint_for(state, &active, &effective_policy).await?);
        execution.limits = ack.effective_limits.clone();
        execution.apply(rev);
        control_state.last_successful = Some(execution);
    }
    control_state.pending = None;
    save_control_state(state, &rev.lease_id, &control_state).await?;

    if rev.action == lattice_protocol::JobControlAction::Stop && applied {
        let _ = stop_active(state, "control_action_stop").await;
    }

    let priv_key = *state.identity.read().await.private_key();
    let signature = sign(&priv_key, &ack)?;

    Ok(SignedJobControlAck { ack, signature })
}

pub async fn stop_active(state: &Arc<AppState>, reason: &str) -> Result<(), String> {
    stop_runtime(state, reason, true).await
}
/// Stop execution while retaining its assignment, events and applied control state.
pub(crate) async fn suspend_active(state: &Arc<AppState>, reason: &str) -> Result<(), String> {
    stop_runtime(state, reason, false).await
}
async fn stop_runtime(state: &Arc<AppState>, reason: &str, terminal: bool) -> Result<(), String> {
    let _transition = RUNTIME_TRANSITION.lock().await;
    let mut cleanup_clean = true;
    let lease_id_opt = state
        .active_lease
        .read()
        .await
        .as_ref()
        .map(|a| a.lease.lease_id.clone());
    let handle = RUNNING_JOB.lock().await.take();
    if let Some(mut handle) = handle {
        handle
            .quiescing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(tx) = handle.stop_tx.take() {
            let _ = tx.send(());
        }
        {
            let mut boundary = handle.boundary.lock().await;
            if let Some(mut boundary) = boundary.take() {
                if let Err(error) = boundary.terminate().await {
                    eprintln!("[SUPERVISOR] boundary termination error: {error}");
                    cleanup_clean = false;
                }
            }
        }
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), handle.worker_done).await,
            Ok(Ok(()))
        ) {
            cleanup_clean = false;
        }
    }
    if let Some(lease_id) = &lease_id_opt {
        let job_dir = job_work_dir(&state.config_path, lease_id);
        let _ = tokio::fs::remove_file(job_dir.join("descriptor.json")).await;
        let _ = tokio::fs::remove_file(job_dir.join("config.json")).await;
    }
    if terminal {
        gc_stale_job_directories(&state.config_path, 10, lease_id_opt.as_deref()).await;
        let (status, detail) = if cleanup_clean {
            (JobState::Completed, reason.to_string())
        } else {
            (JobState::Failed, format!("cleanup_failed: {reason}"))
        };
        let _ = crate::job::report_status(state, status, Some(detail), Some(0)).await;
    }
    if cleanup_clean {
        Ok(())
    } else {
        Err("runtime cleanup incomplete; assignment and recovery state retained".into())
    }
}

async fn gc_stale_job_directories(
    config_path: &Path,
    keep_limit: usize,
    retained_lease: Option<&str>,
) {
    let jobs_root = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("jobs");
    let mut entries = match tokio::fs::read_dir(&jobs_root).await {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut dirs = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(meta) = entry.metadata().await
            && meta.is_dir()
        {
            let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            if retained_lease.is_none_or(|lease| entry.file_name() != lease) {
                dirs.push((entry.path(), modified));
            }
        }
    }
    dirs.sort_by(|a, b| b.1.cmp(&a.1));
    if dirs.len() > keep_limit {
        for (stale_dir, _) in dirs.into_iter().skip(keep_limit) {
            let _ = tokio::fs::remove_dir_all(&stale_dir).await;
        }
    }
}

fn copy_allowed_environment(command: &mut Command) {
    const KEYS: [&str; 10] = [
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
    ];

    for key in KEYS {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn secure_directory(path: &Path) -> Result<(), String> {
    // Restrict access on Windows so only SYSTEM and Administrators can access (HIGH-11)
    let _ = std::process::Command::new("icacls")
        .arg(path.as_os_str())
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)F")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn secure_file(path: &Path) -> Result<(), String> {
    // Restrict access on Windows so only SYSTEM and Administrators can access (HIGH-11)
    let _ = std::process::Command::new("icacls")
        .arg(path.as_os_str())
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(F)")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(F)")
        .output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod recovery_tests;

pub(crate) async fn retained_execution_paused(
    state: &AppState,
    active: &lattice_protocol::JobLeaseStatus,
) -> Result<bool, String> {
    if matches!(
        active.state,
        JobState::Completed | JobState::Failed | JobState::Rejected
    ) {
        return Ok(false);
    }
    let checkpoint = load_control_state(
        &state.config_path,
        &active.lease.lease_id,
        active.control_state_required,
    )
    .await?;
    if checkpoint.pending.is_some() {
        return Ok(true);
    }
    if let Some(execution) = &checkpoint.last_successful {
        validate_checkpoint(state, active, execution).await?;
        return Ok(execution.paused || execution.stopped);
    }
    if checkpoint.latest_seen_revision > 0 {
        return Err("legacy control checkpoint requires recovery".into());
    }
    Ok(false)
}
