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

static RUNNING_JOB: Mutex<Option<RunningJobHandle>> = Mutex::const_new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLeaseControlState {
    pub latest_seen_revision: u64,
    pub latest_seen_revision_digest: String,
    pub latest_applied_revision: u64,
    pub latest_applied_result: Option<JobControlAck>,
}

struct RunningJobHandle {
    job_id: String,
    #[allow(dead_code)]
    lease_id: String,
    effective_limits: ResourceLimits,
    original_lease_limits: ResourceLimits,
    cmd_tx: mpsc::Sender<WorkerIpcMessage>,
    ack_waiter: Arc<Mutex<Option<oneshot::Sender<WorkerIpcMessage>>>>,
    boundary: Arc<Mutex<Option<OsResourceBoundary>>>,
    stop_tx: Option<oneshot::Sender<()>>,
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

async fn load_control_state(config_path: &Path, lease_id: &str) -> NodeLeaseControlState {
    let path = control_state_path(config_path, lease_id);
    if let Ok(content) = tokio::fs::read_to_string(&path).await
        && let Ok(state) = serde_json::from_str(&content)
    {
        return state;
    }
    NodeLeaseControlState {
        latest_seen_revision: 0,
        latest_seen_revision_digest: String::new(),
        latest_applied_revision: 0,
        latest_applied_result: None,
    }
}

async fn save_control_state(
    config_path: &Path,
    lease_id: &str,
    state: &NodeLeaseControlState,
) -> Result<(), String> {
    let path = control_state_path(config_path, lease_id);
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let content = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    tokio::fs::write(&path, content)
        .await
        .map_err(|e| e.to_string())?;
    secure_file(&path)?;
    Ok(())
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
    let lease = state.active_lease.read().await.clone();
    let Some(current) = lease else {
        return Ok(());
    };

    let now = unix_time_ms();
    if current.lease.expires_at_ms <= now || current.lease.offer.expires_at_ms <= now {
        crate::job::expire_local(state).await?;
        return Ok(());
    }

    match current.state {
        JobState::Accepted | JobState::Preparing => {
            start_job(state, &current.lease.offer).await?;
        }
        JobState::Running => {
            let guard = RUNNING_JOB.lock().await;
            if guard.is_none() {
                drop(guard);
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
    let guard = RUNNING_JOB.lock().await;
    if let Some(existing) = guard.as_ref()
        && existing.job_id == offer.job_id
    {
        return Ok(());
    }
    drop(guard);

    // Hard prerequisite: Content preparation must succeed before worker execution (CRIT-03)
    let content = crate::job::prepare_active_content(state).await?;
    let Some((artifact_path, runtime_path)) = content else {
        let _ = crate::job::report_status(
            state,
            JobState::Failed,
            Some("content preparation did not produce runtime content".to_string()),
            None,
        )
        .await;
        return Err("content preparation failed".to_string());
    };

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
    let effective_limits =
        compute_effective_limits(&offer.limits, &None, &offer.limits, &effective_policy)?;

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
        parameters: offer.parameters.clone(),
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
    let mut server = tokio::net::windows::named_pipe::ServerOptions::new()
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
        .arg("--token")
        .arg(&auth_token)
        .arg("--job-id")
        .arg(&offer.job_id);

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear();

    copy_allowed_environment(&mut cmd);
    boundary.prepare_command(&mut cmd);

    let child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn worker '{}': {e}", worker_bin.display()))?;
    let child_pid = child.id().unwrap_or(0);
    boundary
        .attach_process(child_pid)
        .map_err(|e| format!("failed to attach OS boundary: {e}"))?;

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
    let auth_msg: WorkerIpcMessage = serde_json::from_str(&auth_line).map_err(|e| e.to_string())?;

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

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerIpcMessage>(16);
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let ack_waiter = Arc::new(Mutex::new(None));
    let ack_waiter_clone = ack_waiter.clone();
    let boundary_arc = Arc::new(Mutex::new(Some(boundary)));

    let mut guard = RUNNING_JOB.lock().await;
    *guard = Some(RunningJobHandle {
        job_id: offer.job_id.clone(),
        lease_id: lease_id.clone(),
        effective_limits: effective_limits.clone(),
        original_lease_limits: offer.limits.clone(),
        cmd_tx,
        ack_waiter,
        boundary: boundary_arc.clone(),
        stop_tx: Some(stop_tx),
    });
    drop(guard);

    let state_clone = state.clone();

    // Event loop for worker IPC
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            tokio::select! {
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
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let mut b_guard = boundary_arc.lock().await;
                    if let Some(mut b) = b_guard.take() {
                        b.terminate().await;
                    }
                    break;
                }
                res = reader.read_line(&mut line) => {
                    match res {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim();
                            if !trimmed.is_empty()
                                && let Ok(event) = serde_json::from_str::<WorkerIpcMessage>(trimmed)
                            {
                                match event {
                                    WorkerIpcMessage::StateChange { state: new_state, detail, exit_code } => {
                                        let _ = crate::job::report_status(
                                            &state_clone,
                                            new_state,
                                            detail,
                                            exit_code,
                                        ).await;
                                    }
                                    WorkerIpcMessage::ControlAck { .. } => {
                                        let mut waiter = ack_waiter_clone.lock().await;
                                        if let Some(tx) = waiter.take() {
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
        if let Some(mut b) = b_guard.take() {
            b.terminate().await;
        }
        let mut guard = RUNNING_JOB.lock().await;
        *guard = None;
    });

    Ok(())
}

pub async fn apply_control(
    state: &Arc<AppState>,
    signed_rev: SignedJobControlRevision,
) -> Result<SignedJobControlAck, String> {
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
    let node_id = state.identity.read().await.identity().node_id.clone();
    if rev.node_id != node_id {
        return Err("revision node_id mismatch".to_string());
    }

    let active_lease = state.active_lease.read().await.clone();
    let Some(active) = active_lease else {
        return Err("no active lease on node".to_string());
    };

    if rev.lease_id != active.lease.lease_id || rev.job_id != active.lease.offer.job_id {
        return Err("revision lease_id or job_id mismatch".to_string());
    }

    let now = unix_time_ms();
    if now > rev.expires_at_ms || rev.expires_at_ms > active.lease.expires_at_ms {
        return Err("control revision expired".to_string());
    }

    let revision_bytes = serde_json::to_vec(rev).map_err(|e| e.to_string())?;
    let rev_digest = sha256_hex(&revision_bytes);

    let mut control_state = load_control_state(&state.config_path, &rev.lease_id).await;

    // Check replay and idempotency (CRIT-08)
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

    let mut guard = RUNNING_JOB.lock().await;
    let Some(handle) = guard.as_mut() else {
        return Err("no running workload to apply control to".to_string());
    };

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

    // Forward control to worker and wait for backend confirmation (CRIT-06, HIGH-11)
    let (ack_tx, ack_rx) = oneshot::channel();
    {
        let mut waiter = handle.ack_waiter.lock().await;
        *waiter = Some(ack_tx);
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

    let (applied, detail, final_limits) = match ack_result {
        Ok((applied, detail, limits)) => (applied, detail, limits),
        Err(err) => (false, Some(err), new_effective_limits),
    };

    let mut guard = RUNNING_JOB.lock().await;
    if let Some(handle) = guard.as_mut()
        && applied
    {
        handle.effective_limits = final_limits.clone();
    }
    drop(guard);

    let ack = JobControlAck {
        protocol_version: PROTOCOL_VERSION,
        node_id: node_id.clone(),
        lease_id: rev.lease_id.clone(),
        job_id: rev.job_id.clone(),
        revision: rev.revision,
        applied,
        effective_limits: final_limits,
        runtime_state: active.state,
        reason: detail,
        acknowledged_at_ms: unix_time_ms(),
    };

    // Update persisted control state (CRIT-08)
    control_state.latest_seen_revision = rev.revision;
    control_state.latest_seen_revision_digest = rev_digest;
    if applied {
        control_state.latest_applied_revision = rev.revision;
        control_state.latest_applied_result = Some(ack.clone());
    }
    save_control_state(&state.config_path, &rev.lease_id, &control_state).await?;

    let priv_key = *state.identity.read().await.private_key();
    let signature = sign(&priv_key, &ack)?;

    Ok(SignedJobControlAck { ack, signature })
}

pub async fn stop_active(state: &Arc<AppState>, reason: &str) -> Result<(), String> {
    let mut guard = RUNNING_JOB.lock().await;
    if let Some(mut handle) = guard.take() {
        if let Some(tx) = handle.stop_tx.take() {
            let _ = tx.send(());
        }
        let mut b_guard = handle.boundary.lock().await;
        if let Some(mut b) = b_guard.take() {
            b.terminate().await;
        }
    }
    let _ =
        crate::job::report_status(state, JobState::Completed, Some(reason.to_string()), None).await;
    Ok(())
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

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), String> {
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
