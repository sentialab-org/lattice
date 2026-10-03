use crate::AppState;
use crate::identity::unix_time_ms;
use crate::process_supervisor::{ManagedProcess, ProcessSpec, managed_path};
use lattice_protocol::{
    JobOffer, JobState, MiningConfig, MiningTelemetry, WorkloadKind, job_allowed_by_policy,
    mining_config_from_offer,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);
const STOP_GRACE: Duration = Duration::from_secs(8);

pub async fn run(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }

        let candidate = state
            .active_lease
            .read()
            .await
            .as_ref()
            .filter(|status| {
                status.lease.offer.workload_kind == WorkloadKind::Mining
                    && matches!(
                        status.state,
                        JobState::Accepted | JobState::Preparing | JobState::Running
                    )
            })
            .map(|status| status.lease.lease_id.clone());

        if let Some(lease_id) = candidate {
            let _ = execute(&state, &lease_id, shutdown.clone()).await;
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

pub async fn validate_offer(
    state: &Arc<AppState>,
    offer: &JobOffer,
) -> Result<MiningConfig, String> {
    let config = mining_config_from_offer(offer)?;
    if offer.limits.cpu_percent == 0 {
        return Err("mining workload CPU limit must be greater than zero".to_string());
    }
    if offer.limits.gpu_percent.is_some() || offer.limits.gpu_memory_mb.is_some() {
        return Err("xmrig mining workload is CPU-only in the current runtime".to_string());
    }

    let hardware = crate::hardware_snapshot(state).await;
    let maximum_threads =
        (hardware.cpu.logical_cores.saturating_mul(offer.limits.cpu_percent as usize) / 100)
            .max(1);
    if config.threads as usize > maximum_threads {
        return Err(format!(
            "mining thread count {} exceeds CPU limit of {} threads",
            config.threads, maximum_threads
        ));
    }

    Ok(config)
}

async fn execute(
    state: &Arc<AppState>,
    lease_id: &str,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), String> {
    let (offer, initial_state) = {
        let active = state.active_lease.read().await;
        let status = active
            .as_ref()
            .filter(|status| status.lease.lease_id == lease_id)
            .ok_or_else(|| "mining lease is no longer active".to_string())?;
        (status.lease.offer.clone(), status.state.clone())
    };

    let config = match validate_offer(state, &offer).await {
        Ok(config) => config,
        Err(error) => {
            let _ = crate::job::report_status(
                state,
                JobState::Failed,
                Some(format!("mining_config_invalid:{error}")),
                None,
            )
            .await;
            return Err(error);
        }
    };

    if initial_state == JobState::Accepted {
        crate::job::report_status(
            state,
            JobState::Preparing,
            Some("preparing verified XMRig runtime".to_string()),
            None,
        )
        .await?;
    }

    let Some((_artifact_path, runtime_path)) = crate::job::prepare_active_content(state).await?
    else {
        return Err("mining content preparation did not produce runtime content".to_string());
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
        &offer,
        &platform,
        &architecture,
    )
    .await?;

    verify_runtime(&runtime_path, &runtime_manifest.sha256, runtime_manifest.size_bytes).await?;
    prepare_executable(&runtime_path)?;

    let root = state
        .config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("jobs");
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(|error| error.to_string())?;
    let job_dir = managed_path(&root, lease_id)?;
    tokio::fs::create_dir_all(&job_dir)
        .await
        .map_err(|error| error.to_string())?;
    secure_directory(&job_dir)?;

    let api_port = reserve_local_port().await?;
    let config_path = job_dir.join("config.json");
    write_xmrig_config(&config_path, &config, api_port).await?;

    let spec = ProcessSpec {
        executable: runtime_path.clone(),
        args: vec![
            "--config".to_string(),
            config_path.to_string_lossy().to_string(),
            "--threads".to_string(),
            config.threads.to_string(),
            "--no-color".to_string(),
        ],
        current_dir: job_dir.clone(),
        stdout_path: job_dir.join("stdout.log"),
        stderr_path: job_dir.join("stderr.log"),
    };

    let mut restart_count = 0u8;
    let mut process = spawn_verified(&spec, &runtime_manifest.sha256, runtime_manifest.size_bytes)
        .await
        .map_err(|error| format!("xmrig_spawn_failed:{error}"))?;

    if initial_state != JobState::Running {
        if let Err(error) = crate::job::report_status(
            state,
            JobState::Running,
            Some(format!("XMRig started with {} CPU threads", config.threads)),
            None,
        )
        .await
        {
            let _ = process.stop(STOP_GRACE).await;
            return Err(error);
        }
    }

    update_telemetry(
        state,
        &offer,
        &config,
        restart_count,
        MiningTelemetry {
            job_id: offer.job_id.clone(),
            algorithm: config.algorithm.clone(),
            pool: config.pool.clone(),
            worker: config.worker.clone(),
            hashrate_hs: None,
            average_hashrate_hs: None,
            accepted_shares: 0,
            rejected_shares: 0,
            uptime_seconds: 0,
            cpu_threads: config.threads,
            restart_count,
            updated_at_ms: unix_time_ms(),
        },
    )
    .await;

    let mut last_telemetry = tokio::time::Instant::now() - TELEMETRY_INTERVAL;

    loop {
        if let Some(status) = process.try_wait()? {
            let exit_code = status.code();
            let _ = process.finish().await;

            if status.success() {
                let _ = crate::job::report_status(
                    state,
                    JobState::Completed,
                    Some("XMRig exited successfully".to_string()),
                    exit_code,
                )
                .await;
                return Ok(());
            }

            if restart_count >= config.restart_limit {
                let _ = crate::job::report_status(
                    state,
                    JobState::Failed,
                    Some(format!(
                        "xmrig_crash_restart_limit_exhausted:{restart_count}/{}",
                        config.restart_limit
                    )),
                    exit_code,
                )
                .await;
                return Err("XMRig crash restart limit exhausted".to_string());
            }

            restart_count = restart_count.saturating_add(1);
            let backoff = Duration::from_secs(1u64 << restart_count.saturating_sub(1).min(3));
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }

            if stop_reason(state, lease_id, &offer).await.is_some() {
                return Ok(());
            }

            process = spawn_verified(
                &spec,
                &runtime_manifest.sha256,
                runtime_manifest.size_bytes,
            )
            .await
            .map_err(|error| format!("xmrig_restart_failed:{error}"))?;

            if let Some(mut telemetry) = state.mining_telemetry.read().await.clone() {
                telemetry.restart_count = restart_count;
                telemetry.updated_at_ms = unix_time_ms();
                *state.mining_telemetry.write().await = Some(telemetry);
            }
            continue;
        }

        if *shutdown.borrow() {
            stop_running(state, process, "node shutdown").await;
            return Ok(());
        }

        if let Some(reason) = stop_reason(state, lease_id, &offer).await {
            stop_running(state, process, &reason).await;
            return Ok(());
        }

        if last_telemetry.elapsed() >= TELEMETRY_INTERVAL {
            if let Ok(telemetry) =
                fetch_telemetry(state, &offer, &config, api_port, restart_count).await
            {
                update_telemetry(state, &offer, &config, restart_count, telemetry).await;
            }
            last_telemetry = tokio::time::Instant::now();
        }

        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    stop_running(state, process, "node shutdown").await;
                    return Ok(());
                }
            }
        }
    }
}

async fn spawn_verified(
    spec: &ProcessSpec,
    sha256: &str,
    size_bytes: u64,
) -> Result<ManagedProcess, String> {
    verify_runtime(&spec.executable, sha256, size_bytes).await?;
    crate::process_supervisor::spawn(spec).await
}

async fn stop_running(state: &Arc<AppState>, process: ManagedProcess, reason: &str) {
    let current = state
        .active_lease
        .read()
        .await
        .as_ref()
        .map(|status| status.state.clone());

    if matches!(current, Some(JobState::Running | JobState::Preparing)) {
        let _ = crate::job::report_status(
            state,
            JobState::Stopping,
            Some(reason.to_string()),
            None,
        )
        .await;
    }

    let status = process.stop(STOP_GRACE).await.ok();
    let exit_code = status.and_then(|status| status.code());
    let _ = crate::job::report_status(
        state,
        JobState::Completed,
        Some(format!("XMRig stopped: {reason}")),
        exit_code,
    )
    .await;
}

async fn stop_reason(state: &Arc<AppState>, lease_id: &str, offer: &JobOffer) -> Option<String> {
    let status = state.active_lease.read().await.clone();
    let Some(status) = status else {
        return Some("lease removed".to_string());
    };
    if status.lease.lease_id != lease_id {
        return Some("lease replaced".to_string());
    }
    if !matches!(status.state, JobState::Running | JobState::Preparing) {
        return Some("job state changed".to_string());
    }
    if status.lease.expires_at_ms <= unix_time_ms() || offer.expires_at_ms <= unix_time_ms() {
        return Some("lease expired".to_string());
    }

    let local = state.config.read().await.policy.clone();
    let remote = state.remote_policy.read().await.clone();
    let effective = crate::policy::effective(&local, remote.as_ref());
    if !job_allowed_by_policy(&effective, offer) {
        return Some("effective policy revoked mining permission".to_string());
    }

    None
}

async fn write_xmrig_config(
    path: &Path,
    config: &MiningConfig,
    api_port: u16,
) -> Result<(), String> {
    let value = json!({
        "autosave": false,
        "background": false,
        "colors": false,
        "title": false,
        "watch": false,
        "donate-level": config.donation_level,
        "print-time": 10,
        "health-print-time": 30,
        "api": {
            "id": null,
            "worker-id": config.worker
        },
        "http": {
            "enabled": true,
            "host": "127.0.0.1",
            "port": api_port,
            "access-token": null,
            "restricted": true
        },
        "cpu": {
            "enabled": true,
            "huge-pages": config.huge_pages
        },
        "opencl": false,
        "cuda": false,
        "pools": [{
            "algo": config.algorithm,
            "url": config.pool,
            "user": config.wallet,
            "pass": config.password,
            "rig-id": config.worker,
            "keepalive": config.keepalive,
            "tls": config.tls,
            "enabled": true
        }]
    });
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    tokio::fs::write(path, bytes)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
}

async fn reserve_local_port() -> Result<u16, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

async fn fetch_telemetry(
    state: &Arc<AppState>,
    offer: &JobOffer,
    config: &MiningConfig,
    api_port: u16,
    restart_count: u8,
) -> Result<MiningTelemetry, String> {
    let response = state
        .http
        .get(format!("http://127.0.0.1:{api_port}/2/summary"))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("XMRig API returned HTTP {}", response.status()));
    }

    let value: Value = response.json().await.map_err(|error| error.to_string())?;
    let hashrate = value
        .pointer("/hashrate/total/0")
        .and_then(Value::as_f64);
    let average_hashrate = value
        .pointer("/hashrate/total/1")
        .and_then(Value::as_f64);
    let accepted = value
        .pointer("/connection/accepted")
        .and_then(Value::as_u64)
        .or_else(|| value.pointer("/results/shares_good").and_then(Value::as_u64))
        .unwrap_or(0);
    let rejected = value
        .pointer("/connection/rejected")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            value
                .pointer("/results/shares_total")
                .and_then(Value::as_u64)
                .unwrap_or(accepted)
                .saturating_sub(accepted)
        });

    Ok(MiningTelemetry {
        job_id: offer.job_id.clone(),
        algorithm: config.algorithm.clone(),
        pool: config.pool.clone(),
        worker: config.worker.clone(),
        hashrate_hs: hashrate,
        average_hashrate_hs: average_hashrate,
        accepted_shares: accepted,
        rejected_shares: rejected,
        uptime_seconds: value.get("uptime").and_then(Value::as_u64).unwrap_or(0),
        cpu_threads: config.threads,
        restart_count,
        updated_at_ms: unix_time_ms(),
    })
}

async fn update_telemetry(
    state: &Arc<AppState>,
    _offer: &JobOffer,
    _config: &MiningConfig,
    _restart_count: u8,
    telemetry: MiningTelemetry,
) {
    *state.mining_telemetry.write().await = Some(telemetry);
}

async fn verify_runtime(path: &Path, expected_sha256: &str, expected_size: u64) -> Result<(), String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| error.to_string())?;
    if metadata.len() != expected_size {
        return Err(format!(
            "runtime size mismatch before spawn: expected {expected_size}, got {}",
            metadata.len()
        ));
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected_sha256 {
        return Err("runtime SHA-256 mismatch immediately before spawn".to_string());
    }

    Ok(())
}

#[cfg(unix)]
fn prepare_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    let mode = metadata.permissions().mode() | 0o500;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn prepare_executable(_path: &Path) -> Result<(), String> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::{ResourceLimits, WorkloadKind};
    use std::collections::BTreeMap;

    fn mining_offer(cpu_percent: u8, threads: &str) -> JobOffer {
        let mut parameters = BTreeMap::new();
        parameters.insert("algorithm".to_string(), "rx/0".to_string());
        parameters.insert("pool".to_string(), "pool.example.test:443".to_string());
        parameters.insert("wallet".to_string(), "wallet".to_string());
        parameters.insert("worker".to_string(), "worker-1".to_string());
        parameters.insert("threads".to_string(), threads.to_string());

        JobOffer {
            job_id: "job-mining".to_string(),
            workload_kind: WorkloadKind::Mining,
            runtime: "xmrig".to_string(),
            runtime_version: "6.0.0".to_string(),
            artifact_id: "mining-profile".to_string(),
            artifact_version: "1".to_string(),
            limits: ResourceLimits {
                cpu_percent,
                memory_mb: 4096,
                gpu_percent: None,
                gpu_memory_mb: None,
            },
            parameters,
            expires_at_ms: u64::MAX,
        }
    }

    #[test]
    fn mining_offer_parser_rejects_arbitrary_arguments() {
        let mut offer = mining_offer(50, "4");
        assert!(mining_config_from_offer(&offer).is_ok());
        offer
            .parameters
            .insert("command".to_string(), "cmd.exe /c whoami".to_string());
        assert!(mining_config_from_offer(&offer).is_err());
    }
}
