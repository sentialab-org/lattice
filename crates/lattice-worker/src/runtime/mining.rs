#![allow(dead_code)]

use crate::process_supervisor::{ManagedProcess, ProcessSpec};
use crate::runtime::adapter::{AdapterTelemetry, ControlApplyResult};
use crate::runtime::context::RuntimeContext;
use lattice_protocol::{
    JobControlAction, JobControlPatch, MiningConfig, MiningTelemetry, ResourceLimits,
};
use serde_json::{Value, json};
use std::path::Path;
use std::process::ExitStatus;
use std::time::Duration;

pub struct MiningAdapter {
    config: Option<MiningConfig>,
    api_port: u16,
    api_token: String,
    http_client: reqwest::Client,
    process: Option<ManagedProcess>,
    spec: Option<ProcessSpec>,
    restart_count: u8,
    paused: bool,
}

impl MiningAdapter {
    pub fn new() -> Self {
        let token = uuid::Uuid::new_v4().to_string();
        Self {
            config: None,
            api_port: 0,
            api_token: token,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap_or_default(),
            process: None,
            spec: None,
            restart_count: 0,
            paused: false,
        }
    }

    pub fn name(&self) -> &'static str {
        "lattice-miner"
    }

    pub async fn prepare(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        // Enforce pre-execution content verification (CRIT-03)
        ctx.verify_content().await?;

        let runtime_path = ctx.runtime_path();
        prepare_executable(&runtime_path)?;

        // Parse typed mining config from parameters (HIGH-05, HIGH-06: fail closed if missing)
        let config = parse_mining_config_from_params(
            &ctx.descriptor.parameters,
            ctx.current_limits.cpu_percent,
        )?;

        let job_dir = &ctx.job_dir;
        tokio::fs::create_dir_all(job_dir)
            .await
            .map_err(|err| err.to_string())?;
        secure_directory(job_dir)?;

        let api_port = reserve_local_port().await?;
        self.api_port = api_port;

        let config_path = job_dir.join("config.json");
        write_xmrig_config(&config_path, &config, api_port, &self.api_token).await?;

        let spec = ProcessSpec {
            executable: runtime_path,
            args: vec![
                "--config".to_string(),
                config_path.to_string_lossy().to_string(),
                "--threads".to_string(),
                config.threads.to_string(),
                "--no-color".to_string(),
            ],
            current_dir: job_dir.clone(),
            stdout_path: ctx.log_dir.join("stdout.log"),
            stderr_path: ctx.log_dir.join("stderr.log"),
        };

        self.spec = Some(spec);
        self.config = Some(config);

        Ok(())
    }

    pub async fn start(&mut self, ctx: &RuntimeContext) -> Result<(), String> {
        // Re-verify immediately before spawning (CRIT-03)
        ctx.verify_content().await?;

        let spec = self
            .spec
            .as_ref()
            .ok_or_else(|| "mining adapter spec not initialized".to_string())?;

        let process = crate::process_supervisor::spawn(spec).await?;
        self.process = Some(process);
        Ok(())
    }

    pub async fn apply_control(
        &mut self,
        ctx: &mut RuntimeContext,
        _revision_seq: u64,
        action: &JobControlAction,
        limits: &ResourceLimits,
        patch: &Option<JobControlPatch>,
    ) -> Result<ControlApplyResult, String> {
        match action {
            JobControlAction::Pause => {
                if self.paused {
                    return Ok(ControlApplyResult::success(Some(
                        "already paused".to_string(),
                    )));
                }

                // Attempt loopback API pause
                let url = format!("http://127.0.0.1:{}/1/pause", self.api_port);
                let _ = self
                    .http_client
                    .post(url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .send()
                    .await;

                self.paused = true;
                Ok(ControlApplyResult::success(Some(
                    "mining paused".to_string(),
                )))
            }
            JobControlAction::Resume => {
                if !self.paused {
                    return Ok(ControlApplyResult::success(Some(
                        "already running".to_string(),
                    )));
                }

                let url = format!("http://127.0.0.1:{}/1/resume", self.api_port);
                let _ = self
                    .http_client
                    .post(url)
                    .header("Authorization", format!("Bearer {}", self.api_token))
                    .send()
                    .await;

                self.paused = false;
                Ok(ControlApplyResult::success(Some(
                    "mining resumed".to_string(),
                )))
            }
            JobControlAction::UpdateLimits => {
                ctx.current_limits = limits.clone();

                let mut needs_restart = false;
                if let Some(config) = &mut self.config
                    && let Some(JobControlPatch::Mining(mining_patch)) = patch
                {
                    if let Some(threads) = mining_patch.threads
                        && threads != config.threads
                    {
                        config.threads = threads;
                        needs_restart = true;
                    }
                    if let Some(pool) = &mining_patch.pool
                        && pool != &config.pool
                    {
                        config.pool = pool.clone();
                        needs_restart = true;
                    }
                }

                if needs_restart && let Some(config) = &self.config {
                    let config_path = ctx.job_dir.join("config.json");
                    write_xmrig_config(&config_path, config, self.api_port, &self.api_token)
                        .await?;

                    // Gracefully restart XMRig backend with new parameters
                    if let Some(proc) = self.process.take() {
                        let _ = proc.stop(Duration::from_millis(1500)).await;
                    }

                    if let Some(spec) = &mut self.spec {
                        spec.args = vec![
                            "--config".to_string(),
                            config_path.to_string_lossy().to_string(),
                            "--threads".to_string(),
                            config.threads.to_string(),
                            "--no-color".to_string(),
                        ];
                        let proc = crate::process_supervisor::spawn(spec).await?;
                        self.process = Some(proc);
                    }
                }

                Ok(ControlApplyResult::success(Some(
                    "limits applied to miner".to_string(),
                )))
            }
            JobControlAction::Stop => {
                if let Some(proc) = self.process.take() {
                    let _ = proc.stop(Duration::from_secs(5)).await;
                }
                Ok(ControlApplyResult::success(Some(
                    "mining stopped".to_string(),
                )))
            }
        }
    }

    pub async fn poll_status(&mut self) -> Result<Option<ExitStatus>, String> {
        let Some(proc) = &mut self.process else {
            return Ok(None);
        };

        match proc.try_wait()? {
            Some(status) => {
                if status.success() {
                    return Ok(Some(status));
                }

                let max_restarts = self.config.as_ref().map(|c| c.restart_limit).unwrap_or(3);
                if self.restart_count >= max_restarts {
                    return Ok(Some(status));
                }

                self.restart_count += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;

                if let Some(spec) = &self.spec {
                    let new_proc = crate::process_supervisor::spawn(spec).await?;
                    self.process = Some(new_proc);
                    return Ok(None);
                }

                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    pub async fn poll_telemetry(&mut self, ctx: &RuntimeContext) -> Option<AdapterTelemetry> {
        if self.api_port == 0 {
            return None;
        }

        let url = format!("http://127.0.0.1:{}/2/summary", self.api_port);
        let response = self
            .http_client
            .get(url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let val: Value = response.json().await.ok()?;
        let config = self.config.as_ref()?;

        let hashrate = val.pointer("/hashrate/total/0").and_then(Value::as_f64);
        let average_hashrate = val.pointer("/hashrate/total/1").and_then(Value::as_f64);
        let accepted = val
            .pointer("/connection/accepted")
            .and_then(Value::as_u64)
            .or_else(|| val.pointer("/results/shares_good").and_then(Value::as_u64))
            .unwrap_or(0);
        let rejected = val
            .pointer("/connection/rejected")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let uptime = val.get("uptime").and_then(Value::as_u64).unwrap_or(0);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(AdapterTelemetry::Mining(MiningTelemetry {
            job_id: ctx.job_id().to_string(),
            algorithm: config.algorithm.clone(),
            pool: config.pool.clone(),
            worker: config.worker.clone(),
            hashrate_hs: hashrate,
            average_hashrate_hs: average_hashrate,
            accepted_shares: accepted,
            rejected_shares: rejected,
            uptime_seconds: uptime,
            cpu_threads: config.threads,
            restart_count: self.restart_count,
            updated_at_ms: now_ms,
        }))
    }

    pub async fn stop(&mut self, grace: Duration) -> Result<(), String> {
        if let Some(proc) = self.process.take() {
            let _ = proc.stop(grace).await;
        }
        Ok(())
    }
}

fn parse_mining_config_from_params(
    params: &std::collections::BTreeMap<String, String>,
    cpu_percent: u8,
) -> Result<MiningConfig, String> {
    let algorithm = params
        .get("algorithm")
        .cloned()
        .ok_or_else(|| "missing required mining parameter: algorithm".to_string())?;
    let pool = params
        .get("pool")
        .cloned()
        .ok_or_else(|| "missing required mining parameter: pool".to_string())?;
    let wallet = params
        .get("wallet")
        .cloned()
        .ok_or_else(|| "missing required mining parameter: wallet".to_string())?;
    let worker = params
        .get("worker")
        .cloned()
        .unwrap_or_else(|| "lattice-worker".to_string());
    let password = params
        .get("password")
        .cloned()
        .unwrap_or_else(|| "x".to_string());

    let threads = if let Some(t_str) = params.get("threads") {
        t_str
            .parse::<u16>()
            .map_err(|_| "invalid threads parameter".to_string())?
    } else {
        let logical_cores = num_cpus();
        ((logical_cores * cpu_percent as usize) / 100).max(1) as u16
    };

    let huge_pages = params
        .get("huge_pages")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let tls = params
        .get("tls")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let keepalive = params
        .get("keepalive")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let donation_level = params
        .get("donation_level")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(0);
    let restart_limit = params
        .get("restart_limit")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(3);

    Ok(MiningConfig {
        algorithm,
        pool,
        wallet,
        worker,
        password,
        threads,
        huge_pages,
        tls,
        keepalive,
        donation_level,
        restart_limit,
    })
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

async fn write_xmrig_config(
    path: &Path,
    config: &MiningConfig,
    api_port: u16,
    api_token: &str,
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
            "access-token": api_token,
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

    let bytes = serde_json::to_vec_pretty(&value).map_err(|err| err.to_string())?;
    tokio::fs::write(path, bytes)
        .await
        .map_err(|err| err.to_string())?;
    secure_file(path)
}

async fn reserve_local_port() -> Result<u16, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| err.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| err.to_string())
}

#[cfg(unix)]
fn prepare_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|err| err.to_string())?;
    let mode = metadata.permissions().mode() | 0o500;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| err.to_string())
}

#[cfg(not(unix))]
fn prepare_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| err.to_string())
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| err.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}
