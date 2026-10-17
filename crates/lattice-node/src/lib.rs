pub mod artifacts;
mod authorization;
pub mod bundle;
mod content_cache;
mod enrollment;
mod heartbeat;
mod identity;
mod job;
pub(crate) mod mining;
mod modules;
pub mod network;
mod network_manager;
mod policy;
mod process_supervisor;
pub mod resource_containment;
pub mod runtimes;
pub mod setup;
pub mod setup_cli;
pub(crate) mod supervisor;
mod trust_store;
mod updates;
pub mod verification;

use identity::{IdentityState, identity_path};
use lattice_protocol::{
    CpuInfo, GpuInfo, HardwareSnapshot, IpcRequest, IpcResponse, JobLeaseStatus, MemoryInfo,
    MiningTelemetry, NetworkStatusSummary, NodeConfig, NodeRuntimeState, NodeStatus,
    PolicySnapshot, UpdateState, UpdateStatus,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use sysinfo::System;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock, watch};

pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) struct AppState {
    workload_mutation: Mutex<()>,
    workload_authority: RwLock<Option<lattice_protocol::DiscoveryResponse>>,
    offline_authority: Mutex<trust_store::TrustStore>,
    modules: Mutex<modules::ModuleManager>,
    setup: Mutex<setup::SetupRuntime>,
    config: RwLock<NodeConfig>,
    config_path: PathBuf,
    identity: RwLock<IdentityState>,
    remote_policy: RwLock<Option<PolicySnapshot>>,
    remote_policy_path: PathBuf,
    active_lease: RwLock<Option<JobLeaseStatus>>,
    active_lease_path: PathBuf,
    mining_telemetry: RwLock<Option<MiningTelemetry>>,
    artifact_cache_path: PathBuf,
    runtime_cache_path: PathBuf,
    update_status: RwLock<UpdateStatus>,
    update_state_path: PathBuf,
    update_downloaded_bytes: AtomicU64,
    network_status: RwLock<NetworkStatusSummary>,
    network_manager: Mutex<network_manager::NetworkManager>,
    network_journal_path: PathBuf,
    network_key_path: PathBuf,
    network_peers_path: PathBuf,
    system: Mutex<System>,
    http: reqwest::Client,
    content_http: reqwest::Client,
    control_connected: AtomicBool,
}

async fn load_state_at(config_path: PathBuf) -> Result<Arc<AppState>, NodeError> {
    let mut config = load_config(&config_path).await.unwrap_or_default();
    let identity = IdentityState::load_or_create(identity_path(&config_path)).await?;

    if let Some(trust) = identity.trust() {
        config.control_url = Some(trust.control_url.clone());
    }

    if let Some(bootstrap) = identity.bootstrap() {
        config.bootstrap_url = Some(bootstrap.bootstrap_url.clone());
    }

    let remote_policy_path = policy::remote_policy_path(&config_path);
    let remote_policy = if identity.trust().is_some() {
        policy::load(&remote_policy_path).await.unwrap_or(None)
    } else {
        None
    };
    let active_lease_path = job::active_lease_path(&config_path);
    let active_lease = job::load(&active_lease_path).await.unwrap_or(None);
    let artifact_cache_path = artifacts::cache_index_path(&config_path);
    let runtime_cache_path = runtimes::cache_index_path(&config_path);
    let update_state_path = updates::state_path(&config_path);
    let update_status = updates::load(
        &update_state_path,
        env!("CARGO_PKG_VERSION"),
        config.release_channel.clone(),
    )
    .await
    .unwrap_or_else(|_| {
        updates::default_status(env!("CARGO_PKG_VERSION"), config.release_channel.clone())
    });
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("lattice-node/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let artifact_timeout = std::env::var("LATTICE_CONTENT_TIMEOUT_SECS")
        .or_else(|_| std::env::var("LATTICE_ARTIFACT_TIMEOUT_SECS"))
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120)
        .clamp(10, 1800);
    let content_http = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(artifact_timeout))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!(
            "lattice-node/{}/artifact",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let network_key_path = network::wireguard_key_path(&config_path);
    let network_journal_path = network::network_journal_path(&config_path);
    let network_peers_path = network::network_peers_path(&config_path);
    let network_journal = network::load_journal(&network_journal_path).await;
    let peers_cache = network::load_peers_cache(&network_peers_path).await;
    let initial_network_status = NetworkStatusSummary {
        enabled: config.network.enabled,
        status: if identity.trust().is_none() {
            lattice_protocol::NetworkNodeStatus::Unconfigured
        } else if !config.network.enabled {
            lattice_protocol::NetworkNodeStatus::Disabled
        } else if network_journal.last_applied_revision > 0 {
            lattice_protocol::NetworkNodeStatus::Connected
        } else {
            lattice_protocol::NetworkNodeStatus::PendingApproval
        },
        virtual_ipv4: network_journal.virtual_ipv4.clone(),
        assigned_revision: network_journal.last_applied_revision,
        applied_revision: network_journal.last_applied_revision,
        last_handshake_ms: None,
        bytes_rx: 0,
        bytes_tx: 0,
        last_error: network_journal.last_error.clone(),
        peer_count: peers_cache.peers.len() as u64,
        path_policy: peers_cache.path_policy.clone(),
        error_code: None,
        interface_name: None,
        gateway_endpoint: network_journal.gateway_endpoint.clone(),
    };

    let manager = network_manager::NetworkManager::load(&config_path, &identity);
    let state = Arc::new(AppState {
        workload_mutation: Mutex::new(()),
        workload_authority: RwLock::new(authorization::load(&config_path)),
        offline_authority: Mutex::new(trust_store::TrustStore::load(&config_path, &identity)),
        modules: Mutex::new(
            modules::ModuleManager::load(&config_path.with_file_name("modules.json"))
                .unwrap_or_else(modules::ModuleManager::damaged),
        ),
        setup: Mutex::new(setup::SetupRuntime::load(
            &config_path.with_file_name("setup.json"),
        )),
        config: RwLock::new(config),
        config_path,
        identity: RwLock::new(identity),
        remote_policy: RwLock::new(remote_policy),
        remote_policy_path,
        active_lease: RwLock::new(active_lease),
        active_lease_path,
        mining_telemetry: RwLock::new(None),
        artifact_cache_path,
        runtime_cache_path,
        update_downloaded_bytes: AtomicU64::new(update_status.downloaded_bytes),
        update_status: RwLock::new(update_status),
        update_state_path,
        network_status: RwLock::new(initial_network_status),
        network_manager: Mutex::new(manager),
        network_journal_path,
        network_key_path,
        network_peers_path,
        system: Mutex::new(System::new_all()),
        http,
        content_http,
        control_connected: AtomicBool::new(false),
    });

    Ok(state)
}

pub async fn run_node(shutdown: watch::Receiver<bool>) -> Result<(), NodeError> {
    let _network_owner = network_manager::acquire_host()?;
    #[cfg(unix)]
    network_manager::check_ipc_path().await?;
    let state = load_state_at(config_path()).await?;

    tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
    let setup_task = tokio::spawn(setup::run(state.clone(), shutdown.clone()));
    let (module_shutdown, module_rx) = watch::channel(false);
    let mut module_task = tokio::spawn(modules::run(state.clone(), module_rx.clone()));
    let mut ingress_task = tokio::spawn(modules::ingress::run(state.clone(), module_rx));
    let heartbeat_state = state.clone();
    let heartbeat_shutdown = shutdown.clone();
    let heartbeat_task = tokio::spawn(async move {
        heartbeat::run(heartbeat_state, heartbeat_shutdown).await;
    });
    let update_state = state.clone();
    let update_shutdown = shutdown.clone();
    let update_task = tokio::spawn(async move {
        updates::run(update_state, update_shutdown).await;
    });
    let network_state = state.clone();
    let network_shutdown = shutdown.clone();
    let network_task = tokio::spawn(async move {
        network::run(network_state, network_shutdown).await;
    });
    let supervisor_state = state.clone();
    let mut supervisor_shutdown = shutdown.clone();
    let mut supervisor_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = supervisor::check_and_run(&supervisor_state).await;
                }
                res = supervisor_shutdown.changed() => {
                    if res.is_err() || *supervisor_shutdown.borrow() {
                        let _ = supervisor::stop_active(&supervisor_state, "node shutdown").await;
                        break;
                    }
                }
            }
        }
    });
    let result = serve(state, shutdown).await;
    let _ = module_shutdown.send(true);
    setup_task.abort();
    heartbeat_task.abort();
    update_task.abort();
    network_task.abort();
    let _ = network_task.await;
    let _ = tokio::time::timeout(Duration::from_secs(12), &mut supervisor_task).await;
    supervisor_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(12), &mut module_task).await;
    module_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut ingress_task).await;
    ingress_task.abort();
    result
}

pub fn config_path() -> PathBuf {
    if let Ok(path) = std::env::var("LATTICE_CONFIG") {
        return PathBuf::from(path);
    }

    #[cfg(windows)]
    {
        let root = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        return root.join("Lattice").join("node.json");
    }

    #[cfg(target_os = "linux")]
    {
        return PathBuf::from("/var/lib/lattice/node.json");
    }

    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/Library/Application Support/Lattice/node.json");
    }

    #[allow(unreachable_code)]
    PathBuf::from("lattice-node.json")
}

async fn load_config(path: &Path) -> Result<NodeConfig, String> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(NodeConfig::default());
        }
        Err(error) => return Err(error.to_string()),
    };

    serde_json::from_str(&content).map_err(|error| error.to_string())
}

async fn save_config(path: &Path, config: &NodeConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| error.to_string())?;
    }

    let content = serde_json::to_string_pretty(config).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())
}

fn validate_config(
    config: &mut NodeConfig,
    pinned_control_url: Option<&str>,
) -> Result<(), String> {
    if config.policy.limits.cpu_percent > 100 {
        return Err("CPU allocation must be between 0 and 100".to_string());
    }

    if config
        .policy
        .limits
        .gpu_percent
        .is_some_and(|value| value > 100)
    {
        return Err("GPU allocation must be between 0 and 100".to_string());
    }

    if config.policy.limits.memory_mb == 0 {
        return Err("Memory allocation must be greater than 0".to_string());
    }

    config.control_url = config
        .control_url
        .take()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(url) = config.control_url.as_deref() {
        if Some(url) != pinned_control_url {
            config.control_url = Some(enrollment::normalize_control_url(url)?);
        }
    }

    config.bootstrap_url = config
        .bootstrap_url
        .take()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(url) = config.bootstrap_url.as_deref() {
        config.bootstrap_url = Some(enrollment::normalize_bootstrap_url(url)?);
    }

    Ok(())
}

async fn build_status(state: &Arc<AppState>) -> NodeStatus {
    let _ = job::expire_local(state).await;
    let config = state.config.read().await.clone();
    let remote_policy = state.remote_policy.read().await.clone();
    let effective_policy = policy::effective(&config.policy, remote_policy.as_ref());
    let enrollment = state.identity.read().await.status();
    let active_lease = state.active_lease.read().await.clone();
    let artifact_cache = artifacts::cache_summary(&state.artifact_cache_path).await;
    let runtime_cache = runtimes::cache_summary(&state.runtime_cache_path).await;
    let mut update = match updates::load(
        &state.update_state_path,
        env!("CARGO_PKG_VERSION"),
        config.release_channel.clone(),
    )
    .await
    {
        Ok(update) => {
            *state.update_status.write().await = update.clone();
            update
        }
        Err(_) => state.update_status.read().await.clone(),
    };
    if matches!(&update.state, lattice_protocol::UpdateState::Downloading) {
        update.downloaded_bytes = state.update_downloaded_bytes.load(Ordering::Relaxed);
    }
    let hardware = hardware_snapshot(state).await;
    let runtime_state = if !effective_policy.enabled {
        NodeRuntimeState::Paused
    } else if active_lease.as_ref().is_some_and(|lease| {
        matches!(
            lease.state,
            lattice_protocol::JobState::Accepted
                | lattice_protocol::JobState::Preparing
                | lattice_protocol::JobState::Running
                | lattice_protocol::JobState::Stopping
        )
    }) {
        NodeRuntimeState::Running
    } else if active_lease
        .as_ref()
        .is_some_and(|lease| lease.state == lattice_protocol::JobState::Failed)
    {
        NodeRuntimeState::Degraded
    } else {
        NodeRuntimeState::Idle
    };
    let mining = state.mining_telemetry.read().await.clone();

    NodeStatus {
        node_id: enrollment.identity.node_id.clone(),
        node_name: enrollment.identity.node_name.clone(),
        runtime_state,
        control_url: enrollment
            .trust
            .as_ref()
            .map(|trust| trust.control_url.clone())
            .or(config.control_url.clone()),
        control_connected: state.control_connected.load(Ordering::Relaxed),
        hardware,
        policy: config.policy,
        remote_policy,
        effective_policy,
        active_lease,
        mining,
        artifact_cache,
        runtime_cache,
        update,
        enrollment,
        network: Some(state.network_status.read().await.clone()),
    }
}

async fn hardware_snapshot(state: &Arc<AppState>) -> HardwareSnapshot {
    let mut system = state.system.lock().await;
    system.refresh_memory();
    system.refresh_cpu_usage();

    let cpu_model = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Unknown CPU".to_string());

    let cpu = CpuInfo {
        model: cpu_model,
        logical_cores: system.cpus().len(),
        physical_cores: System::physical_core_count(),
        usage_percent: system.global_cpu_usage(),
    };

    let memory = MemoryInfo {
        total_mb: system.total_memory() / 1024 / 1024,
        used_mb: system.used_memory() / 1024 / 1024,
        available_mb: system.available_memory() / 1024 / 1024,
    };

    drop(system);

    HardwareSnapshot {
        os: System::long_os_version().unwrap_or_else(|| "Unknown OS".to_string()),
        kernel: System::kernel_long_version(),
        architecture: System::cpu_arch(),
        uptime_seconds: System::uptime(),
        cpu,
        memory,
        gpus: detect_nvidia_gpus().await,
    }
}

async fn detect_nvidia_gpus() -> Vec<GpuInfo> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,utilization.gpu",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .await;

    let Ok(output) = output else {
        return Vec::new();
    };

    if !output.status.success() {
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 3 {
                return None;
            }

            Some(GpuInfo {
                name: parts[0].to_string(),
                memory_total_mb: parts[1].parse().ok(),
                utilization_percent: parts[2].parse().ok(),
            })
        })
        .collect()
}

fn update_mutation_locked(state: &UpdateState) -> bool {
    matches!(
        state,
        UpdateState::Applying
            | UpdateState::Restarting
            | UpdateState::Verifying
            | UpdateState::RollingBack
    )
}

async fn dispatch(request: IpcRequest, state: &Arc<AppState>) -> IpcResponse {
    match request {
        IpcRequest::GetNetworkManager => {
            IpcResponse::NetworkManager(state.network_manager.lock().await.status())
        }
        IpcRequest::SubmitGatewayIntent { intent } => {
            match network_manager::submit_gateway(state, intent, &lattice_network::SystemRunner)
                .await
            {
                Ok(status) => IpcResponse::NetworkManager(status),
                Err(message) => IpcResponse::Error { message },
            }
        }
        IpcRequest::GetModules => IpcResponse::Modules(state.modules.lock().await.statuses()),
        IpcRequest::EnableModule { activation } => {
            match modules::enable(state, activation, false).await {
                Ok(m) => IpcResponse::Modules(m),
                Err(message) => IpcResponse::Error { message },
            }
        }
        IpcRequest::DisableModule { kind } => match modules::disable(state, kind).await {
            Ok(m) => IpcResponse::Modules(m),
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::ImportAuthority { context } => match trust_store::ingest(state, &context).await
        {
            Ok(()) => IpcResponse::AuthorityImported,
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::SyncAuthority => match authorization::refresh(state).await {
            Ok(()) => IpcResponse::AuthorityImported,
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::LocalMaster { request } => match modules::local_master(state, request).await {
            Ok(r) => IpcResponse::LocalMaster(r),
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::GetParticipation => {
            IpcResponse::Participation(setup::participation(state).await)
        }
        IpcRequest::AcceptParticipation { version, sha256 } => {
            match setup::accept_participation(state, &version, &sha256).await {
                Ok(p) => IpcResponse::Participation(p),
                Err(message) => IpcResponse::Error { message },
            }
        }
        IpcRequest::GetMasterCatalog => match setup::master_catalog(state).await {
            Ok(catalog) => IpcResponse::MasterCatalog(catalog),
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::ListMasters => match setup::list_masters(state).await {
            Ok(d) => IpcResponse::Masters(d),
            Err(message) => IpcResponse::Error { message },
        },
        IpcRequest::SelectMaster { control_id } => {
            match setup::select_master(state, control_id).await {
                Ok(p) => IpcResponse::Participation(p),
                Err(message) => IpcResponse::Error { message },
            }
        }
        IpcRequest::GetBuildInfo => IpcResponse::BuildInfo(lattice_protocol::NodeBuildInfo {
            process_id: std::process::id(),
            executable_path: std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            source_revision: option_env!("LATTICE_BUILD_REVISION").map(String::from),
            version: env!("CARGO_PKG_VERSION").into(),
        }),
        IpcRequest::BeginSetup { options } => match setup::begin(state.clone(), options).await {
            Ok(r) => IpcResponse::SetupStatus(r),
            Err(e) => IpcResponse::Error {
                message: e.to_string(),
            },
        },
        IpcRequest::GetSetupStatus => IpcResponse::SetupStatus(setup::status(state).await),
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::GetStatus => IpcResponse::Status(build_status(state).await),
        IpcRequest::GetConfig => IpcResponse::Config(state.config.read().await.clone()),
        IpcRequest::SetConfig { mut config } => {
            let pinned = state
                .identity
                .read()
                .await
                .trust()
                .map(|t| t.control_url.clone());
            if let Err(message) = validate_config(&mut config, pinned.as_deref()) {
                return IpcResponse::Error { message };
            }

            let previous_channel = state.config.read().await.release_channel.clone();

            if previous_channel != config.release_channel
                && update_mutation_locked(&state.update_status.read().await.state)
            {
                return IpcResponse::Error {
                    message: "release channel cannot change while an update is being applied"
                        .to_string(),
                };
            }

            if let Some(trust) = state.identity.read().await.trust()
                && config.control_url.as_deref() != Some(trust.control_url.as_str())
            {
                return IpcResponse::Error {
                    message: "reset enrollment before changing the trusted control server"
                        .to_string(),
                };
            }

            if let Some(bootstrap) = state.identity.read().await.bootstrap()
                && config.bootstrap_url.as_deref() != Some(bootstrap.bootstrap_url.as_str())
            {
                return IpcResponse::Error {
                    message: "reset bootstrap before changing the trusted bootstrapper".to_string(),
                };
            }

            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }

            if previous_channel != config.release_channel {
                let update = match updates::reset(
                    &state.update_state_path,
                    env!("CARGO_PKG_VERSION"),
                    config.release_channel.clone(),
                )
                .await
                {
                    Ok(update) => update,
                    Err(message) => return IpcResponse::Error { message },
                };
                *state.update_status.write().await = update;
            }

            *state.config.write().await = config.clone();
            IpcResponse::ConfigUpdated(config)
        }
        IpcRequest::GetEnrollmentStatus => {
            IpcResponse::EnrollmentStatus(state.identity.read().await.status())
        }
        IpcRequest::Enroll {
            control_url,
            enrollment_token,
        } => {
            {
                let identity = state.identity.read().await;
                if identity.trust().is_some() {
                    return IpcResponse::Error {
                        message: "node is already enrolled; reset enrollment first".to_string(),
                    };
                }
            }

            let trust = {
                let identity = state.identity.read().await;
                match enrollment::enroll(&state.http, &identity, &control_url, &enrollment_token)
                    .await
                {
                    Ok(trust) => trust,
                    Err(message) => return IpcResponse::Error { message },
                }
            };

            {
                let mut identity = state.identity.write().await;
                if let Err(message) = identity.set_trust(trust.clone()).await {
                    return IpcResponse::Error { message };
                }
            }

            let mut config = state.config.read().await.clone();
            config.control_url = Some(trust.control_url);
            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }
            *state.config.write().await = config;

            state.control_connected.store(false, Ordering::Relaxed);
            IpcResponse::EnrollmentUpdated(state.identity.read().await.status())
        }
        IpcRequest::EnrollBootstrap {
            bootstrap_url,
            enrollment_token,
        } => {
            {
                let identity = state.identity.read().await;
                if identity.bootstrap().is_some() {
                    return IpcResponse::Error {
                        message: "node already joined a bootstrapper; reset bootstrap first"
                            .to_string(),
                    };
                }
            }

            let bootstrap = {
                let identity = state.identity.read().await;
                match enrollment::enroll_bootstrap(
                    &state.http,
                    &identity,
                    &bootstrap_url,
                    &enrollment_token,
                )
                .await
                {
                    Ok(bootstrap) => bootstrap,
                    Err(message) => return IpcResponse::Error { message },
                }
            };

            {
                let mut identity = state.identity.write().await;
                if let Err(message) = identity.set_bootstrap(bootstrap.clone()).await {
                    return IpcResponse::Error { message };
                }
            }

            let mut config = state.config.read().await.clone();
            config.bootstrap_url = Some(bootstrap.bootstrap_url);
            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }
            *state.config.write().await = config;

            IpcResponse::EnrollmentUpdated(state.identity.read().await.status())
        }
        IpcRequest::ResetEnrollment => {
            if let Err(error) = setup::suspend(state).await {
                return IpcResponse::Error {
                    message: error.to_string(),
                };
            }
            if update_mutation_locked(&state.update_status.read().await.state) {
                return IpcResponse::Error {
                    message: "enrollment cannot be reset while an update is being applied"
                        .to_string(),
                };
            }

            {
                let mut identity = state.identity.write().await;
                if let Err(message) = identity.clear_trust().await {
                    return IpcResponse::Error { message };
                }
            }

            let mut config = state.config.read().await.clone();
            config.control_url = None;
            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }
            *state.config.write().await = config;
            if let Err(message) = policy::clear(&state.remote_policy_path).await {
                return IpcResponse::Error { message };
            }
            *state.remote_policy.write().await = None;
            if let Err(message) = job::clear(&state.active_lease_path).await {
                return IpcResponse::Error { message };
            }
            *state.active_lease.write().await = None;
            let release_channel = state.config.read().await.release_channel.clone();
            let update = match updates::reset(
                &state.update_state_path,
                env!("CARGO_PKG_VERSION"),
                release_channel,
            )
            .await
            {
                Ok(update) => update,
                Err(message) => return IpcResponse::Error { message },
            };
            *state.update_status.write().await = update;
            state.control_connected.store(false, Ordering::Relaxed);

            IpcResponse::EnrollmentUpdated(state.identity.read().await.status())
        }
        IpcRequest::ResetBootstrap => {
            if let Err(error) = setup::suspend(state).await {
                return IpcResponse::Error {
                    message: error.to_string(),
                };
            }
            {
                let mut identity = state.identity.write().await;
                if let Err(message) = identity.clear_bootstrap().await {
                    return IpcResponse::Error { message };
                }
            }

            *state.workload_authority.write().await = None;
            let _ =
                tokio::fs::remove_file(state.config_path.with_file_name("workload-authority.json"))
                    .await;
            let mut config = state.config.read().await.clone();
            config.bootstrap_url = None;
            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }
            *state.config.write().await = config;
            if let Err(message) = network::clear_bootstrap_state(state).await {
                return IpcResponse::Error { message };
            }
            {
                let mut net_status = state.network_status.write().await;
                net_status.status = lattice_protocol::NetworkNodeStatus::Unconfigured;
                net_status.virtual_ipv4 = None;
                net_status.peer_count = 0;
                net_status.path_policy = String::new();
                net_status.last_error = None;
                net_status.error_code = None;
            }

            IpcResponse::EnrollmentUpdated(state.identity.read().await.status())
        }
        IpcRequest::GetNetworkStatus => match state.network_status.try_read() {
            Ok(summary) => IpcResponse::NetworkStatus(summary.clone()),
            Err(_) => IpcResponse::Error {
                message: "network status busy".to_string(),
            },
        },
        IpcRequest::SetNetworkEnabled { enabled } => {
            let mut config = state.config.read().await.clone();
            config.network.enabled = enabled;
            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
            }
            *state.config.write().await = config.clone();
            if !enabled {
                if let Err(message) = network_manager::disconnect(state, None).await {
                    return IpcResponse::Error { message };
                }
            }
            {
                let mut net_status = state.network_status.write().await;
                net_status.enabled = enabled;
                if !enabled {
                    net_status.status = lattice_protocol::NetworkNodeStatus::Disabled;
                }
            }
            IpcResponse::NetworkConfigUpdated(config.network)
        }
    }
}

async fn handle_stream<S>(
    stream: S,
    state: Arc<AppState>,
    administrator: bool,
) -> Result<(), NodeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let line = tokio::time::timeout(
        Duration::from_secs(30),
        lattice_ipc::read_frame(&mut reader, lattice_ipc::MAX_FRAME_BYTES),
    )
    .await
    .map_err(|_| std::io::Error::other("IPC request timed out"))?
    .map_err(std::io::Error::other)?;
    if line.is_empty() {
        return Ok(());
    }

    respond(reader, &line, state, administrator).await
}
async fn respond<S>(
    mut reader: BufReader<S>,
    line: &str,
    state: Arc<AppState>,
    administrator: bool,
) -> Result<(), NodeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = match serde_json::from_str::<IpcRequest>(line) {
        Ok(IpcRequest::EnableModule { activation }) => {
            match modules::enable(&state, activation, administrator).await {
                Ok(m) => IpcResponse::Modules(m),
                Err(message) => IpcResponse::Error { message },
            }
        }
        Ok(request) => dispatch(request, &state).await,
        Err(error) => IpcResponse::Error {
            message: error.to_string(),
        },
    };

    let mut payload = serde_json::to_vec(&response)?;
    payload.push(b'\n');
    reader.get_mut().write_all(&payload).await?;
    reader.get_mut().flush().await?;
    Ok(())
}

#[cfg(windows)]
async fn serve(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) -> Result<(), NodeError> {
    use lattice_ipc::WINDOWS_PIPE_NAME;

    let pipe_name = std::env::var("LATTICE_PIPE").unwrap_or_else(|_| WINDOWS_PIPE_NAME.to_string());

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let server = create_windows_pipe(&pipe_name)?;

        tokio::select! {
            result = server.connect() => {
                result?;
                let state = state.clone();
                tokio::spawn(async move {
                    let mut reader=BufReader::new(server);
                    if let Ok(Ok(line))=tokio::time::timeout(Duration::from_secs(30), lattice_ipc::read_frame(&mut reader,lattice_ipc::MAX_FRAME_BYTES)).await {
                        let administrator=windows_peer_is_administrator(reader.get_ref());
                        let _=respond(reader,&line,state,administrator).await;
                    }
                });
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(windows)]
fn create_windows_pipe(
    pipe_name: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use tokio::net::windows::named_pipe::ServerOptions;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let descriptor_text = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();

    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };

    if converted == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };

    let result = unsafe {
        ServerOptions::new()
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                pipe_name,
                &mut attributes as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
    };

    unsafe {
        LocalFree(descriptor as _);
    }

    result
}

#[cfg(windows)]
fn windows_peer_is_administrator(
    server: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> bool {
    use std::{os::windows::io::AsRawHandle, ptr::null_mut};
    use windows_sys::Win32::{
        Security::{
            CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid,
        },
        System::Pipes::ImpersonateNamedPipeClient,
    };
    unsafe {
        if ImpersonateNamedPipeClient(server.as_raw_handle() as _) == 0 {
            return false;
        }
        let mut sid = [0u8; 68];
        let mut size = sid.len() as u32;
        let mut member = 0;
        let valid = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            null_mut(),
            sid.as_mut_ptr().cast(),
            &mut size,
        ) != 0
            && CheckTokenMembership(null_mut(), sid.as_mut_ptr().cast(), &mut member) != 0
            && member != 0;
        if RevertToSelf() == 0 {
            std::process::abort();
        }
        valid
    }
}

#[cfg(unix)]
fn local_owner_peer(uid: u32, configured: Option<&str>, daemon_uid: u32) -> bool {
    uid == 0
        || match configured {
            Some(value) => value.parse::<u32>().is_ok_and(|owner| uid == owner),
            None => uid == daemon_uid,
        }
}

#[cfg(unix)]
async fn serve(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) -> Result<(), NodeError> {
    use lattice_ipc::UNIX_SOCKET_PATH;
    use tokio::net::UnixListener;

    let socket_path =
        std::env::var("LATTICE_SOCKET").unwrap_or_else(|_| UNIX_SOCKET_PATH.to_string());

    network_manager::check_ipc_path().await?;
    if tokio::fs::try_exists(&socket_path).await? {
        tokio::fs::remove_file(&socket_path).await?;
    }

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660)).await?;
        if unsafe { libc::geteuid() } == 0 {
            let gid = std::env::var("LATTICE_IPC_GID")
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(if cfg!(target_os = "macos") { 80 } else { 0 });
            let path = std::ffi::CString::new(socket_path.as_bytes())?;
            if unsafe { libc::chown(path.as_ptr(), 0, gid) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let Ok(peer) = stream.peer_cred() else { continue; };
                if !local_owner_peer(peer.uid(), std::env::var("LATTICE_OWNER_UID").ok().as_deref(), unsafe {libc::geteuid()}) { continue; }
                let administrator=peer.uid()==0;
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_stream(stream, state,administrator).await;
                });
            }
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

pub fn ipc_endpoint() -> String {
    #[cfg(windows)]
    {
        return std::env::var("LATTICE_PIPE")
            .unwrap_or_else(|_| lattice_ipc::WINDOWS_PIPE_NAME.to_string());
    }

    #[cfg(unix)]
    {
        return std::env::var("LATTICE_SOCKET")
            .unwrap_or_else(|_| lattice_ipc::UNIX_SOCKET_PATH.to_string());
    }

    #[allow(unreachable_code)]
    "unsupported".to_string()
}

#[cfg(all(test, unix))]
mod local_owner_tests {
    #[test]
    fn shared_socket_group_does_not_authorize_another_local_account() {
        assert!(super::local_owner_peer(0, Some("501"), 0));
        assert!(super::local_owner_peer(501, Some("501"), 0));
        assert!(!super::local_owner_peer(502, Some("501"), 0));
        assert!(!super::local_owner_peer(501, Some("invalid"), 0));
        assert!(!super::local_owner_peer(501, None, 0));
        assert!(super::local_owner_peer(501, None, 501));
    }
}
