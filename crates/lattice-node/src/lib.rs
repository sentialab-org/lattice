pub mod artifacts;
mod content_cache;
mod enrollment;
mod heartbeat;
mod identity;
mod job;
mod policy;
pub mod runtimes;

use identity::{IdentityState, identity_path};
use lattice_protocol::{
    CpuInfo, GpuInfo, HardwareSnapshot, IpcRequest, IpcResponse, JobLeaseStatus, MemoryInfo,
    NodeConfig, NodeRuntimeState, NodeStatus, PolicySnapshot,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sysinfo::System;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock, watch};

pub type NodeError = Box<dyn std::error::Error + Send + Sync>;

struct AppState {
    config: RwLock<NodeConfig>,
    config_path: PathBuf,
    identity: RwLock<IdentityState>,
    remote_policy: RwLock<Option<PolicySnapshot>>,
    remote_policy_path: PathBuf,
    active_lease: RwLock<Option<JobLeaseStatus>>,
    active_lease_path: PathBuf,
    artifact_cache_path: PathBuf,
    runtime_cache_path: PathBuf,
    system: Mutex<System>,
    http: reqwest::Client,
    content_http: reqwest::Client,
    control_connected: AtomicBool,
}

pub async fn run_node(shutdown: watch::Receiver<bool>) -> Result<(), NodeError> {
    let config_path = config_path();
    let mut config = load_config(&config_path).await.unwrap_or_default();
    let identity = IdentityState::load_or_create(identity_path(&config_path)).await?;

    if let Some(trust) = identity.trust() {
        config.control_url = Some(trust.control_url.clone());
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
    let http = reqwest::Client::builder()
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
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(artifact_timeout))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(format!(
            "lattice-node/{}/artifact",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?;
    let state = Arc::new(AppState {
        config: RwLock::new(config),
        config_path,
        identity: RwLock::new(identity),
        remote_policy: RwLock::new(remote_policy),
        remote_policy_path,
        active_lease: RwLock::new(active_lease),
        active_lease_path,
        artifact_cache_path,
        runtime_cache_path,
        system: Mutex::new(System::new_all()),
        http,
        content_http,
        control_connected: AtomicBool::new(false),
    });

    tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
    let heartbeat_state = state.clone();
    let heartbeat_shutdown = shutdown.clone();
    let heartbeat_task = tokio::spawn(async move {
        heartbeat::run(heartbeat_state, heartbeat_shutdown).await;
    });
    let result = serve(state, shutdown).await;
    heartbeat_task.abort();
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
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        return home
            .join("Library")
            .join("Application Support")
            .join("Lattice")
            .join("node.json");
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

fn validate_config(config: &mut NodeConfig) -> Result<(), String> {
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
        config.control_url = Some(enrollment::normalize_control_url(url)?);
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
    let hardware = hardware_snapshot(state).await;
    let runtime_state = if effective_policy.enabled {
        NodeRuntimeState::Idle
    } else {
        NodeRuntimeState::Paused
    };

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
        artifact_cache,
        runtime_cache,
        enrollment,
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

async fn dispatch(request: IpcRequest, state: &Arc<AppState>) -> IpcResponse {
    match request {
        IpcRequest::Ping => IpcResponse::Pong,
        IpcRequest::GetStatus => IpcResponse::Status(build_status(state).await),
        IpcRequest::GetConfig => IpcResponse::Config(state.config.read().await.clone()),
        IpcRequest::SetConfig { mut config } => {
            if let Err(message) = validate_config(&mut config) {
                return IpcResponse::Error { message };
            }

            if let Some(trust) = state.identity.read().await.trust()
                && config.control_url.as_deref() != Some(trust.control_url.as_str())
            {
                return IpcResponse::Error {
                    message: "reset enrollment before changing the trusted control server"
                        .to_string(),
                };
            }

            if let Err(message) = save_config(&state.config_path, &config).await {
                return IpcResponse::Error { message };
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
        IpcRequest::ResetEnrollment => {
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
            state.control_connected.store(false, Ordering::Relaxed);

            IpcResponse::EnrollmentUpdated(state.identity.read().await.status())
        }
    }
}

async fn handle_stream<S>(stream: S, state: Arc<AppState>) -> Result<(), NodeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<IpcRequest>(&line) {
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
                    let _ = handle_stream(server, state).await;
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

#[cfg(unix)]
async fn serve(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) -> Result<(), NodeError> {
    use lattice_ipc::UNIX_SOCKET_PATH;
    use tokio::net::UnixListener;

    let socket_path =
        std::env::var("LATTICE_SOCKET").unwrap_or_else(|_| UNIX_SOCKET_PATH.to_string());

    if tokio::fs::try_exists(&socket_path).await? {
        tokio::fs::remove_file(&socket_path).await?;
    }

    let listener = UnixListener::bind(&socket_path)?;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_stream(stream, state).await;
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
