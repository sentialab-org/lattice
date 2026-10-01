#[cfg(not(windows))]
fn main() {
    eprintln!("lattice-update-helper is only supported on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
use lattice_ipc::request;
#[cfg(windows)]
use lattice_protocol::{IpcRequest, IpcResponse, UpdateApplyPlan, UpdateState, UpdateStatus};
#[cfg(windows)]
use semver::Version;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use windows_service::service::{ServiceAccess, ServiceState};
#[cfg(windows)]
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

#[cfg(windows)]
const SERVICE_NAME: &str = "LatticeNode";

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let plan_path = parse_plan_path()?;
    let content = tokio::fs::read_to_string(&plan_path).await?;
    let plan: UpdateApplyPlan = serde_json::from_str(&content)?;

    if let Err(error) = apply(&plan).await {
        eprintln!("{error}");
        std::process::exit(1);
    }

    let _ = tokio::fs::remove_file(plan_path).await;
    Ok(())
}

#[cfg(windows)]
fn parse_plan_path() -> Result<PathBuf, String> {
    let mut args = std::env::args_os().skip(1);
    let Some(flag) = args.next() else {
        return Err("missing --apply-plan".to_string());
    };
    if flag != OsStr::new("--apply-plan") {
        return Err("expected --apply-plan".to_string());
    }
    let Some(path) = args.next() else {
        return Err("missing update apply plan path".to_string());
    };
    if args.next().is_some() {
        return Err("unexpected extra update helper arguments".to_string());
    }
    Ok(PathBuf::from(path))
}

#[cfg(windows)]
async fn apply(plan: &UpdateApplyPlan) -> Result<(), String> {
    validate_plan(plan)?;
    let staged_path = PathBuf::from(&plan.staged_path);
    let target_path = PathBuf::from(&plan.target_path);
    let backup_path = PathBuf::from(&plan.backup_path);
    let state_path = PathBuf::from(&plan.state_path);
    let mut status = load_status(&state_path).await?;

    if status.staged_version.as_deref() != Some(plan.expected_version.as_str()) {
        return fail_before_replace(
            &state_path,
            &mut status,
            "staged update version does not match the apply plan".to_string(),
        )
        .await;
    }
    if status.staged_path.as_deref() != Some(plan.staged_path.as_str()) {
        return fail_before_replace(
            &state_path,
            &mut status,
            "staged update path does not match the apply plan".to_string(),
        )
        .await;
    }
    if let Err(error) = verify_file(&staged_path, plan.size_bytes, &plan.sha256) {
        return fail_before_replace(&state_path, &mut status, error).await;
    }

    status.state = UpdateState::Applying;
    status.previous_version = Some(plan.previous_version.clone());
    status.backup_path = Some(plan.backup_path.clone());
    status.last_error = None;
    save_status(&state_path, &status).await?;

    if let Some(parent) = backup_path.parent()
        && let Err(error) = tokio::fs::create_dir_all(parent).await
    {
        return fail_before_replace(&state_path, &mut status, error.to_string()).await;
    }

    if let Err(error) = tokio::fs::copy(&target_path, &backup_path).await {
        return fail_before_replace(
            &state_path,
            &mut status,
            format!("failed to back up current node executable: {error}"),
        )
        .await;
    }
    if let Err(error) = sync_file(&backup_path).await {
        return fail_before_replace(&state_path, &mut status, error).await;
    }

    let backup_metadata = match tokio::fs::metadata(&backup_path).await {
        Ok(metadata) => metadata,
        Err(error) => {
            return fail_before_replace(&state_path, &mut status, error.to_string()).await;
        }
    };
    let backup_hash = match sha256_file(&backup_path) {
        Ok(hash) => hash,
        Err(error) => {
            return fail_before_replace(&state_path, &mut status, error).await;
        }
    };

    let replacement_path = match replacement_path(&target_path, "new") {
        Ok(path) => path,
        Err(error) => {
            return fail_before_replace(&state_path, &mut status, error).await;
        }
    };

    match tokio::fs::try_exists(&replacement_path).await {
        Ok(true) => {
            let _ = tokio::fs::remove_file(&replacement_path).await;
        }
        Ok(false) => {}
        Err(error) => {
            return fail_before_replace(&state_path, &mut status, error.to_string()).await;
        }
    }

    if let Err(error) = tokio::fs::copy(&staged_path, &replacement_path).await {
        return fail_before_replace(
            &state_path,
            &mut status,
            format!("failed to copy staged update next to target: {error}"),
        )
        .await;
    }
    if let Err(error) = sync_file(&replacement_path).await {
        return fail_before_replace(&state_path, &mut status, error).await;
    }
    if let Err(error) = verify_file(&replacement_path, plan.size_bytes, &plan.sha256) {
        return fail_before_replace(&state_path, &mut status, error).await;
    }

    if let Err(error) = stop_service() {
        return fail_before_replace(
            &state_path,
            &mut status,
            format!("failed to stop node service before replacement: {error}"),
        )
        .await;
    }

    if let Err(error) = atomic_replace(&replacement_path, &target_path) {
        let _ = start_service();
        mark_failed(
            &state_path,
            &mut status,
            format!("failed to replace node executable: {error}"),
        )
        .await?;
        return Err(error);
    }

    status.state = UpdateState::Restarting;
    save_status(&state_path, &status).await?;

    if let Err(error) = start_service() {
        return rollback(
            plan,
            &state_path,
            &backup_path,
            backup_metadata.len(),
            &backup_hash,
            &mut status,
            format!("failed to restart updated node: {error}"),
        )
        .await;
    }

    status.state = UpdateState::Verifying;
    save_status(&state_path, &status).await?;

    if let Err(error) = wait_for_node_version(&plan.expected_version).await {
        return rollback(
            plan,
            &state_path,
            &backup_path,
            backup_metadata.len(),
            &backup_hash,
            &mut status,
            error,
        )
        .await;
    }

    status.installed_version = plan.expected_version.clone();
    status.available_version = None;
    status.state = UpdateState::Idle;
    status.downloaded_bytes = 0;
    status.total_bytes = None;
    status.staged_version = None;
    status.staged_path = None;
    status.last_error = None;
    status.retry_count = 0;
    save_status(&state_path, &status).await?;
    Ok(())
}

#[cfg(windows)]
async fn fail_before_replace(
    state_path: &Path,
    status: &mut UpdateStatus,
    error: String,
) -> Result<(), String> {
    let _ = start_service();
    mark_failed(state_path, status, error.clone()).await?;
    Err(error)
}

#[cfg(windows)]
async fn rollback(
    plan: &UpdateApplyPlan,
    state_path: &Path,
    backup_path: &Path,
    backup_size: u64,
    backup_hash: &str,
    status: &mut UpdateStatus,
    cause: String,
) -> Result<(), String> {
    status.state = UpdateState::RollingBack;
    status.last_error = Some(cause.clone());
    save_status(state_path, status).await?;

    let rollback_result: Result<(), String> = async {
        stop_service()
            .map_err(|error| format!("failed to stop updated node for rollback: {error}"))?;
        verify_file(backup_path, backup_size, backup_hash)?;

        let target_path = PathBuf::from(&plan.target_path);
        let rollback_path = replacement_path(&target_path, "rollback")?;
        if tokio::fs::try_exists(&rollback_path)
            .await
            .map_err(|error| error.to_string())?
        {
            let _ = tokio::fs::remove_file(&rollback_path).await;
        }
        tokio::fs::copy(backup_path, &rollback_path)
            .await
            .map_err(|error| format!("failed to prepare rollback executable: {error}"))?;
        sync_file(&rollback_path).await?;
        verify_file(&rollback_path, backup_size, backup_hash)?;
        atomic_replace(&rollback_path, &target_path)
            .map_err(|error| format!("failed to restore previous node executable: {error}"))?;
        start_service().map_err(|error| format!("failed to restart rolled-back node: {error}"))?;
        wait_for_node_version(&plan.previous_version).await
    }
    .await;

    status.state = UpdateState::Failed;
    status.retry_count = status.retry_count.saturating_add(1);

    match rollback_result {
        Ok(()) => {
            status.installed_version = plan.previous_version.clone();
            status.last_error = Some(format!(
                "update to {} failed and rollback succeeded: {}",
                plan.expected_version, cause
            ));
        }
        Err(rollback_error) => {
            let _ = start_service();
            status.last_error = Some(format!(
                "update to {} failed: {}; rollback failed: {}",
                plan.expected_version, cause, rollback_error
            ));
        }
    }

    let persisted_error = status
        .last_error
        .clone()
        .unwrap_or_else(|| "update failed".to_string());
    save_status(state_path, status).await?;
    Err(persisted_error)
}

#[cfg(windows)]
fn validate_plan(plan: &UpdateApplyPlan) -> Result<(), String> {
    let expected = Version::parse(&plan.expected_version)
        .map_err(|error| format!("invalid expected version: {error}"))?;
    let previous = Version::parse(&plan.previous_version)
        .map_err(|error| format!("invalid previous version: {error}"))?;

    if expected <= previous {
        return Err("update target version must be greater than the current version".to_string());
    }
    if plan.sha256.len() != 64
        || !plan
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("update apply plan contains an invalid SHA-256".to_string());
    }
    if plan.size_bytes == 0 {
        return Err("update apply plan size must be greater than zero".to_string());
    }

    for value in [
        &plan.staged_path,
        &plan.target_path,
        &plan.backup_path,
        &plan.state_path,
    ] {
        if value.trim().is_empty() {
            return Err("update apply plan paths must not be empty".to_string());
        }
    }

    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> Result<(), String> {
    let source_wide = wide_path(source);
    let target_wide = wide_path(target);
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn replacement_path(target: &Path, label: &str) -> Result<PathBuf, String> {
    let parent = target
        .parent()
        .ok_or_else(|| "node executable path has no parent directory".to_string())?;
    Ok(parent.join(format!(
        ".lattice-node-{label}-{}.tmp",
        std::process::id()
    )))
}

#[cfg(windows)]
fn stop_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| error.to_string())?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .map_err(|error| error.to_string())?;

    if service
        .query_status()
        .map_err(|error| error.to_string())?
        .current_state
        != ServiceState::Stopped
    {
        service.stop().map_err(|error| error.to_string())?;
        wait_for_service_state(&service, ServiceState::Stopped, Duration::from_secs(20))?;
    }

    Ok(())
}

#[cfg(windows)]
fn start_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| error.to_string())?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .map_err(|error| error.to_string())?;

    if service
        .query_status()
        .map_err(|error| error.to_string())?
        .current_state
        == ServiceState::Stopped
    {
        service
            .start::<&OsStr>(&[])
            .map_err(|error| error.to_string())?;
    }
    wait_for_service_state(&service, ServiceState::Running, Duration::from_secs(20))
}

#[cfg(windows)]
fn wait_for_service_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if service
            .query_status()
            .is_ok_and(|status| status.current_state == expected)
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("service did not reach {expected:?} before timeout"))
}

#[cfg(windows)]
async fn wait_for_node_version(expected_version: &str) -> Result<(), String> {
    for _ in 0..60 {
        match request(&IpcRequest::GetStatus).await {
            Ok(IpcResponse::Status(status)) if status.update.installed_version == expected_version => {
                return Ok(());
            }
            _ => {}
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(format!(
        "updated node did not pass IPC and version health verification for {expected_version}"
    ))
}

#[cfg(windows)]
async fn load_status(path: &Path) -> Result<UpdateStatus, String> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::from_str(&content).map_err(|error| error.to_string())
}

#[cfg(windows)]
async fn save_status(path: &Path, status: &UpdateStatus) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(status).map_err(|error| error.to_string())?;
    tokio::fs::write(path, content)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
async fn mark_failed(
    path: &Path,
    status: &mut UpdateStatus,
    error: String,
) -> Result<(), String> {
    status.state = UpdateState::Failed;
    status.last_error = Some(error);
    status.retry_count = status.retry_count.saturating_add(1);
    save_status(path, status).await
}

#[cfg(windows)]
async fn sync_file(path: &Path) -> Result<(), String> {
    let file = tokio::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .await
        .map_err(|error| error.to_string())?;
    file.sync_all().await.map_err(|error| error.to_string())
}

#[cfg(windows)]
fn verify_file(path: &Path, expected_size: u64, expected_sha256: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() != expected_size {
        return Err("file size does not match update metadata".to_string());
    }

    let digest = sha256_file(path)?;
    if digest != expected_sha256 {
        return Err("file SHA-256 does not match update metadata".to_string());
    }

    Ok(())
}

#[cfg(windows)]
fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
