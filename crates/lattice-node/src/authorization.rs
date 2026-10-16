//! Coordinator authorization is independent of a workload master's retained key.
use crate::{AppState, enrollment, identity::unix_time_ms};
use lattice_protocol::{ControlTrust, DiscoveryResponse};
use std::path::Path;
fn path(s: &AppState) -> std::path::PathBuf {
    s.config_path.with_file_name("workload-authority.json")
}
pub(crate) fn cache_origin(index: &Path, origin: &str) -> Result<(), String> {
    crate::setup::write_private(&index.with_file_name("authorized-origin.json"), &origin)
        .map_err(|_| "content origin persistence failed".into())
}
pub(crate) fn content_origin(index: &Path) -> Option<String> {
    std::fs::read(index.with_file_name("authorized-origin.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}
pub(crate) fn load(config: &Path) -> Option<DiscoveryResponse> {
    std::fs::read(config.with_file_name("workload-authority.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}
pub(crate) async fn record(s: &AppState, response: &DiscoveryResponse) -> Result<(), String> {
    let identity = s.identity.read().await.clone();
    let bootstrap = identity.bootstrap().ok_or("bootstrap trust required")?;
    enrollment::validate_discovery(response, &identity, bootstrap)?;
    let mut cache = s.workload_authority.write().await;
    if let Some(previous) = cache.as_ref() {
        let old = &previous.directory.directory;
        let new = &response.directory.directory;
        if old.network_id != new.network_id
            || new.revision < old.revision
            || (new.revision == old.revision && new.masters != old.masters)
        {
            return Err("directory rollback rejected".into());
        }
    }
    crate::setup::write_private(&path(s), response).map_err(|_| "authority persistence failed")?;
    *cache = Some(response.clone());
    Ok(())
}
pub(crate) async fn refresh(s: &AppState) -> Result<(), String> {
    if !s.setup.lock().await.is_managed() {
        return Ok(());
    }
    if !s.config.read().await.network.enabled {
        return Err("network disabled by owner".into());
    }
    let identity = s.identity.read().await.clone();
    let bootstrap = identity.bootstrap().ok_or("bootstrap trust required")?;
    let response = crate::setup::discover_current(s, &identity, bootstrap).await?;
    record(s, &response).await
}
pub(crate) async fn require(s: &AppState, trust: &ControlTrust) -> Result<(), String> {
    if !s.config.read().await.network.enabled {
        return Err("network disabled by owner".into());
    }
    let participation = crate::setup::participation(s).await;
    if !participation.accepted
        || participation.master_choice.control_id.as_deref() != Some(&trust.control_id)
    {
        return Err("owner has not selected this workload master".into());
    }
    let identity = s.identity.read().await.clone();
    let bootstrap = identity.bootstrap().ok_or("bootstrap trust required")?;
    let cache = s.workload_authority.read().await;
    let response = cache.as_ref().ok_or("workload directory unavailable")?;
    enrollment::validate_discovery(response, &identity, bootstrap)?;
    let d = &response.directory.directory;
    if unix_time_ms().saturating_sub(d.issued_at_ms) > 120_000 {
        return Err("workload directory expired".into());
    }
    let grant = d
        .masters
        .iter()
        .find(|g| g.grant.control_id == trust.control_id)
        .ok_or("selected master is not authorized")?;
    if grant.grant.control_id != trust.control_id
        || grant.grant.control_public_key != trust.control_public_key
        || trust.control_url != format!("http://{}:7443", grant.grant.overlay_ipv4)
    {
        return Err("workload master authority revoked or replaced".into());
    }
    Ok(())
}
