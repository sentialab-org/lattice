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
    if let Some(context) = &response.authority {
        crate::trust_store::ingest(s, context).await?;
    } else if identity.offline_authority_required() {
        return Err("certified authority downgrade rejected".into());
    }
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
    // Revoked members may no longer use discovery, but can still receive public signed tombstones.
    if let Ok(response) = s
        .http
        .get(format!("{}/api/v2/authority", bootstrap.bootstrap_url))
        .send()
        .await
    {
        if response.status().is_success() {
            let snapshot = response
                .json::<lattice_protocol::SignedAuthoritySnapshot>()
                .await
                .map_err(|_| "invalid authority snapshot")?;
            if s.offline_authority.lock().await.checked()?.is_some() {
                crate::trust_store::ingest(
                    s,
                    &lattice_protocol::AuthorityContext {
                        snapshot: Some(snapshot),
                        ..Default::default()
                    },
                )
                .await?;
            }
        }
    }
    let response = crate::setup::discover_current(s, &identity, bootstrap).await?;
    record(s, &response).await
}
pub(crate) async fn require(s: &AppState, trust: &ControlTrust) -> Result<(), String> {
    require_scope(s, trust, lattice_protocol::CommandScope::Workloads).await
}
pub(crate) async fn learn_from_master(s: &AppState, trust: &ControlTrust) -> Result<(), String> {
    require_contact(s, trust).await?;
    let response = s
        .http
        .get(format!("{}/api/v2/authority", trust.control_url))
        .send()
        .await
        .map_err(|_| "Master authority presentation unavailable")?;
    if !response.status().is_success() {
        return Err("Master authority presentation rejected".into());
    }
    let snapshot = response
        .json::<lattice_protocol::SignedAuthoritySnapshot>()
        .await
        .map_err(|_| "invalid Master authority presentation")?;
    crate::trust_store::ingest_presented(
        s,
        &lattice_protocol::AuthorityContext {
            snapshot: Some(snapshot),
            ..Default::default()
        },
    )
    .await
}
pub(crate) async fn require_contact(s: &AppState, trust: &ControlTrust) -> Result<(), String> {
    if !s.config.read().await.network.enabled {
        return Err("network disabled by owner".into());
    }
    let participation = crate::setup::participation(s).await;
    if !participation.accepted
        || participation.master_choice.control_id.as_deref() != Some(&trust.control_id)
    {
        return Err("owner has not selected this workload master".into());
    }
    Ok(())
}
pub(crate) async fn require_scope(
    s: &AppState,
    trust: &ControlTrust,
    scope: lattice_protocol::CommandScope,
) -> Result<(), String> {
    require_contact(s, trust).await?;
    let identity = s.identity.read().await.clone();
    let bootstrap = identity.bootstrap().ok_or("bootstrap trust required")?;
    {
        crate::trust_store::observe_time(s).await?;
        let store = s.offline_authority.lock().await;
        if let Some(cache) = store.checked()? {
            cache.require_membership(
                &identity.identity().node_id,
                &identity.identity().public_key,
                unix_time_ms(),
            )?;
            let master = cache.require_master(
                &trust.control_id,
                &trust.control_public_key,
                &scope,
                unix_time_ms(),
            )?;
            if !matches!(&master.certificate.subject,lattice_protocol::CertificateSubject::Master{overlay_ipv4,..}
                if trust.control_url==format!("http://{overlay_ipv4}:7443"))
            {
                return Err("master endpoint mismatch".into());
            }
            return Ok(());
        }
        if identity.offline_authority_required() {
            return Err("certified authority missing".into());
        }
    }
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
