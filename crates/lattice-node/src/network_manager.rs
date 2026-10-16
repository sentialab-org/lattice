//! The Base Node is the single host owner of network mutation.
use std::path::PathBuf;

pub(crate) fn acquire_host() -> Result<lattice_network::HostLock, String> {
    let path = match std::env::var_os("LATTICE_NETWORK_OWNER_LOCK") {
        Some(path) => PathBuf::from(path),
        None => {
            #[cfg(windows)]
            {
                PathBuf::from(
                    std::env::var_os("PROGRAMDATA").unwrap_or_else(|| r"C:\ProgramData".into()),
                )
                .join("Lattice")
                .join("network-owner.lock")
            }
            #[cfg(unix)]
            {
                PathBuf::from(lattice_ipc::UNIX_SOCKET_PATH).with_file_name("network-owner.lock")
            }
            #[cfg(not(any(unix, windows)))]
            {
                return Err("host network ownership unsupported".into());
            }
        }
    };
    lattice_network::HostLock::acquire(&path)
}

#[cfg(unix)]
pub(crate) async fn check_ipc_path() -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path =
        std::env::var("LATTICE_SOCKET").unwrap_or_else(|_| lattice_ipc::UNIX_SOCKET_PATH.into());
    match std::fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                return Err("IPC path is not an owned socket; preserve and inspect it".into());
            }
            if tokio::net::UnixStream::connect(&path).await.is_ok() {
                return Err(
                    "another Node owns the IPC socket; stop its service before migration".into(),
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("IPC socket metadata unavailable".into()),
    }
}

use crate::identity::IdentityState;
use lattice_protocol::{NetworkManagerStatus, SignedGatewayIntent, SignedNetworkDesiredConfig};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedBase {
    signed: SignedNetworkDesiredConfig,
    supervisor: String,
    transport: String,
    interface: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerState {
    schema_version: u32,
    node_id: String,
    node_public_key: String,
    network_id: Option<String>,
    supervisor_key: Option<String>,
    desired: Option<SignedGatewayIntent>,
    applied_revision: Option<u64>,
    #[serde(default)]
    applied_bandwidth_limit_bps: Option<u64>,
    #[serde(default)]
    base: Option<CachedBase>,
    #[serde(default)]
    base_applied_revision: Option<u64>,
}
pub(crate) struct NetworkManager {
    path: PathBuf,
    state: ManagerState,
    failure: Option<String>,
    runtime_verified: bool,
    runtime_base_fingerprint: Option<String>,
    forwarding_blocked: bool,
}
impl NetworkManager {
    pub(crate) fn load(config: &std::path::Path, identity: &IdentityState) -> Self {
        let path = config.with_file_name("network-manager.json");
        let node = identity.identity();
        let empty = ManagerState {
            schema_version: 1,
            node_id: node.node_id.clone(),
            node_public_key: node.public_key.clone(),
            network_id: None,
            supervisor_key: None,
            desired: None,
            applied_revision: None,
            applied_bandwidth_limit_bps: None,
            base: None,
            base_applied_revision: None,
        };
        let result = (|| -> Result<ManagerState, String> {
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && !identity.network_manager_required() =>
                {
                    return Ok(empty.clone());
                }
                Err(_) => {
                    return Err("network manager state unavailable; recover protected state".into());
                }
            };
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8 * 1024 * 1024 {
                return Err("network manager state rejected".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                    return Err("network manager state requires private ownership".into());
                }
            }
            let stored: ManagerState = serde_json::from_slice(
                &std::fs::read(&path).map_err(|_| "network manager state unreadable")?,
            )
            .map_err(|_| "network manager state corrupt; preserve it for recovery")?;
            if stored.schema_version != 1
                || stored.node_id != node.node_id
                || stored.node_public_key != node.public_key
            {
                return Err("network manager identity binding rejected".into());
            }
            if let Some(intent) = &stored.desired {
                if stored.network_id.as_deref() != Some(&intent.intent.network_id)
                    || intent.intent.target_node_id != node.node_id
                    || stored
                        .applied_revision
                        .is_some_and(|r| r > intent.intent.revision)
                {
                    return Err("network manager revision binding rejected".into());
                }
                lattice_crypto::verify_domain(
                    stored
                        .supervisor_key
                        .as_deref()
                        .ok_or("network manager authority pin missing")?,
                    lattice_protocol::NETWORK_INTENT_DOMAIN,
                    &intent.signature,
                    &intent.intent,
                )?;
            }
            if let Some(base) = &stored.base {
                lattice_crypto::verify(
                    &base.supervisor,
                    &base.signed.signature,
                    &base.signed.config,
                )?;
                lattice_network::validate_base_desired_config(&base.signed.config)?;
                if base.signed.config.node_id != node.node_id
                    || stored.network_id.as_deref() != Some(base.signed.config.network_id.as_str())
                    || stored.supervisor_key.as_deref() != Some(base.supervisor.as_str())
                    || stored
                        .base_applied_revision
                        .is_some_and(|r| r > base.signed.config.revision)
                {
                    return Err("stored Base Node binding rejected".into());
                }
            }
            Ok(stored)
        })();
        match result {
            Ok(state) => Self {
                path,
                state,
                failure: None,
                runtime_verified: false,
                runtime_base_fingerprint: None,
                forwarding_blocked: false,
            },
            Err(error) => Self {
                path,
                state: empty,
                failure: Some(error),
                runtime_verified: false,
                runtime_base_fingerprint: None,
                forwarding_blocked: false,
            },
        }
    }
    fn checked(&self) -> Result<(), String> {
        self.failure
            .as_ref()
            .map_or(Ok(()), |error| Err(error.clone()))
    }
    pub(crate) fn status(&self) -> NetworkManagerStatus {
        NetworkManagerStatus {
            owner_process_id: std::process::id(),
            desired_revision: self
                .state
                .desired
                .as_ref()
                .map(|p| p.intent.revision)
                .or_else(|| self.state.base.as_ref().map(|b| b.signed.config.revision))
                .unwrap_or(0),
            applied_revision: if self.runtime_verified {
                self.state.applied_revision
            } else if self.runtime_base_fingerprint.is_some() {
                self.state.base_applied_revision
            } else {
                None
            },
            interface_name: self
                .state
                .desired
                .as_ref()
                .map(|p| p.intent.interface_name.clone())
                .or_else(|| self.state.base.as_ref().map(|b| b.interface.clone())),
            error_code: self.failure.clone().or_else(|| {
                ((self.state.desired.is_some()
                    && !self.runtime_verified
                    && !self.forwarding_blocked)
                    || (self.state.base.is_some()
                        && self.runtime_base_fingerprint.is_none()
                        && self.state.desired.is_none()))
                .then(|| "network_apply_pending".into())
            }),
        }
    }
    async fn remember_base(
        &mut self,
        identity: &mut IdentityState,
        signed: &SignedNetworkDesiredConfig,
        supervisor: &str,
        transport: &str,
        interface: &str,
    ) -> Result<(), String> {
        self.checked()?;
        lattice_crypto::verify(supervisor, &signed.signature, &signed.config)?;
        lattice_network::validate_base_desired_config(&signed.config)?;
        if signed.config.node_id != self.state.node_id
            || self
                .state
                .network_id
                .as_deref()
                .is_some_and(|n| n != signed.config.network_id)
            || self
                .state
                .supervisor_key
                .as_deref()
                .is_some_and(|p| p != supervisor)
        {
            return Err("Base Node authority binding rejected".into());
        }
        if let Some(previous) = &self.state.base {
            let mut old = previous.signed.config.clone();
            let mut new = signed.config.clone();
            old.issued_at_ms = 0;
            new.issued_at_ms = 0;
            old.status = lattice_protocol::NetworkNodeStatus::Allocated;
            new.status = lattice_protocol::NetworkNodeStatus::Allocated;
            if new.revision < old.revision
                || (new.revision == old.revision && new != old)
                || previous.transport != transport
                || previous.interface != interface
            {
                return Err(
                    "Base Node rollback, conflicting revision or transport owner rejected".into(),
                );
            }
            if old == new {
                return Ok(());
            }
        }
        if let Some(relay) = &self.state.desired {
            if signed.config.enabled
                && (signed.config.virtual_ipv4.as_deref() != Some(relay.intent.address.as_str())
                    || signed.config.overlay_cidr.as_deref()
                        != Some(relay.intent.overlay_cidr.as_str()))
            {
                return Err("Base Node plan conflicts with pinned Relay address".into());
            }
        }
        let mut next = self.state.clone();
        next.network_id = Some(signed.config.network_id.clone());
        next.supervisor_key = Some(supervisor.into());
        next.base = Some(CachedBase {
            signed: signed.clone(),
            supervisor: supervisor.into(),
            transport: transport.into(),
            interface: interface.into(),
        });
        next.base_applied_revision = None;
        identity.require_network_manager().await?;
        lattice_network::write_atomic_private(&self.path, &next)?;
        self.state = next;
        self.runtime_base_fingerprint = None;
        Ok(())
    }
    async fn remember_intent(
        &mut self,
        identity: &mut IdentityState,
        signed: &SignedGatewayIntent,
        validated: &lattice_network::ValidatedGateway,
    ) -> Result<(), String> {
        self.checked()?;
        if signed.intent != *validated.intent()
            || signed.intent.target_node_id != self.state.node_id
            || self
                .state
                .network_id
                .as_deref()
                .is_some_and(|n| n != signed.intent.network_id)
            || self
                .state
                .supervisor_key
                .as_deref()
                .is_some_and(|k| k != validated.authority().supervisor_key)
        {
            return Err("network manager authority binding rejected".into());
        }
        if let Some(previous) = &self.state.desired {
            if signed.intent.revision < previous.intent.revision
                || (signed.intent.revision == previous.intent.revision
                    && signed.intent != previous.intent)
            {
                return Err("network intent rollback or conflicting revision rejected".into());
            }
            if previous == signed {
                return Ok(());
            }
        }
        let mut next = self.state.clone();
        next.network_id = Some(signed.intent.network_id.clone());
        next.supervisor_key = Some(validated.authority().supervisor_key.clone());
        next.desired = Some(signed.clone());
        next.applied_revision = None;
        identity.require_network_manager().await?;
        lattice_network::write_atomic_private(&self.path, &next)?;
        self.state = next;
        self.runtime_verified = false;
        Ok(())
    }
}

pub(crate) async fn apply_base_configuration(
    s: &crate::AppState,
    signed: &SignedNetworkDesiredConfig,
    supervisor: &str,
    runner: Option<&dyn lattice_network::NetworkRunner>,
) -> Result<(), String> {
    if !s.config.read().await.network.enabled || !crate::setup::participation(s).await.accepted {
        return Err("network participation disabled by owner".into());
    }
    let identity = s.identity.read().await.clone();
    let coordinator = crate::network::select_coordinator(
        identity
            .bootstrap()
            .map(|t| (t.bootstrap_url.clone(), t.bootstrap_public_key.clone())),
        identity
            .trust()
            .map(|t| (t.control_url.clone(), t.control_public_key.clone())),
    )
    .ok_or("network coordinator is not pinned")?;
    if coordinator.public_key != supervisor {
        return Err("network authority pin mismatch".into());
    }
    let membership = {
        let store = s.offline_authority.lock().await;
        if let Some(cache) = store.checked()? {
            if cache.supervisor_key != supervisor || cache.network_id != signed.config.network_id {
                return Err("network configuration authority mismatch".into());
            }
            cache
                .require_membership(
                    &identity.identity().node_id,
                    &identity.identity().public_key,
                    crate::identity::unix_time_ms(),
                )
                .map(|_| ())
        } else if identity.offline_authority_required() {
            Err("offline authority must be recovered".into())
        } else {
            Ok(())
        }
    };
    if let Err(error) = membership {
        // Release the authority lock before entering the serialized OS boundary.
        disconnect(s, runner).await?;
        return Err(error);
    }
    let mut manager = s.network_manager.lock().await;
    manager.checked()?;
    if !s.config.read().await.network.enabled || !crate::setup::participation(s).await.accepted {
        return Err("network participation disabled by owner".into());
    }
    let old_journal = crate::network::load_journal(&s.network_journal_path).await;
    if (identity.network_manager_required() || old_journal.last_applied_revision > 0)
        && !s.network_key_path.exists()
    {
        return Err(
            "previous transport key missing; recover it before applying configuration".into(),
        );
    }
    let (private, public) =
        crate::network::load_or_create_wireguard_key(&s.network_key_path).await?;
    let transport = lattice_crypto::encode_wireguard_key(&public);
    let interface = crate::network::configured_interface_name();
    if manager.runtime_verified {
        if let Some(relay) = &manager.state.desired {
            let own = relay
                .intent
                .address
                .split('/')
                .next()
                .ok_or("Relay address required")?;
            if signed.config.gateway_ipv4.as_deref() == Some(own) {
                lattice_crypto::verify(supervisor, &signed.signature, &signed.config)?;
                let address = format!("{own}/32");
                let endpoint = match &relay.certificate.certificate.subject {
                    lattice_protocol::CertificateSubject::Relay { endpoint, .. } => endpoint,
                    _ => return Err("Relay capability required".into()),
                };
                if signed.config.schema_version != 1
                    || !signed.config.enabled
                    || signed.config.node_id != manager.state.node_id
                    || signed.config.network_id != relay.intent.network_id
                    || signed.config.gateway_wireguard_public_key.as_deref()
                        != Some(transport.as_str())
                    || signed.config.gateway_endpoint.as_deref() != Some(endpoint.as_str())
                    || !matches!(signed.config.virtual_ipv4.as_deref(), Some(a) if a == address || a == relay.intent.address)
                    || signed.config.overlay_cidr.as_deref()
                        != Some(relay.intent.overlay_cidr.as_str())
                    || signed.config.allowed_overlay_routes != [relay.intent.overlay_cidr.clone()]
                    || signed.config.keepalive_seconds > 600
                {
                    return Err(
                        "self-gateway configuration conflicts with the applied Relay binding"
                            .into(),
                    );
                }
                // The signed Relay plan already owns the complete peer set. Never create a self-peer.
                return Ok(());
            }
        }
    }
    let (rendered, _) =
        crate::network::render_current_config(&signed.config, &private, &s.network_peers_path)
            .await?;
    let plan = lattice_network::validate_base_configuration(
        &signed.config,
        &interface,
        &transport,
        &rendered,
    )?;
    manager
        .remember_base(
            &mut *s.identity.write().await,
            signed,
            supervisor,
            &transport,
            &interface,
        )
        .await?;
    // A Base Node synchronization cannot replace the peer set of an active Relay.
    if manager.runtime_verified && manager.state.desired.is_some() {
        return Ok(());
    }
    let fingerprint = lattice_crypto::sha256_hex(rendered.as_bytes());
    let path = s.config_path.with_file_name("network-transaction.json");
    if let Some(runner) = runner {
        lattice_network::apply_base(runner, &plan, &path).await?;
    } else {
        #[cfg(target_os = "linux")]
        lattice_network::apply_base(&lattice_network::SystemRunner, &plan, &path).await?;
        #[cfg(not(target_os = "linux"))]
        {
            let conf = crate::network::interface_conf_path(
                s.config_path
                    .parent()
                    .ok_or("network state directory required")?,
                &interface,
            );
            crate::network::apply_network_config(
                &signed.config,
                &private,
                &s.network_peers_path,
                &conf,
            )
            .await?;
        }
    }
    let mut committed = manager.state.clone();
    committed.base_applied_revision = Some(signed.config.revision);
    lattice_network::write_atomic_private(&manager.path, &committed)?;
    manager.state = committed;
    manager.runtime_base_fingerprint = Some(fingerprint);
    let mut status = s.network_status.write().await;
    status.enabled = true;
    status.status = lattice_protocol::NetworkNodeStatus::Allocated;
    status.assigned_revision = signed.config.revision;
    status.applied_revision = signed.config.revision;
    status.virtual_ipv4 = signed.config.virtual_ipv4.clone();
    status.interface_name = Some(interface);
    status.gateway_endpoint = signed.config.gateway_endpoint.clone();
    status.last_error = None;
    status.error_code = None;
    Ok(())
}
pub(crate) async fn restore_cached_base(
    s: &crate::AppState,
    runner: Option<&dyn lattice_network::NetworkRunner>,
) -> Result<(), String> {
    let base = {
        let manager = s.network_manager.lock().await;
        manager.checked()?;
        manager.state.base.clone()
    };
    if let Some(base) = base {
        if base.signed.config.enabled {
            apply_base_configuration(s, &base.signed, &base.supervisor, runner).await?;
        }
    }
    Ok(())
}

pub(crate) async fn submit_gateway(
    s: &crate::AppState,
    signed: lattice_protocol::SignedGatewayIntent,
    runner: &dyn lattice_network::NetworkRunner,
) -> Result<lattice_protocol::NetworkManagerStatus, String> {
    if !s.config.read().await.network.enabled || !crate::setup::participation(s).await.accepted {
        return Err("network participation disabled by owner".into());
    }
    let modules = s.modules.lock().await;
    let owner_limit = modules
        .forwarding_budget()
        .ok_or("Relay forwarding budget is not enabled by the owner")?;
    let result = apply_gateway_configuration(s, signed, owner_limit, runner).await;
    drop(modules);
    result
}
async fn apply_gateway_configuration(
    s: &crate::AppState,
    signed: SignedGatewayIntent,
    owner_limit: u64,
    runner: &dyn lattice_network::NetworkRunner,
) -> Result<NetworkManagerStatus, String> {
    let identity = s.identity.read().await.clone();
    let mut manager = s.network_manager.lock().await;
    manager.checked()?;
    if !s.config.read().await.network.enabled || !crate::setup::participation(s).await.accepted {
        return Err("network participation disabled by owner".into());
    }
    let journal = crate::network::load_journal(&s.network_journal_path).await;
    if (identity.network_manager_required() || journal.last_applied_revision > 0)
        && !s.network_key_path.exists()
    {
        return Err(
            "previous transport key missing; recover it instead of generating a replacement".into(),
        );
    }
    let (private, public) =
        crate::network::load_or_create_wireguard_key(&s.network_key_path).await?;
    let public = lattice_crypto::encode_wireguard_key(&public);
    let interface = crate::network::configured_interface_name();
    let address = manager
        .state
        .desired
        .as_ref()
        .map(|p| p.intent.address.clone())
        .or(journal.virtual_ipv4.clone());
    let overlay = manager
        .state
        .desired
        .as_ref()
        .map(|p| p.intent.overlay_cidr.clone())
        .or(journal.overlay_cidr.clone());
    let binding = lattice_network::NetworkBinding {
        node_id: &identity.identity().node_id,
        node_public_key: &identity.identity().public_key,
        transport_public_key: &public,
        interface_name: &interface,
        address: address.as_deref(),
        overlay_cidr: overlay.as_deref(),
    };
    {
        let store = s.offline_authority.lock().await;
        lattice_network::validate_gateway_intent(
            store.checked()?.ok_or("Supervisor authority required")?,
            &signed,
            &binding,
            crate::identity::unix_time_ms(),
        )?;
    }
    crate::trust_store::ingest(
        s,
        &lattice_protocol::AuthorityContext {
            relay_certificate: Some(signed.certificate.clone()),
            ..Default::default()
        },
    )
    .await?;
    let plan = {
        let store = s.offline_authority.lock().await;
        lattice_network::validate_gateway_intent(
            store.checked()?.ok_or("Supervisor authority required")?,
            &signed,
            &binding,
            crate::identity::unix_time_ms(),
        )?
    };
    manager
        .remember_intent(&mut *s.identity.write().await, &signed, &plan)
        .await?;
    if manager.runtime_verified
        && manager.state.applied_revision == Some(signed.intent.revision)
        && manager.state.applied_bandwidth_limit_bps == Some(owner_limit)
    {
        return Ok(manager.status());
    }
    manager.runtime_verified = false;
    let applied = lattice_network::apply_gateway(
        runner,
        &plan,
        &private,
        owner_limit,
        &s.config_path.with_file_name("network-transaction.json"),
    )
    .await?;
    let mut committed = manager.state.clone();
    committed.applied_revision = Some(applied.revision);
    committed.applied_bandwidth_limit_bps = Some(owner_limit);
    lattice_network::write_atomic_private(&manager.path, &committed)?;
    manager.state = committed;
    manager.runtime_verified = true;
    manager.forwarding_blocked = false;
    Ok(manager.status())
}

pub(crate) async fn disconnect(
    s: &crate::AppState,
    runner: Option<&dyn lattice_network::NetworkRunner>,
) -> Result<(), String> {
    let mut manager = s.network_manager.lock().await;
    manager.checked()?;
    let relay = manager.state.desired.as_ref();
    let base = manager.state.base.as_ref();
    let journal = crate::network::load_journal(&s.network_journal_path).await;
    let interface = relay
        .map(|p| p.intent.interface_name.clone())
        .or_else(|| base.map(|b| b.interface.clone()))
        .unwrap_or_else(crate::network::configured_interface_name);
    let overlay = relay
        .map(|p| p.intent.overlay_cidr.clone())
        .or_else(|| base.and_then(|b| b.signed.config.overlay_cidr.clone()))
        .or(journal.overlay_cidr);
    let Some(overlay) = overlay else {
        return Ok(());
    };
    if !s.network_key_path.exists() {
        return Err("transport key must be recovered before disconnect".into());
    }
    let (_, public) = crate::network::load_or_create_wireguard_key(&s.network_key_path).await?;
    let transport = lattice_crypto::encode_wireguard_key(&public);
    if relay.is_some_and(|p| p.intent.transport_public_key != transport)
        || base.is_some_and(|b| b.transport != transport)
    {
        return Err("disconnect transport owner mismatch".into());
    }
    manager.runtime_verified = false;
    manager.runtime_base_fingerprint = None;
    let mut next = manager.state.clone();
    next.applied_revision = None;
    next.base_applied_revision = None;
    next.applied_bandwidth_limit_bps = None;
    lattice_network::write_atomic_private(&manager.path, &next)?;
    manager.state = next;
    if let Some(runner) = runner {
        lattice_network::disconnect_owned(runner, &interface, &transport, &overlay).await?;
    } else {
        #[cfg(target_os = "linux")]
        lattice_network::disconnect_owned(
            &lattice_network::SystemRunner,
            &interface,
            &transport,
            &overlay,
        )
        .await?;
        #[cfg(not(target_os = "linux"))]
        crate::network::teardown_network_interface(&s.network_journal_path).await?;
    }
    manager.forwarding_blocked = true;
    Ok(())
}
pub(crate) async fn remember_disabled(
    s: &crate::AppState,
    signed: &SignedNetworkDesiredConfig,
    pin: &str,
) -> Result<(), String> {
    if signed.config.enabled {
        return Err("disabled network configuration required".into());
    }
    let identity = s.identity.read().await.clone();
    let expected = identity
        .bootstrap()
        .map(|b| b.bootstrap_public_key.as_str())
        .or_else(|| identity.trust().map(|t| t.control_public_key.as_str()))
        .ok_or("network coordinator is not pinned")?;
    if expected != pin {
        return Err("network authority pin mismatch".into());
    }
    let mut manager = s.network_manager.lock().await;
    let interface = crate::network::configured_interface_name();
    let transport = if let Some(base) = &manager.state.base {
        base.transport.clone()
    } else if let Some(relay) = &manager.state.desired {
        relay.intent.transport_public_key.clone()
    } else if s.network_key_path.exists() {
        let (_, public) = crate::network::load_or_create_wireguard_key(&s.network_key_path).await?;
        lattice_crypto::encode_wireguard_key(&public)
    } else {
        return Ok(());
    };
    manager
        .remember_base(
            &mut *s.identity.write().await,
            signed,
            pin,
            &transport,
            &interface,
        )
        .await
}

pub(crate) async fn withdraw_relay(
    s: &crate::AppState,
    runner: &dyn lattice_network::NetworkRunner,
) -> Result<(), String> {
    let mut manager = s.network_manager.lock().await;
    manager.checked()?;
    if manager.forwarding_blocked {
        return Ok(());
    }
    let Some(intent) = manager.state.desired.clone() else {
        return Ok(());
    };
    manager.runtime_verified = false;
    manager.runtime_base_fingerprint = None;
    let mut next = manager.state.clone();
    next.applied_revision = None;
    next.applied_bandwidth_limit_bps = None;
    lattice_network::write_atomic_private(&manager.path, &next)?;
    manager.state = next;
    lattice_network::withdraw_forwarding(
        runner,
        &intent.intent.interface_name,
        &intent.intent.transport_public_key,
        &intent.intent.overlay_cidr,
    )
    .await?;
    manager.forwarding_blocked = true;
    Ok(())
}
/// The caller holds the module consent lock throughout apply, serializing opt-out with forwarding.
pub(crate) async fn reconcile_relay(
    s: &crate::AppState,
    budget: Option<u64>,
    runner: &dyn lattice_network::NetworkRunner,
) -> Result<NetworkManagerStatus, String> {
    let Some(budget) = budget else {
        withdraw_relay(s, runner).await?;
        return Err("owner_forwarding_budget_required".into());
    };
    let desired = {
        let manager = s.network_manager.lock().await;
        manager.checked()?;
        manager.state.desired.clone()
    };
    let Some(desired) = desired else {
        return Err("forwarding_intent_required".into());
    };
    apply_gateway_configuration(s, desired, budget, runner).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityState;
    use lattice_crypto::{authority::issue_certificate, authority_cache::AuthorityCache, *};
    use lattice_protocol::*;
    use std::collections::BTreeSet;
    fn public(seed: u8) -> String {
        encode_key(&public_key(&[seed; 32]))
    }
    fn transport(seed: u8) -> String {
        encode_wireguard_key(&wireguard_public_key(&[seed; 32]))
    }
    async fn fixture() -> (
        tempfile::TempDir,
        IdentityState,
        AuthorityCache,
        SignedGatewayIntent,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let identity = IdentityState::load_or_create(directory.path().join("identity.json"))
            .await
            .unwrap();
        let node = identity.identity();
        let mut authority = AuthorityCache::new(public(1), "network-test".into());
        let membership = issue_certificate(
            &[1; 32],
            "network-test",
            CertificateSubject::Membership {
                node_id: node.node_id.clone(),
                node_public_key: node.public_key.clone(),
                terms_version: PARTICIPATION_VERSION.into(),
                terms_sha256: PARTICIPATION_SHA256.into(),
            },
            BTreeSet::new(),
            1,
            1000,
        )
        .unwrap();
        authority
            .ingest(
                &AuthorityContext {
                    membership_certificate: Some(membership),
                    ..Default::default()
                },
                1000,
            )
            .unwrap();
        let certificate = issue_certificate(
            &[1; 32],
            "network-test",
            CertificateSubject::Relay {
                node_id: node.node_id.clone(),
                node_public_key: node.public_key.clone(),
                transport_public_key: transport(4),
                overlay_ipv4: "10.77.0.4".into(),
                endpoint: "198.51.100.1:51820".into(),
                bandwidth_limit_bps: 8_000_000,
            },
            BTreeSet::from([CommandScope::NetworkForwarding]),
            1,
            1000,
        )
        .unwrap();
        let intent = GatewayIntent {
            schema_version: AUTHORITY_VERSION,
            network_id: "network-test".into(),
            target_node_id: node.node_id.clone(),
            revision: 2,
            interface_name: "lattice0".into(),
            address: "10.77.0.4/32".into(),
            overlay_cidr: "10.77.0.0/16".into(),
            listen_port: 51820,
            transport_public_key: transport(4),
            peers: vec![],
        };
        let signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &intent).unwrap();
        (
            directory,
            identity,
            authority,
            SignedGatewayIntent {
                intent,
                certificate,
                signature,
            },
        )
    }
    fn validated(
        cache: &AuthorityCache,
        signed: &SignedGatewayIntent,
        identity: &IdentityState,
    ) -> lattice_network::ValidatedGateway {
        lattice_network::validate_gateway_intent(
            cache,
            signed,
            &lattice_network::NetworkBinding {
                node_id: &identity.identity().node_id,
                node_public_key: &identity.identity().public_key,
                transport_public_key: &transport(4),
                interface_name: "lattice0",
                address: Some("10.77.0.4/32"),
                overlay_cidr: Some("10.77.0.0/16"),
            },
            2000,
        )
        .unwrap()
    }
    fn base(identity: &IdentityState, revision: u64) -> SignedNetworkDesiredConfig {
        let config = NetworkDesiredConfig {
            schema_version: 1,
            node_id: identity.identity().node_id.clone(),
            control_id: "root-test".into(),
            network_id: "network-test".into(),
            revision,
            enabled: true,
            status: NetworkNodeStatus::Allocated,
            virtual_ipv4: Some("10.77.0.4/32".into()),
            overlay_cidr: Some("10.77.0.0/16".into()),
            gateway_ipv4: Some("10.77.0.1".into()),
            gateway_endpoint: Some("198.51.100.1:51820".into()),
            gateway_wireguard_public_key: Some(transport(5)),
            allowed_overlay_routes: vec!["10.77.0.0/16".into()],
            keepalive_seconds: 25,
            issued_at_ms: 1000,
        };
        SignedNetworkDesiredConfig {
            signature: sign(&[1; 32], &config).unwrap(),
            config,
        }
    }
    #[tokio::test]
    async fn base_plan_is_retained_offline_and_conflicting_revisions_cannot_replace_it() {
        let (directory, mut identity, _, _) = fixture().await;
        let config = directory.path().join("node.json");
        let mut manager = NetworkManager::load(&config, &identity);
        let signed = base(&identity, 3);
        manager
            .remember_base(
                &mut identity,
                &signed,
                &public(1),
                &transport(4),
                "lattice0",
            )
            .await
            .unwrap();
        let mut restored = NetworkManager::load(&config, &identity);
        let saved = restored.state.base.as_ref().unwrap();
        assert_eq!(saved.signed, signed);
        assert_eq!(saved.transport, transport(4));
        assert_eq!(restored.status().applied_revision, None);
        for revision in [2, 3] {
            let mut other = base(&identity, revision);
            other.config.virtual_ipv4 = Some("10.77.0.9/32".into());
            other.signature = sign(&[1; 32], &other.config).unwrap();
            assert!(
                restored
                    .remember_base(&mut identity, &other, &public(1), &transport(4), "lattice0")
                    .await
                    .is_err()
            );
        }
        let mut refreshed = signed.clone();
        refreshed.config.issued_at_ms = 2000;
        refreshed.config.status = NetworkNodeStatus::Connected;
        refreshed.signature = sign(&[1; 32], &refreshed.config).unwrap();
        restored
            .remember_base(
                &mut identity,
                &refreshed,
                &public(1),
                &transport(4),
                "lattice0",
            )
            .await
            .unwrap();
    }
    struct RecordingRunner {
        transport: String,
        events: std::sync::Mutex<Vec<&'static str>>,
    }
    impl lattice_network::NetworkRunner for RecordingRunner {
        fn capture<'a>(
            &'a self,
            interface: &'a str,
            overlay: &'a str,
        ) -> lattice_network::NetworkFuture<'a, lattice_network::NetworkSnapshot> {
            Box::pin(async move {
                Ok(lattice_network::NetworkSnapshot {
                    interface_name: interface.into(),
                    overlay_cidr: overlay.into(),
                    existed: true,
                    link_up: true,
                    transport_public_key: Some(self.transport.clone()),
                    wireguard_config: Some("original private state".into()),
                    addresses: vec!["10.77.0.4/32".into()],
                    route: None,
                    forwarding: true,
                    owned_firewall: None,
                })
            })
        }
        fn execute<'a>(
            &'a self,
            command: lattice_network::NetworkCommand,
        ) -> lattice_network::NetworkFuture<'a, ()> {
            Box::pin(async move {
                self.events.lock().unwrap().push(command.kind());
                Ok(())
            })
        }
    }
    #[tokio::test]
    async fn restart_restores_cached_base_without_contacting_the_supervisor() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("node.json");
        let node = crate::load_state_at(config.clone()).await.unwrap();
        crate::setup::accept_participation(&node, PARTICIPATION_VERSION, PARTICIPATION_SHA256)
            .await
            .unwrap();
        node.config.write().await.network.enabled = true;
        crate::save_config(&config, &*node.config.read().await)
            .await
            .unwrap();
        node.identity
            .write()
            .await
            .set_bootstrap(BootstrapTrust {
                bootstrap_url: "http://127.0.0.1:1".into(),
                bootstrap_id: "root-test".into(),
                bootstrap_public_key: public(1),
                bootstrap_fingerprint: "test".into(),
                enrolled_at_ms: 1000,
            })
            .await
            .unwrap();
        let (_, key) = crate::network::load_or_create_wireguard_key(&node.network_key_path)
            .await
            .unwrap();
        let runner = RecordingRunner {
            transport: encode_wireguard_key(&key),
            events: Default::default(),
        };
        let signed = base(&*node.identity.read().await, 3);
        apply_base_configuration(&node, &signed, &public(1), Some(&runner))
            .await
            .unwrap();
        assert!(runner.events.lock().unwrap().contains(&"wireguard"));
        runner.events.lock().unwrap().clear();
        let restored = crate::load_state_at(config).await.unwrap();
        restore_cached_base(&restored, Some(&runner)).await.unwrap();
        assert!(
            runner.events.lock().unwrap().contains(&"wireguard"),
            "a reboot must reapply retained configuration before any HTTP exchange"
        );
        assert!(!runner.events.lock().unwrap().contains(&"forwarding"));
        assert_eq!(restored.network_status.read().await.applied_revision, 3);
        assert_eq!(
            restored.network_status.read().await.virtual_ipv4.as_deref(),
            Some("10.77.0.4/32")
        );
        assert_eq!(
            restored.identity.read().await.identity(),
            node.identity.read().await.identity()
        );
        runner.events.lock().unwrap().clear();
        disconnect(&restored, Some(&runner)).await.unwrap();
        assert_eq!(
            *runner.events.lock().unwrap(),
            vec!["firewall", "disconnect"]
        );
        assert_eq!(
            restored
                .network_manager
                .lock()
                .await
                .status()
                .applied_revision,
            None
        );
        assert_eq!(
            restored.identity.read().await.identity(),
            node.identity.read().await.identity()
        );
    }
    #[tokio::test]
    #[cfg(unix)]
    async fn relay_activation_and_revocation_use_manager_acknowledgments_without_changing_identity()
    {
        let (directory, _, cache, signed) = fixture().await;
        let mut signed = signed;
        signed.intent.interface_name = crate::network::configured_interface_name();
        signed.signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &signed.intent).unwrap();
        let node = crate::load_state_at(directory.path().join("node.json"))
            .await
            .unwrap();
        crate::setup::accept_participation(&node, PARTICIPATION_VERSION, PARTICIPATION_SHA256)
            .await
            .unwrap();
        node.config.write().await.network.enabled = true;
        node.identity
            .write()
            .await
            .set_bootstrap(BootstrapTrust {
                bootstrap_url: "http://127.0.0.1:1".into(),
                bootstrap_id: "root-test".into(),
                bootstrap_public_key: public(1),
                bootstrap_fingerprint: "test".into(),
                enrolled_at_ms: 1000,
            })
            .await
            .unwrap();
        node.offline_authority.lock().await.cache = Some(cache);
        lattice_network::write_atomic_private(&node.network_key_path,&serde_json::json!({"public_key":transport(4),"private_key_blob":encode_wireguard_key(&[4;32])})).unwrap();
        let original = node.identity.read().await.identity().clone();
        crate::modules::enable(
            &node,
            ModuleActivation {
                kind: ModuleKind::Relay,
                certificate: Some(signed.certificate.clone()),
                authority_data_dir: None,
                adopt_gateway: false,
                activation_token: None,
                forwarding_limit_bps: Some(4_000_000),
            },
            false,
        )
        .await
        .unwrap();
        let runner = RecordingRunner {
            transport: transport(4),
            events: Default::default(),
        };
        submit_gateway(&node, signed.clone(), &runner)
            .await
            .unwrap();
        crate::modules::reconcile_with_runner(&node, &runner).await;
        assert_eq!(
            node.modules
                .lock()
                .await
                .statuses()
                .into_iter()
                .find(|s| s.kind == ModuleKind::Relay)
                .unwrap()
                .state,
            ModuleState::Active
        );
        let mut host = base(&*node.identity.read().await, 3);
        host.config.gateway_ipv4 = Some("10.77.0.4".into());
        host.config.gateway_wireguard_public_key = Some(transport(4));
        host.signature = sign(&[1; 32], &host.config).unwrap();
        runner.events.lock().unwrap().clear();
        apply_base_configuration(&node, &host, &public(1), Some(&runner))
            .await
            .unwrap();
        assert!(
            runner.events.lock().unwrap().is_empty(),
            "self-gateway synchronization must not install a WireGuard peer to its own transport key"
        );
        let snapshot = AuthoritySnapshot {
            schema_version: AUTHORITY_VERSION,
            network_id: "network-test".into(),
            issuer_key_id: fingerprint(&public(1)).unwrap(),
            authority_epoch: 1,
            revision: 2,
            issued_at_ms: crate::identity::unix_time_ms(),
            certificates: vec![],
            revocations: std::collections::BTreeMap::from([(
                signed.certificate.certificate.subject.revocation_key(),
                1,
            )]),
        };
        let revoked = SignedAuthoritySnapshot {
            signature: sign_domain(&[1; 32], SNAPSHOT_DOMAIN, &snapshot).unwrap(),
            snapshot,
        };
        crate::trust_store::ingest(
            &node,
            &AuthorityContext {
                snapshot: Some(revoked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        runner.events.lock().unwrap().clear();
        crate::modules::reconcile_with_runner(&node, &runner).await;
        let status = node
            .modules
            .lock()
            .await
            .statuses()
            .into_iter()
            .find(|s| s.kind == ModuleKind::Relay)
            .unwrap();
        assert_eq!(status.state, ModuleState::Revoked);
        assert_eq!(*runner.events.lock().unwrap(), vec!["firewall"]);
        assert_eq!(
            node.network_manager.lock().await.status().applied_revision,
            None
        );
        assert_eq!(node.identity.read().await.identity(), &original);

        let base = base(&*node.identity.read().await, 3);
        apply_base_configuration(&node, &base, &public(1), Some(&runner))
            .await
            .unwrap();
        let snapshot = AuthoritySnapshot {
            schema_version: AUTHORITY_VERSION,
            network_id: "network-test".into(),
            issuer_key_id: fingerprint(&public(1)).unwrap(),
            authority_epoch: 1,
            revision: 3,
            issued_at_ms: crate::identity::unix_time_ms(),
            certificates: vec![],
            revocations: std::collections::BTreeMap::from([
                (signed.certificate.certificate.subject.revocation_key(), 1),
                (format!("node/{}", original.node_id), 1),
            ]),
        };
        let revoked = SignedAuthoritySnapshot {
            signature: sign_domain(&[1; 32], SNAPSHOT_DOMAIN, &snapshot).unwrap(),
            snapshot,
        };
        crate::trust_store::ingest(
            &node,
            &AuthorityContext {
                snapshot: Some(revoked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        runner.events.lock().unwrap().clear();
        assert!(restore_cached_base(&node, Some(&runner)).await.is_err());
        assert!(
            runner.events.lock().unwrap().contains(&"disconnect"),
            "a known membership revocation must remove the cached transport plane"
        );
    }
    #[tokio::test]
    async fn intent_high_water_survives_restart_and_rejects_conflicting_equal_revision() {
        let (directory, mut identity, cache, signed) = fixture().await;
        let config = directory.path().join("node.json");
        let mut manager = NetworkManager::load(&config, &identity);
        let plan = validated(&cache, &signed, &identity);
        manager
            .remember_intent(&mut identity, &signed, &plan)
            .await
            .unwrap();
        assert_eq!(manager.status().desired_revision, 2);
        assert_eq!(manager.status().applied_revision, None);
        let mut restored = NetworkManager::load(&config, &identity);
        let mut older = signed.clone();
        older.intent.revision = 1;
        older.signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &older.intent).unwrap();
        let plan = validated(&cache, &older, &identity);
        assert!(
            restored
                .remember_intent(&mut identity, &older, &plan)
                .await
                .is_err()
        );
        let mut conflicting = signed.clone();
        conflicting.intent.peers.push(NetworkPeerIntent {
            node_id: "peer-one".into(),
            public_key: transport(5),
            allowed_ipv4: "10.77.0.6/32".into(),
            endpoint: None,
        });
        conflicting.signature =
            sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &conflicting.intent).unwrap();
        let plan = validated(&cache, &conflicting, &identity);
        assert!(
            restored
                .remember_intent(&mut identity, &conflicting, &plan)
                .await
                .is_err()
        );
        assert_eq!(
            NetworkManager::load(&config, &identity)
                .status()
                .desired_revision,
            2
        );
    }
    #[tokio::test]
    async fn a_missing_manager_store_after_first_use_cannot_reset_intent_replay_protection() {
        let (directory, mut identity, cache, signed) = fixture().await;
        let config = directory.path().join("node.json");
        let plan = validated(&cache, &signed, &identity);
        let mut manager = NetworkManager::load(&config, &identity);
        manager
            .remember_intent(&mut identity, &signed, &plan)
            .await
            .unwrap();
        let node = identity.identity().clone();
        assert!(identity.network_manager_required());
        std::fs::remove_file(config.with_file_name("network-manager.json")).unwrap();
        let mut recovered = IdentityState::load_or_create(directory.path().join("identity.json"))
            .await
            .unwrap();
        let mut damaged = NetworkManager::load(&config, &recovered);
        assert!(
            damaged
                .remember_intent(&mut recovered, &signed, &plan)
                .await
                .is_err()
        );
        assert_eq!(recovered.identity(), &node);
    }
    #[tokio::test]
    async fn a_signed_gateway_plan_cannot_activate_forwarding_without_owner_opt_in() {
        let (directory, _identity, cache, signed) = fixture().await;
        let node = crate::load_state_at(directory.path().join("node.json"))
            .await
            .unwrap();
        crate::setup::accept_participation(&node, PARTICIPATION_VERSION, PARTICIPATION_SHA256)
            .await
            .unwrap();
        node.config.write().await.network.enabled = true;
        node.offline_authority.lock().await.cache = Some(cache);
        let result = submit_gateway(&node, signed, &lattice_network::SystemRunner).await;
        assert!(
            result.is_err_and(|e| e.contains("owner")),
            "a Supervisor signature cannot replace host consent"
        );
        assert!(!node.identity.read().await.network_manager_required());
        assert!(
            !node.network_key_path.exists(),
            "denied role activation must not initialize a transport key"
        );
    }
}
