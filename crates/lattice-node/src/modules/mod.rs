use lattice_protocol::*;
pub(crate) mod ingress;
mod process;
use crate::{AppState, identity::unix_time_ms};
use lattice_crypto::authority_cache::AuthorityCache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleRecord {
    enabled: bool,
    certificate_id: Option<String>,
    authority_data_dir: Option<PathBuf>,
    adopt_gateway: bool,
}
#[derive(Default)]
pub(crate) struct ModuleManager {
    records: BTreeMap<ModuleKind, ModuleRecord>,
    status: BTreeMap<ModuleKind, ModuleStatus>,
    children: BTreeMap<ModuleKind, process::ModuleChild>,
    fatal: Option<String>,
    ingress_ready: bool,
    ingress_error: Option<String>,
}
impl ModuleManager {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let records = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| "module state corrupt")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_) => return Err("module state unavailable".into()),
        };
        Ok(Self {
            records,
            ..Default::default()
        })
    }
    pub(crate) fn damaged(error: String) -> Self {
        Self {
            fatal: Some(error),
            ..Default::default()
        }
    }
    fn save(&self, path: &Path) -> Result<(), String> {
        crate::setup::write_private(path, &self.records).map_err(|e| e.to_string())
    }
    pub(crate) fn statuses(&self) -> Vec<ModuleStatus> {
        [
            ModuleKind::Master,
            ModuleKind::Relay,
            ModuleKind::Supervisor,
        ]
        .into_iter()
        .map(|kind| {
            let mut status = self.status.get(&kind).cloned().unwrap_or_else(|| {
                let record = self.records.get(&kind);
                let enabled = record.is_some_and(|r| r.enabled);
                ModuleStatus {
                    kind,
                    enabled,
                    state: if self.fatal.is_some() {
                        ModuleState::Failed
                    } else if enabled {
                        ModuleState::Verifying
                    } else {
                        ModuleState::Disabled
                    },
                    process_id: None,
                    certificate_id: record.and_then(|r| r.certificate_id.clone()),
                    error_code: self.fatal.clone(),
                }
            });
            if status.enabled
                && !self.ingress_ready
                && matches!(status.state, ModuleState::Active | ModuleState::Starting)
            {
                status.state = ModuleState::Starting;
                status.error_code = Some(
                    self.ingress_error
                        .clone()
                        .unwrap_or_else(|| "ingress_starting".into()),
                );
            }
            status
        })
        .collect()
    }
    fn set_enabled(
        &mut self,
        kind: ModuleKind,
        certificate_id: Option<String>,
        authority_data_dir: Option<PathBuf>,
        adopt_gateway: bool,
    ) {
        self.records.insert(
            kind,
            ModuleRecord {
                enabled: true,
                certificate_id,
                authority_data_dir,
                adopt_gateway,
            },
        );
        self.status.remove(&kind);
    }
    fn fail(&mut self, kind: ModuleKind, state: ModuleState, error: &str) {
        self.status.insert(
            kind,
            ModuleStatus {
                kind,
                enabled: self.records.get(&kind).is_some_and(|r| r.enabled),
                state,
                process_id: None,
                certificate_id: self
                    .records
                    .get(&kind)
                    .and_then(|r| r.certificate_id.clone()),
                error_code: Some(error.into()),
            },
        );
    }
}

#[derive(Deserialize)]
struct ControlIdentity {
    control_id: String,
    public_key: String,
    private_key: String,
}
fn control_identity(data: &Path) -> Result<ControlIdentity, String> {
    let value: ControlIdentity = serde_json::from_slice(
        &std::fs::read(data.join("control-identity.json"))
            .map_err(|_| "control identity unavailable")?,
    )
    .map_err(|_| "control identity corrupt")?;
    let secret = lattice_crypto::decode_key::<32>(&value.private_key)?;
    if lattice_crypto::encode_key(&lattice_crypto::public_key(&secret)) != value.public_key {
        return Err("control identity key mismatch".into());
    }
    Ok(value)
}
fn authority_directory(input: &str) -> Result<PathBuf, String> {
    let path = Path::new(input);
    if !path.is_absolute() {
        return Err("absolute authority data directory required".into());
    }
    let path = std::fs::canonicalize(path).map_err(|_| "authority directory unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(&path).map_err(|_| "authority directory unavailable")?;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err("authority directory requires private administrator ownership".into());
        }
    }
    for name in ["control-identity.json", "account.json", "network.json"] {
        let meta = std::fs::symlink_metadata(path.join(name))
            .map_err(|_| "provision the existing Supervisor authority first")?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("invalid authority provisioning file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
                return Err("authority files require private administrator ownership".into());
            }
        }
    }
    // Only the authority service reads and validates its signing key and owner account.
    Ok(path)
}
fn default_master_data(s: &AppState) -> PathBuf {
    crate::setup::master_dir(s)
}
fn state_path(s: &AppState) -> PathBuf {
    s.config_path.with_file_name("modules.json")
}
pub(crate) async fn enable(
    s: &Arc<AppState>,
    a: ModuleActivation,
    administrator: bool,
) -> Result<Vec<ModuleStatus>, String> {
    if (a.kind == ModuleKind::Supervisor || a.adopt_gateway) && !administrator {
        return Err(
            "administrator authorization required for authority provisioning or gateway adoption"
                .into(),
        );
    }
    if let Some(error) = &s.modules.lock().await.fatal {
        return Err(error.clone());
    }
    if !crate::setup::participation(s).await.accepted {
        return Err("accept participation terms before enabling a module".into());
    }
    let source = if a.kind == ModuleKind::Supervisor {
        Some(authority_directory(
            a.authority_data_dir
                .as_deref()
                .ok_or("Supervisor authority directory required")?,
        )?)
    } else {
        if a.authority_data_dir.is_some() {
            return Err("authority data directory is only valid for Supervisor".into());
        }
        None
    };
    if let Some(c) = &a.certificate {
        let context = match a.kind {
            ModuleKind::Master => AuthorityContext {
                master_certificate: Some(c.clone()),
                ..Default::default()
            },
            ModuleKind::Relay => AuthorityContext {
                relay_certificate: Some(c.clone()),
                ..Default::default()
            },
            ModuleKind::Supervisor => {
                return Err(
                    "Supervisor authority cannot be supplied by a capability certificate".into(),
                );
            }
        };
        crate::trust_store::ingest(s, &context).await?;
    }
    let pending = a.kind == ModuleKind::Master && a.activation_token.is_some();
    let certificate_id = if pending {
        let bootstrap = s
            .identity
            .read()
            .await
            .bootstrap()
            .cloned()
            .ok_or("join the network before activating Master")?;
        crate::setup::begin(
            s.clone(),
            SetupOptions {
                role: NodeRole::Master,
                bootstrap_url: bootstrap.bootstrap_url,
                master_token: a.activation_token,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        None
    } else if a.kind != ModuleKind::Supervisor {
        if a.activation_token.is_some() {
            return Err("activation tokens apply only to Master".into());
        }
        let id = s.identity.read().await.clone();
        let store = s.offline_authority.lock().await;
        let cache = store
            .checked()?
            .ok_or("synchronize Supervisor authority first")?;
        Some(
            validate_grant(
                a.kind,
                &id.identity().node_id,
                &id.identity().public_key,
                cache,
                unix_time_ms(),
            )?
            .certificate
            .certificate_id
            .clone(),
        )
    } else {
        None
    };
    let mut manager = s.modules.lock().await;
    if let Some(e) = &manager.fatal {
        return Err(e.clone());
    }
    let old = manager.records.clone();
    let status = manager.status.clone();
    manager.set_enabled(a.kind, certificate_id, source, a.adopt_gateway);
    if let Err(e) = manager.save(&state_path(s)) {
        manager.records = old;
        manager.status = status;
        return Err(e);
    }
    Ok(manager.statuses())
}
pub(crate) async fn disable(s: &AppState, kind: ModuleKind) -> Result<Vec<ModuleStatus>, String> {
    let mut manager = s.modules.lock().await;
    if let Some(e) = &manager.fatal {
        return Err(e.clone());
    }
    let old = manager.records.clone();
    if let Some(record) = manager.records.get_mut(&kind) {
        record.enabled = false;
    }
    if let Err(e) = manager.save(&state_path(s)) {
        manager.records = old;
        return Err(e);
    }
    if let Some(mut child) = manager.children.remove(&kind) {
        child.stop().await?;
    }
    manager.status.remove(&kind);
    Ok(manager.statuses())
}
pub(crate) fn private_client(data: &Path) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(2))
        .read_timeout(std::time::Duration::from_secs(120));
    #[cfg(unix)]
    let builder = builder.unix_socket(data.join("module-http.sock"));
    #[cfg(windows)]
    let builder = builder.windows_named_pipe(process::private_pipe(data));
    builder
        .build()
        .map_err(|_| "private module transport unavailable".into())
}
pub(crate) async fn run(s: Arc<AppState>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            _=tick.tick()=>{reconcile(&s).await;},
            result=shutdown.changed()=>{if result.is_err() || *shutdown.borrow(){break;}},
        }
    }
    let mut manager = s.modules.lock().await;
    for child in manager.children.values_mut() {
        let _ = child.stop().await;
    }
    manager.children.clear();
}
async fn reconcile(s: &Arc<AppState>) {
    let identity = s.identity.read().await.clone();
    let cache = s
        .offline_authority
        .lock()
        .await
        .checked()
        .ok()
        .flatten()
        .cloned();
    let config = s.config.read().await.clone();
    let bundle = match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        Some(p) => p,
        None => return,
    };
    let mut manager = s.modules.lock().await;
    if manager.fatal.is_some() {
        return;
    }
    for kind in [
        ModuleKind::Master,
        ModuleKind::Relay,
        ModuleKind::Supervisor,
    ] {
        let Some(record) = manager.records.get(&kind).filter(|r| r.enabled).cloned() else {
            continue;
        };
        let validation = (|| -> Result<(PathBuf, Option<String>), String> {
            if kind == ModuleKind::Supervisor {
                let path = record
                    .authority_data_dir
                    .as_ref()
                    .ok_or("Supervisor provisioning required")?;
                return Ok((authority_directory(&path.to_string_lossy())?, None));
            }
            if !config.network.enabled {
                return Err("network_disabled_by_owner".into());
            }
            let cache = cache.as_ref().ok_or("certified_authority_unavailable")?;
            let c = validate_grant(
                kind,
                &identity.identity().node_id,
                &identity.identity().public_key,
                cache,
                unix_time_ms(),
            )?;
            let data = default_master_data(s);
            if kind == ModuleKind::Master {
                let control = control_identity(&data)?;
                if !matches!(&c.certificate.subject,CertificateSubject::Master{control_id,control_public_key,..} if control_id==&control.control_id && control_public_key==&control.public_key)
                {
                    return Err("master_control_identity_mismatch".into());
                }
                synchronize_master_authority(&data, &identity, cache)?;
            }
            Ok((data, Some(c.certificate.certificate_id.clone())))
        })();
        let (data, certificate_id) = match validation {
            Ok(value) => value,
            Err(e) => {
                if let Some(mut child) = manager.children.remove(&kind) {
                    let _ = child.stop().await;
                }
                manager.fail(
                    kind,
                    if e == "certificate revoked" {
                        ModuleState::Revoked
                    } else {
                        ModuleState::Suspended
                    },
                    &e,
                );
                continue;
            }
        };
        if kind == ModuleKind::Relay {
            manager.fail(kind, ModuleState::Starting, "forwarding_intent_required");
            continue;
        }
        if manager
            .children
            .get_mut(&kind)
            .is_some_and(|c| c.exited().unwrap_or(true))
        {
            manager.children.remove(&kind);
            manager.fail(kind, ModuleState::Failed, "module_process_exited");
        }
        if !manager.children.contains_key(&kind) {
            let start = (|| -> Result<process::ModuleChild, String> {
                if kind == ModuleKind::Master {
                    let token = data.join("module-operator-token.json");
                    if !token.exists() {
                        crate::setup::write_private(
                            &token,
                            &format!(
                                "{}{}",
                                uuid::Uuid::new_v4().simple(),
                                uuid::Uuid::new_v4().simple()
                            ),
                        )
                        .map_err(|e| e.to_string())?;
                    }
                }
                process::VerifiedComponent::load(&bundle, kind)?.spawn(
                    &data,
                    config
                        .bootstrap_url
                        .as_deref()
                        .unwrap_or("http://127.0.0.1:7443"),
                )
            })();
            match start {
                Ok(child) => {
                    manager.children.insert(kind, child);
                }
                Err(e) => {
                    manager.fail(kind, ModuleState::Failed, &e);
                    continue;
                }
            }
        }
        let healthy = match private_client(&data) {
            Ok(client) => tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.get("http://localhost/health").send(),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|r| r.status().is_success()),
            Err(_) => false,
        };
        let pid = manager.children.get(&kind).and_then(|c| c.id());
        manager.status.insert(
            kind,
            ModuleStatus {
                kind,
                enabled: true,
                state: if healthy {
                    ModuleState::Active
                } else {
                    ModuleState::Starting
                },
                process_id: pid,
                certificate_id,
                error_code: (!healthy).then(|| "module_backend_starting".into()),
            },
        );
    }
}
pub(crate) fn current_master_context(
    identity: &crate::identity::IdentityState,
    cache: &AuthorityCache,
) -> Result<AuthorityContext, String> {
    let id = identity.identity();
    let now = unix_time_ms();
    let certificate =
        validate_grant(ModuleKind::Master, &id.node_id, &id.public_key, cache, now)?.clone();
    let membership = cache
        .require_membership(&id.node_id, &id.public_key, now)?
        .clone();
    Ok(AuthorityContext {
        snapshot: cache.snapshot().cloned(),
        master_certificate: Some(certificate),
        membership_certificate: Some(membership),
        relay_certificate: None,
    })
}
fn synchronize_master_authority(
    data: &Path,
    identity: &crate::identity::IdentityState,
    cache: &AuthorityCache,
) -> Result<(), String> {
    let path = data.join("master-authority.json");
    let mut authority: MasterAuthority = serde_json::from_slice(
        &std::fs::read(&path).map_err(|_| "Master activation record unavailable")?,
    )
    .map_err(|_| "Master activation record corrupt")?;
    let context = current_master_context(identity, cache)?;
    let cert = context
        .master_certificate
        .as_ref()
        .ok_or("Master certificate unavailable")?;
    if authority.coordinator_key != cache.supervisor_key || authority.network_id != cache.network_id
    {
        return Err("Master authority pin mismatch".into());
    }
    lattice_crypto::verify(
        &cache.supervisor_key,
        &authority.grant.signature,
        &authority.grant.grant,
    )?;
    let g = &authority.grant.grant;
    if !matches!(&cert.certificate.subject, CertificateSubject::Master {node_id,node_public_key,control_id,control_public_key,overlay_ipv4}
        if node_id==&g.node_id && node_public_key==&g.node_public_key && control_id==&g.control_id && control_public_key==&g.control_public_key && overlay_ipv4==&g.overlay_ipv4)
        || g.network_id != cache.network_id
    {
        return Err("Master activation identity mismatch".into());
    }
    if authority.authority.as_ref() != Some(&context) {
        authority.authority = Some(context);
        crate::setup::write_private(&path, &authority).map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub(crate) async fn local_master(
    s: &AppState,
    request: LocalMasterRequest,
) -> Result<LocalMasterReply, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    if !s.config.read().await.network.enabled || !crate::setup::participation(s).await.accepted {
        return Err("network participation disabled by owner".into());
    }
    {
        let manager = s.modules.lock().await;
        if !manager
            .status
            .values()
            .any(|m| m.kind == ModuleKind::Master && m.enabled && m.state == ModuleState::Active)
        {
            return Err("local Master module is not active".into());
        }
    }
    let id = s.identity.read().await.clone();
    {
        let store = s.offline_authority.lock().await;
        let cache = store.checked()?.ok_or("authority unavailable")?;
        let certificate = validate_grant(
            ModuleKind::Master,
            &id.identity().node_id,
            &id.identity().public_key,
            cache,
            unix_time_ms(),
        )?;
        if let CertificateSubject::Master {
            control_id,
            control_public_key,
            ..
        } = &certificate.certificate.subject
        {
            for scope in request.operation.required_scopes() {
                cache.require_master(control_id, control_public_key, scope, unix_time_ms())?;
            }
        }
    }
    let (method, path) = match &request.operation {
        WorkloadOperation::FleetInventory => (reqwest::Method::GET, "/api/v1/master/fleet".into()),
        WorkloadOperation::ListJobs => (reqwest::Method::GET, "/api/v1/operator/jobs".into()),
        WorkloadOperation::ListRuntimes => {
            (reqwest::Method::GET, "/api/v1/operator/runtimes".into())
        }
        WorkloadOperation::ListArtifacts => {
            (reqwest::Method::GET, "/api/v1/operator/artifacts".into())
        }
        WorkloadOperation::QueueMining => {
            (reqwest::Method::POST, "/api/v1/operator/jobs/mining".into())
        }
        WorkloadOperation::ControlJob => (
            reqwest::Method::POST,
            "/api/v1/operator/jobs/control".into(),
        ),
        WorkloadOperation::CancelJob => {
            (reqwest::Method::POST, "/api/v1/operator/jobs/cancel".into())
        }
        WorkloadOperation::PublishRuntime {
            version,
            platform,
            architecture,
        } => {
            semver::Version::parse(version).map_err(|_| "invalid runtime version")?;
            let p = match platform {
                Platform::Linux => "linux",
                Platform::Macos => "macos",
                Platform::Windows => "windows",
                _ => return Err("unsupported runtime platform".into()),
            };
            let a = match architecture {
                Architecture::X86_64 => "x86_64",
                Architecture::Aarch64 => "aarch64",
                _ => return Err("unsupported runtime architecture".into()),
            };
            (
                reqwest::Method::POST,
                format!("/api/v1/operator/xmrig/runtimes/{version}/{p}/{a}"),
            )
        }
    };
    if request.body_base64.len() > 90 * 1024 * 1024 {
        return Err("local operation exceeds size limit".into());
    }
    let body = STANDARD
        .decode(request.body_base64)
        .map_err(|_| "invalid local operation body")?;
    if body.len() > 64 * 1024 * 1024 || (method == reqwest::Method::GET && !body.is_empty()) {
        return Err("invalid local operation body".into());
    }
    let data = default_master_data(s);
    let token: String = serde_json::from_slice(
        &std::fs::read(data.join("module-operator-token.json"))
            .map_err(|_| "private operator credential unavailable")?,
    )
    .map_err(|_| "private operator credential corrupt")?;
    let content_type = if matches!(request.operation, WorkloadOperation::PublishRuntime { .. }) {
        "application/octet-stream"
    } else {
        "application/json"
    };
    let mut response = private_client(&data)?
        .request(method, format!("http://localhost{path}"))
        .bearer_auth(token)
        .header("content-type", content_type)
        .body(body)
        .send()
        .await
        .map_err(|_| "local Master operation failed")?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "local Master response failed")?
    {
        if body.len() + chunk.len() > 64 * 1024 * 1024 {
            return Err("local Master response exceeds size limit".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(LocalMasterReply {
        status,
        content_type,
        body_base64: STANDARD.encode(body),
    })
}
fn validate_grant<'a>(
    kind: ModuleKind,
    node_id: &str,
    key: &str,
    cache: &'a AuthorityCache,
    now: u64,
) -> Result<&'a SignedCertificate, String> {
    let cert=match kind {
        ModuleKind::Master=>cache.certificates().find(|c|matches!(&c.certificate.subject,CertificateSubject::Master{node_id:id,node_public_key,..} if id==node_id && node_public_key==key))
            .ok_or_else(||"Master grant for this device required".to_string()).and_then(|c|match &c.certificate.subject{
                CertificateSubject::Master{control_id,control_public_key,..}=>cache.require_master(control_id,control_public_key,&CommandScope::Workloads,now),
                _=>unreachable!(),
            })?,
        ModuleKind::Relay=>cache.require_relay(node_id,key,now)?,
        ModuleKind::Supervisor=>return Err("Supervisor requires privileged authority provisioning".into()),
    };
    if cert.certificate.subject.node_id() != node_id
        || cert.certificate.subject.node_public_key() != key
    {
        return Err("module device identity mismatch".into());
    }
    Ok(cert)
}
#[cfg(test)]
mod tests;
