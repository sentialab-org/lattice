use crate::{
    AppState, enrollment,
    identity::{IdentityState, unix_time_ms},
    network,
};
use lattice_crypto::{decode_key, sign, verify};
use lattice_protocol::*;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::watch;
#[derive(Debug)]
pub enum SetupError {
    Preflight,
    Identity,
    Join,
    Allocation,
    Network,
    Activation,
    Timeout,
    Persistence,
}
impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "setup failed: {self:?}")
    }
}
impl std::error::Error for SetupError {}
pub struct NetworkEvidence {
    pub handshake_age_ms: Option<u64>,
    pub route_verified: bool,
    pub probe_success: bool,
}
pub fn evaluate_readiness(e: &NetworkEvidence, attached: bool) -> (bool, bool, SetupStage) {
    let ready =
        e.handshake_age_ms.is_some_and(|age| age <= 180_000) && e.route_verified && e.probe_success;
    (
        ready,
        ready && attached,
        if !ready {
            SetupStage::VerifyingNetwork
        } else if attached {
            SetupStage::Ready
        } else {
            SetupStage::WaitingForMaster
        },
    )
}
pub fn enable_network(c: &mut NodeConfig, url: &str) {
    c.network.enabled = true;
    c.bootstrap_url = Some(url.into());
}
pub fn durable_options(o: &SetupOptions) -> SetupOptions {
    SetupOptions {
        role: o.role,
        bootstrap_url: o.bootstrap_url.clone(),
        master_token: None,
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) struct SetupRuntime {
    #[serde(default)]
    public_joined: bool,
    options: Option<SetupOptions>,
    pub(crate) report: SetupReport,
}
impl SetupRuntime {
    pub(crate) fn is_managed(&self) -> bool {
        self.public_joined || self.options.is_some()
    }
    pub(crate) fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Self {
                public_joined: false,
                options: None,
                report: SetupReport::initial(NodeRole::Node),
            })
    }
}
fn state_path(s: &AppState) -> PathBuf {
    s.config_path.with_file_name("setup.json")
}
pub(crate) fn write_private<T: Serialize>(path: &Path, value: &T) -> Result<(), SetupError> {
    use std::io::Write;
    let parent = path.parent().ok_or(SetupError::Persistence)?;
    std::fs::create_dir_all(parent).map_err(|_| SetupError::Persistence)?;
    let temp = parent.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let result = (|| {
        let mut f = o.open(&temp).map_err(|_| SetupError::Persistence)?;
        f.write_all(&serde_json::to_vec(value).map_err(|_| SetupError::Persistence)?)
            .and_then(|_| f.sync_all())
            .map_err(|_| SetupError::Persistence)?;
        std::fs::rename(&temp, path).map_err(|_| SetupError::Persistence)?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| SetupError::Persistence)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
fn persist(s: &AppState, r: &SetupRuntime) -> Result<(), SetupError> {
    let stored = SetupRuntime {
        public_joined: r.public_joined,
        options: r.options.as_ref().map(durable_options),
        report: r.report.clone(),
    };
    write_private(&state_path(s), &stored)
}
pub(crate) async fn begin(
    s: Arc<AppState>,
    mut o: SetupOptions,
) -> Result<SetupReport, SetupError> {
    o.bootstrap_url =
        enrollment::normalize_bootstrap_url(&o.bootstrap_url).map_err(|_| SetupError::Preflight)?;
    if let Some(t) = s.identity.read().await.bootstrap() {
        if t.bootstrap_url != o.bootstrap_url {
            return Err(SetupError::Identity);
        }
    }
    {
        let mut config = s.config.write().await;
        enable_network(&mut config, &o.bootstrap_url);
        crate::save_config(&s.config_path, &config)
            .await
            .map_err(|_| SetupError::Persistence)?;
    }
    let mut r = s.setup.lock().await;
    r.public_joined = false;
    r.options = Some(o.clone());
    r.report = SetupReport::initial(o.role);
    persist(&s, &r)?;
    Ok(r.report.clone())
}
pub(crate) async fn suspend(s: &AppState) -> Result<(), SetupError> {
    let mut r = s.setup.lock().await;
    r.options = None;
    r.report.stage = SetupStage::Preflight;
    r.report.network_ready = false;
    r.report.workload_ready = false;
    r.report.error_code = Some("setup_suspended_by_owner".into());
    persist(s, &r)
}
pub(crate) async fn status(s: &AppState) -> SetupReport {
    s.setup.lock().await.report.clone()
}
async fn stage(s: &AppState, stage: SetupStage) -> Result<(), SetupError> {
    let mut r = s.setup.lock().await;
    r.report.stage = stage;
    r.report.error_code = None;
    persist(s, &r)
}
pub(crate) async fn run(s: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        tokio::select! {_ = tick.tick()=>{},_ = shutdown.changed()=>return}
        let o = s.setup.lock().await.options.clone();
        if let Some(o) = o {
            if let Err(e) = reconcile(&s, o).await {
                let mut r = s.setup.lock().await;
                r.report.stage = SetupStage::Degraded;
                r.report.error_code = Some(format!("setup_{e:?}").to_lowercase());
                let _ = persist(&s, &r);
            }
        }
    }
}
async fn reconcile(s: &Arc<AppState>, o: SetupOptions) -> Result<(), SetupError> {
    reconcile_with_probe(s, o, |j| async move { probe_journal(&j).await }).await
}
async fn reconcile_with_probe<F, Fut>(
    s: &Arc<AppState>,
    o: SetupOptions,
    probe: F,
) -> Result<(), SetupError>
where
    F: FnOnce(network::NetworkJournal) -> Fut,
    Fut: std::future::Future<Output = NetworkEvidence>,
{
    if !s.config.read().await.network.enabled {
        let mut r = s.setup.lock().await;
        r.report.network_ready = false;
        r.report.workload_ready = false;
        r.report.stage = SetupStage::Preflight;
        r.report.error_code = Some("network_disabled_by_owner".into());
        persist(s, &r)?;
        return Ok(());
    }
    let mut identity = s.identity.read().await.clone();
    let mut trust = identity.bootstrap().cloned();
    if !s.setup.lock().await.public_joined {
        stage(s, SetupStage::Joining).await?;
        let t = enrollment::join_public(&s.http, &identity, &o.bootstrap_url)
            .await
            .map_err(|_| SetupError::Join)?;
        if trust.as_ref().is_some_and(|p| {
            p.bootstrap_public_key != t.bootstrap_public_key || p.bootstrap_id != t.bootstrap_id
        }) {
            return Err(SetupError::Identity);
        }
        s.identity
            .write()
            .await
            .set_bootstrap(t.clone())
            .await
            .map_err(|_| SetupError::Persistence)?;
        trust = Some(t);
        {
            let mut r = s.setup.lock().await;
            r.public_joined = true;
            persist(s, &r)?;
        }
        identity = s.identity.read().await.clone();
    }
    {
        let mut r = s.setup.lock().await;
        r.report.node_id = identity.identity().node_id.clone();
        persist(s, &r)?;
    }
    let trust = trust.ok_or(SetupError::Identity)?;
    stage(s, SetupStage::Allocating).await?;
    let journal = network::load_journal(&s.network_journal_path).await;
    {
        let mut r = s.setup.lock().await;
        r.report.virtual_ipv4 = journal.virtual_ipv4.clone();
        r.report.network_ready = false;
        r.report.workload_ready = false;
        persist(s, &r)?;
    }
    if journal.virtual_ipv4.is_none() {
        return Ok(());
    }
    stage(s, SetupStage::VerifyingNetwork).await?;
    let evidence = probe(journal.clone()).await;
    let (ready, _, _) = evaluate_readiness(&evidence, false);
    if !ready {
        return Ok(());
    }
    {
        let mut r = s.setup.lock().await;
        r.report.network_ready = true;
        persist(s, &r)?;
    }
    let discovery = enrollment::discover(&s.http, &identity, &trust)
        .await
        .map_err(|_| SetupError::Join)?;
    if o.role == NodeRole::Master {
        stage(s, SetupStage::ActivatingMaster).await?;
        let control = load_control(&master_dir(s))?;
        let claim = MasterActivationClaim {
            schema_version: PRODUCT_SCHEMA_VERSION,
            request_id: uuid::Uuid::new_v4().to_string(),
            node_id: identity.identity().node_id.clone(),
            control_id: control.control_id.clone(),
            control_public_key: control.public_key.clone(),
            issued_at_ms: unix_time_ms(),
        };
        let private = decode_key::<32>(&control.private_key).map_err(|_| SetupError::Identity)?;
        // The durable role/control identity exists before activation; retries can prove both keys without a saved token.
        let request = MasterActivationRequest {
            node_signature: sign(identity.private_key(), &claim)
                .map_err(|_| SetupError::Identity)?,
            control_signature: sign(&private, &claim).map_err(|_| SetupError::Identity)?,
            activation_token: o.master_token.clone().unwrap_or_default(),
            claim,
        };
        let response = s
            .http
            .post(format!(
                "{}/api/v1/bootstrap/activate-master",
                trust.bootstrap_url
            ))
            .json(&request)
            .send()
            .await
            .map_err(|_| SetupError::Activation)?;
        if !response.status().is_success() {
            return Err(SetupError::Activation);
        }
        let grant: SignedMasterGrant = response.json().await.map_err(|_| SetupError::Activation)?;
        verify(&trust.bootstrap_public_key, &grant.signature, &grant.grant)
            .map_err(|_| SetupError::Activation)?;
        if grant.grant.node_id != identity.identity().node_id
            || grant.grant.control_id != control.control_id
            || grant.grant.control_public_key != control.public_key
            || grant.grant.node_public_key != identity.identity().public_key
        {
            return Err(SetupError::Activation);
        }
        let fresh = enrollment::discover(&s.http, &identity, &trust)
            .await
            .map_err(|_| SetupError::Join)?;
        write_private(
            &master_dir(s).join("master-authority.json"),
            &MasterAuthority {
                bootstrap_url: trust.bootstrap_url.clone(),
                coordinator_key: trust.bootstrap_public_key.clone(),
                network_id: grant.grant.network_id.clone(),
                grant,
                directory: fresh.directory,
            },
        )?;
        if let Some(o) = &mut s.setup.lock().await.options {
            o.master_token = None;
        }
    }
    let discovery = if o.role == NodeRole::Master {
        enrollment::discover(&s.http, &identity, &trust)
            .await
            .map_err(|_| SetupError::Join)?
    } else {
        discovery
    };
    let d = &discovery.directory.directory;
    crate::authorization::record(s, &discovery)
        .await
        .map_err(|_| SetupError::Identity)?;
    let active = d
        .active_master_id
        .as_ref()
        .and_then(|id| d.masters.iter().find(|g| &g.grant.control_id == id));
    let mut attached = false;
    if let Some(g) = active {
        stage(s, SetupStage::AttachingWorkload).await?;
        if identity
            .trust()
            .is_none_or(|t| t.control_id != g.grant.control_id)
        {
            if s.active_lease.read().await.as_ref().is_some_and(|l| {
                !matches!(
                    l.state,
                    JobState::Completed | JobState::Failed | JobState::Rejected
                )
            }) {
                let mut r = s.setup.lock().await;
                r.report.stage = SetupStage::WaitingForMaster;
                r.report.workload_ready = false;
                r.report.error_code = Some("existing_lease_handover_pending".into());
                persist(s, &r)?;
                return Ok(());
            }
            let t = match attach(&s.http, &identity, &discovery.membership, &g.grant).await {
                Ok(t) => t,
                Err(_) => {
                    let mut r = s.setup.lock().await;
                    r.report.stage = SetupStage::WaitingForMaster;
                    r.report.workload_ready = false;
                    r.report.error_code = Some("workload_attachment_pending".into());
                    persist(s, &r)?;
                    return Ok(());
                }
            };
            s.identity
                .write()
                .await
                .set_trust(t.clone())
                .await
                .map_err(|_| SetupError::Persistence)?;
            let mut c = s.config.write().await;
            c.control_url = Some(t.control_url);
            crate::save_config(&s.config_path, &c)
                .await
                .map_err(|_| SetupError::Persistence)?;
        }
        attached = s
            .control_connected
            .load(std::sync::atomic::Ordering::Relaxed);
    }
    let mut r = s.setup.lock().await;
    r.report.stage = if attached {
        SetupStage::Ready
    } else {
        SetupStage::WaitingForMaster
    };
    r.report.workload_ready = attached;
    r.report.error_code = None;
    persist(s, &r)?;
    Ok(())
}
fn master_dir(s: &AppState) -> PathBuf {
    std::env::var_os("LATTICE_MASTER_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| s.config_path.with_file_name("master"))
}
#[derive(Serialize, Deserialize)]
struct LocalControl {
    control_id: String,
    private_key: String,
    public_key: String,
    created_at_ms: u64,
}
fn load_control(dir: &Path) -> Result<LocalControl, SetupError> {
    let path = dir.join("control-identity.json");
    match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b).map_err(|_| SetupError::Identity),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = lattice_crypto::generate_private_key();
            let c = LocalControl {
                control_id: format!("control_{}", uuid::Uuid::new_v4().simple()),
                private_key: lattice_crypto::encode_key(&key),
                public_key: lattice_crypto::encode_key(&lattice_crypto::public_key(&key)),
                created_at_ms: unix_time_ms(),
            };
            write_private(&path, &c)?;
            Ok(c)
        }
        Err(_) => Err(SetupError::Identity),
    }
}
async fn attach(
    client: &reqwest::Client,
    id: &IdentityState,
    m: &SignedMembership,
    g: &MasterGrant,
) -> Result<ControlTrust, SetupError> {
    let ip = g
        .overlay_ipv4
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| SetupError::Identity)?;
    let url = format!("http://{ip}:7443");
    let n = id.identity();
    let enrollment = EnrollmentClaim {
        protocol_version: PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().to_string(),
        node_id: n.node_id.clone(),
        node_name: n.node_name.clone(),
        platform: n.platform.clone(),
        architecture: n.architecture.clone(),
        public_key: n.public_key.clone(),
        client_version: env!("CARGO_PKG_VERSION").into(),
        issued_at_ms: unix_time_ms(),
    };
    let claim = WorkloadJoinClaim {
        schema_version: PRODUCT_SCHEMA_VERSION,
        enrollment,
        membership: m.clone(),
        master_control_id: g.control_id.clone(),
    };
    let r = client
        .post(format!("{url}/api/v1/master/join"))
        .json(&WorkloadJoinRequest {
            signature: sign(id.private_key(), &claim).map_err(|_| SetupError::Identity)?,
            claim: claim.clone(),
        })
        .send()
        .await
        .map_err(|_| SetupError::Join)?;
    if !r.status().is_success() {
        return Err(SetupError::Join);
    }
    let r: EnrollmentResponse = r.json().await.map_err(|_| SetupError::Join)?;
    verify(&g.control_public_key, &r.signature, &r.receipt).map_err(|_| SetupError::Join)?;
    if r.receipt.node_id != n.node_id
        || r.receipt.request_id != claim.enrollment.request_id
        || r.receipt.control_id != g.control_id
        || r.receipt.control_public_key != g.control_public_key
    {
        return Err(SetupError::Join);
    }
    Ok(ControlTrust {
        control_url: url,
        control_id: g.control_id.clone(),
        control_public_key: g.control_public_key.clone(),
        control_fingerprint: lattice_crypto::fingerprint(&g.control_public_key)
            .map_err(|_| SetupError::Identity)?,
        policy_revision: r.receipt.policy_revision,
        enrolled_at_ms: unix_time_ms(),
    })
}
async fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if out.status.success() {
        String::from_utf8(out.stdout).ok()
    } else {
        None
    }
}
pub(crate) async fn probe_journal(j: &network::NetworkJournal) -> NetworkEvidence {
    let interface = network::active_interface_name();
    let gateway = j.gateway_ipv4.as_deref().unwrap_or("");
    let mut e = NetworkEvidence {
        handshake_age_ms: None,
        route_verified: false,
        probe_success: false,
    };
    if gateway.parse::<std::net::Ipv4Addr>().is_err() {
        return e;
    }
    if let Some(text) = output("wg", &["show", &interface, "latest-handshakes"]).await {
        e.handshake_age_ms = network::parse_wg_handshakes(&text)
            .into_iter()
            .find(|(k, _)| Some(k) == j.gateway_wireguard_public_key.as_ref())
            .filter(|(_, t)| *t > 0 && *t <= unix_time_ms() / 1000)
            .map(|(_, t)| unix_time_ms().saturating_sub(t * 1000));
    }
    e.route_verified = route_verified(gateway, &interface).await;
    #[cfg(target_os = "linux")]
    {
        e.probe_success = output("ping", &["-c", "1", "-W", "2", "-I", &interface, gateway])
            .await
            .is_some();
    }
    #[cfg(target_os = "macos")]
    {
        e.probe_success = output("ping", &["-c", "1", "-W", "2000", gateway])
            .await
            .is_some();
    }
    #[cfg(windows)]
    {
        e.probe_success = output("ping.exe", &["-n", "1", "-w", "2000", gateway])
            .await
            .is_some();
    }

    e
}

pub(crate) async fn route_verified(address: &str, interface: &str) -> bool {
    if address.parse::<std::net::Ipv4Addr>().is_err()
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    #[cfg(target_os = "linux")]
    if let Some(text) = output("ip", &["-j", "route", "get", address]).await {
        return serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|j| j[0]["dev"].as_str().map(|d| d == interface))
            .unwrap_or(false);
    }
    #[cfg(target_os = "macos")]
    if let Some(text) = output("route", &["-n", "get", address]).await {
        return text.lines().any(|l| {
            l.trim()
                .strip_prefix("interface:")
                .is_some_and(|v| v.trim() == interface)
        });
    }
    #[cfg(windows)]
    {
        let script = format!(
            "$r=Find-NetRoute -RemoteIPAddress '{address}'; if ($r.NetRoute.InterfaceAlias -ne '{interface}') {{ exit 1 }}"
        );
        return output(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .await
        .is_some();
    }
    #[allow(unreachable_code)]
    false
}

#[cfg(test)]
mod review_regressions {
    use super::*;
    struct Fixture {
        _dir: tempfile::TempDir,
        node: Arc<AppState>,
        coordinator: lattice_control::AppState,
        server: tokio::task::JoinHandle<()>,
        options: SetupOptions,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }
    async fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let node = crate::load_state_at(dir.path().join("node.json"))
            .await
            .unwrap();
        let coordinator = lattice_control::load_state(
            &dir.path().join("coordinator"),
            String::new(),
            None,
            "https://coordinator.test".into(),
            "bootstrapper".into(),
        )
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = coordinator.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                lattice_control::build_router(state).route(
                    "/api/v1/releases/latest",
                    axum::routing::get(|| async { axum::Json(serde_json::Value::Null) }),
                ),
            )
            .await
            .unwrap();
        });
        let id = node.identity.read().await.identity().node_id.clone();
        let key =
            lattice_crypto::encode_wireguard_key(&lattice_crypto::generate_wireguard_keypair().1);
        let allocation = {
            let mut n = coordinator.network.write().await;
            n.overlay_cidr = "127.0.0.0/16".into();
            n.gateway_ipv4 = "127.0.0.1".into();
            lattice_control::network::ensure_public_allocation(&mut n, &id, &key, unix_time_ms())
                .unwrap()
        };
        network::save_journal(
            &node.network_journal_path,
            &network::NetworkJournal {
                virtual_ipv4: Some(allocation.virtual_ipv4),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let token = coordinator
            .master_tokens
            .create("fixture", unix_time_ms())
            .await
            .unwrap();
        let options = SetupOptions {
            role: NodeRole::Master,
            bootstrap_url: url,
            master_token: Some(token.activation_token),
        };
        begin(node.clone(), options.clone()).await.unwrap();
        Fixture {
            _dir: dir,
            node,
            coordinator,
            server,
            options,
        }
    }
    async fn reconcile_ready(f: &Fixture) -> Result<(), SetupError> {
        reconcile_with_probe(&f.node, f.options.clone(), |_| async {
            NetworkEvidence {
                handshake_age_ms: Some(10),
                route_verified: true,
                probe_success: true,
            }
        })
        .await
    }
    #[tokio::test]
    async fn first_master_activation_waits_for_service_without_rolling_back_network() {
        let f = fixture().await;
        reconcile_ready(&f).await.unwrap();
        let r = status(&f.node).await;
        assert!(r.network_ready);
        assert!(!r.workload_ready);
        assert_eq!(r.stage, SetupStage::WaitingForMaster);
        assert!(master_dir(&f.node).join("master-authority.json").exists());
    }
    #[tokio::test]
    async fn master_handover_preserves_running_lease_and_its_control_pin() {
        let f = fixture().await;
        let key = lattice_crypto::generate_private_key();
        let public = lattice_crypto::encode_key(&lattice_crypto::public_key(&key));
        let old = ControlTrust {
            control_url: "https://old-master.test".into(),
            control_id: "old-master".into(),
            control_public_key: public.clone(),
            control_fingerprint: lattice_crypto::fingerprint(&public).unwrap(),
            policy_revision: 1,
            enrolled_at_ms: unix_time_ms(),
        };
        f.node
            .identity
            .write()
            .await
            .set_trust(old.clone())
            .await
            .unwrap();
        let offer = JobOffer {
            job_id: "existing-job".into(),
            workload_kind: WorkloadKind::Research,
            runtime: "native".into(),
            runtime_version: "1".into(),
            artifact_id: "artifact".into(),
            artifact_version: "1".into(),
            limits: ResourceLimits::default(),
            parameters: Default::default(),
            expires_at_ms: u64::MAX,
        };
        let lease = JobLeaseStatus {
            lease: JobLease {
                lease_id: "existing-lease".into(),
                node_id: f.node.identity.read().await.identity().node_id.clone(),
                offer,
                issued_at_ms: unix_time_ms(),
                decision_deadline_ms: u64::MAX,
                expires_at_ms: u64::MAX,
            },
            state: JobState::Running,
            reason: None,
            events: vec![],
            pending_event: None,
        };
        write_private(&f.node.active_lease_path, &lease).unwrap();
        *f.node.active_lease.write().await = Some(lease.clone());
        reconcile_ready(&f).await.unwrap();
        assert_eq!(
            f.node.identity.read().await.trust().unwrap().control_id,
            old.control_id
        );
        assert_eq!(f.node.active_lease.read().await.as_ref(), Some(&lease));
        let restarted = crate::load_state_at(f.node.config_path.clone())
            .await
            .unwrap();
        assert_eq!(restarted.active_lease.read().await.as_ref(), Some(&lease));
        assert_eq!(
            status(&f.node).await.error_code.as_deref(),
            Some("existing_lease_handover_pending")
        );
    }
    #[tokio::test]
    async fn owner_network_disable_survives_setup_reconciliation() {
        let f = fixture().await;
        crate::dispatch(IpcRequest::SetNetworkEnabled { enabled: false }, &f.node).await;
        reconcile_with_probe(&f.node, f.options.clone(), |_| async {
            panic!("disabled setup must not probe or reconnect")
        })
        .await
        .unwrap();
        assert!(!f.node.config.read().await.network.enabled);
    }
    #[tokio::test]
    async fn explicit_reset_suspends_automatic_setup() {
        let f = fixture().await;
        crate::dispatch(IpcRequest::ResetBootstrap, &f.node).await;
        assert!(f.node.setup.lock().await.options.is_none());
    }
    #[tokio::test]
    async fn owner_can_save_policy_after_pinned_overlay_attachment() {
        let f = fixture().await;
        let control = load_control(&master_dir(&f.node)).unwrap();
        let t = ControlTrust {
            control_url: "http://10.77.0.2:7443".into(),
            control_id: control.control_id,
            control_public_key: control.public_key.clone(),
            control_fingerprint: lattice_crypto::fingerprint(&control.public_key).unwrap(),
            policy_revision: 1,
            enrolled_at_ms: unix_time_ms(),
        };
        f.node
            .identity
            .write()
            .await
            .set_trust(t.clone())
            .await
            .unwrap();
        f.node.config.write().await.control_url = Some(t.control_url);
        let IpcResponse::Config(mut c) = crate::dispatch(IpcRequest::GetConfig, &f.node).await
        else {
            panic!("config")
        };
        c.policy.limits.cpu_percent = 17;
        c.policy.allow_mining = false;
        assert!(matches!(
            crate::dispatch(IpcRequest::SetConfig { config: c }, &f.node).await,
            IpcResponse::ConfigUpdated(_)
        ));
    }
    #[tokio::test]
    async fn signed_revocation_rejects_a_late_master_response_after_restart() {
        let f = fixture().await;
        let _ = reconcile_ready(&f).await;
        let a: MasterAuthority = serde_json::from_slice(
            &std::fs::read(master_dir(&f.node).join("master-authority.json")).unwrap(),
        )
        .unwrap();
        let t = ControlTrust {
            control_url: format!("http://{}:7443", a.grant.grant.overlay_ipv4),
            control_id: a.grant.grant.control_id.clone(),
            control_public_key: a.grant.grant.control_public_key.clone(),
            control_fingerprint: lattice_crypto::fingerprint(&a.grant.grant.control_public_key)
                .unwrap(),
            policy_revision: 1,
            enrolled_at_ms: unix_time_ms(),
        };
        f.node
            .identity
            .write()
            .await
            .set_trust(t.clone())
            .await
            .unwrap();
        let id = f.node.identity.read().await.clone();
        let b = id.bootstrap().unwrap().clone();
        let current = enrollment::discover(&f.node.http, &id, &b).await.unwrap();
        crate::authorization::record(&f.node, &current)
            .await
            .unwrap();
        assert!(crate::authorization::require(&f.node, &t).await.is_ok());
        f.coordinator
            .master_tokens
            .revoke_master(&t.control_id)
            .await
            .unwrap();
        let removed = enrollment::discover(&f.node.http, &id, &b).await.unwrap();
        crate::authorization::record(&f.node, &removed)
            .await
            .unwrap();
        assert!(crate::authorization::require(&f.node, &t).await.is_err());
        let restarted = crate::load_state_at(f.node.config_path.clone())
            .await
            .unwrap();
        assert!(crate::authorization::require(&restarted, &t).await.is_err());
        let mut old_update_trust = t;
        old_update_trust.control_url = f.options.bootstrap_url.clone();
        f.node
            .identity
            .write()
            .await
            .set_trust(old_update_trust)
            .await
            .unwrap();
        assert!(
            crate::updates::check_once(&f.node).await.is_err(),
            "revoked control must not offer updates even with a valid-looking endpoint response"
        );
    }
}
