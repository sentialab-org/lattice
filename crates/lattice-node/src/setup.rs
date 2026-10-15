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
    let mut r = s.setup.lock().await;
    r.public_joined = false;
    r.options = Some(o.clone());
    r.report = SetupReport::initial(o.role);
    persist(&s, &r)?;
    Ok(r.report.clone())
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
    {
        let mut c = s.config.write().await;
        if !c.network.enabled || c.bootstrap_url.as_deref() != Some(&o.bootstrap_url) {
            enable_network(&mut c, &o.bootstrap_url);
            crate::save_config(&s.config_path, &c)
                .await
                .map_err(|_| SetupError::Persistence)?;
        }
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
    let evidence = probe(s, &journal).await;
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
            let t = attach(&s.http, &identity, &discovery.membership, &g.grant).await?;
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
async fn probe(s: &Arc<AppState>, j: &network::NetworkJournal) -> NetworkEvidence {
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
    #[cfg(target_os = "linux")]
    {
        if let Some(text) = output("ip", &["-j", "route", "get", gateway]).await {
            e.route_verified = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|j| j[0]["dev"].as_str().map(|d| d == interface))
                .unwrap_or(false);
        }
        e.probe_success = output("ping", &["-c", "1", "-W", "2", "-I", &interface, gateway])
            .await
            .is_some();
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(text) = output("route", &["-n", "get", gateway]).await {
            e.route_verified = text.lines().any(|l| {
                l.trim()
                    .strip_prefix("interface:")
                    .is_some_and(|v| v.trim() == interface)
            });
        }
        e.probe_success = output("ping", &["-c", "1", "-W", "2000", gateway])
            .await
            .is_some();
    }
    #[cfg(windows)]
    {
        let script = format!(
            "$r=Find-NetRoute -RemoteIPAddress '{gateway}'; if ($r.NetRoute.InterfaceAlias -ne '{interface}') {{ exit 1 }}"
        );
        e.route_verified = output(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .await
        .is_some();
        e.probe_success = output("ping.exe", &["-n", "1", "-w", "2000", gateway])
            .await
            .is_some();
    }
    let _ = s;
    e
}
