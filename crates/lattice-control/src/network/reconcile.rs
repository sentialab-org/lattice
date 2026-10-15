use super::gateway;
use crate::{AppState, auth};
use serde::{Deserialize, Serialize};
use std::{future::Future, path::PathBuf, pin::Pin, sync::Arc};
use tokio::sync::watch;
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayApplyReport {
    pub desired_revision: u64,
    pub applied_revision: Option<u64>,
    pub error_code: Option<String>,
}
#[derive(Debug, Clone)]
pub enum GatewayCommand {
    ShowConfig {
        interface: String,
    },
    SyncConfig {
        interface: String,
        config_path: PathBuf,
    },
    EnsureInterface {
        interface: String,
    },
    EnsureAddress {
        interface: String,
        address: String,
    },
    EnsureRoute {
        interface: String,
        overlay: String,
    },
    ApplyFirewall {
        path: PathBuf,
    },
    EnableForwarding,
}
#[derive(Debug)]
pub enum GatewayError {
    Apply,
    Storage,
    InvalidConfig,
    Unsupported,
}
pub type CommandFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, GatewayError>> + Send + 'a>>;
pub trait GatewayCommandRunner: Send + Sync {
    fn execute<'a>(&'a self, command: GatewayCommand) -> CommandFuture<'a>;
}
pub struct SystemGatewayRunner;
impl GatewayCommandRunner for SystemGatewayRunner {
    fn execute<'a>(&'a self, c: GatewayCommand) -> CommandFuture<'a> {
        Box::pin(async move {
            if !cfg!(target_os = "linux") {
                return Err(GatewayError::Unsupported);
            }
            let (program, args): (String, Vec<String>) = match c {
                GatewayCommand::ShowConfig { interface } => {
                    ("wg".into(), vec!["showconf".into(), interface])
                }
                GatewayCommand::SyncConfig {
                    interface,
                    config_path,
                } => (
                    "wg".into(),
                    vec![
                        "syncconf".into(),
                        interface,
                        config_path.to_string_lossy().into(),
                    ],
                ),
                GatewayCommand::EnsureInterface { interface } => {
                    let exists = tokio::process::Command::new("ip")
                        .args(["link", "show", "dev", &interface])
                        .output()
                        .await
                        .map_err(|_| GatewayError::Apply)?;
                    if exists.status.success() {
                        return Ok(Vec::new());
                    }
                    (
                        "ip".into(),
                        vec![
                            "link".into(),
                            "add".into(),
                            "dev".into(),
                            interface,
                            "type".into(),
                            "wireguard".into(),
                        ],
                    )
                }
                GatewayCommand::EnsureAddress { interface, address } => {
                    let out = tokio::process::Command::new("ip")
                        .args(["address", "replace", &address, "dev", &interface])
                        .output()
                        .await
                        .map_err(|_| GatewayError::Apply)?;
                    if !out.status.success() {
                        return Err(GatewayError::Apply);
                    }
                    (
                        "ip".into(),
                        vec![
                            "link".into(),
                            "set".into(),
                            "dev".into(),
                            interface,
                            "up".into(),
                        ],
                    )
                }
                GatewayCommand::EnsureRoute { interface, overlay } => (
                    "ip".into(),
                    vec![
                        "route".into(),
                        "replace".into(),
                        overlay,
                        "dev".into(),
                        interface,
                    ],
                ),
                GatewayCommand::ApplyFirewall { path } => (
                    "nft".into(),
                    vec!["-f".into(), path.to_string_lossy().into()],
                ),
                GatewayCommand::EnableForwarding => (
                    "sysctl".into(),
                    vec!["-w".into(), "net.ipv4.ip_forward=1".into()],
                ),
            };
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::process::Command::new(program)
                    .args(args)
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .map_err(|_| GatewayError::Apply)?
            .map_err(|_| GatewayError::Apply)?;
            if result.status.success() {
                Ok(result.stdout)
            } else {
                Err(GatewayError::Apply)
            }
        })
    }
}
fn validate(interface: &str, address: &str, overlay: &str) -> Result<(), GatewayError> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || address.parse::<std::net::Ipv4Addr>().is_err()
        || super::parse_cidr(overlay).is_err()
    {
        return Err(GatewayError::InvalidConfig);
    }
    Ok(())
}
pub async fn reconcile_once(
    s: &AppState,
    runner: &dyn GatewayCommandRunner,
) -> Result<GatewayApplyReport, GatewayError> {
    let _guard = s.gateway_lock.lock().await;
    let net = s.network.read().await.clone();
    validate(&net.interface_name, &net.gateway_ipv4, &net.overlay_cidr)?;
    let dir = s.network_path.parent().ok_or(GatewayError::Storage)?;
    let (key, _) = super::load_or_create_gateway_keys(&dir.join("gateway_wireguard.json"))
        .await
        .map_err(|_| GatewayError::Storage)?;
    let config = gateway::build_gateway_config(&net, &key, 51820, &net.interface_name);
    let text = gateway::render_wireguard_config(&config);
    let desired = u64::from_str_radix(&auth::digest(text.as_bytes())[..16], 16)
        .map_err(|_| GatewayError::InvalidConfig)?;
    let mut report = GatewayApplyReport {
        desired_revision: desired,
        applied_revision: s.gateway_report.read().await.applied_revision,
        error_code: Some("gateway_apply_pending".into()),
    };
    *s.gateway_report.write().await = report.clone();
    let candidate = dir.join("gateway-candidate.conf");
    super::write_atomic(&candidate, text.as_bytes())
        .await
        .map_err(|_| GatewayError::Storage)?;
    let rollback = dir.join("gateway-rollback.conf");
    let firewall = dir.join("gateway-owned.nft");
    // The dedicated table uses accept policy; it cannot drop traffic belonging to other interfaces.
    super::write_atomic(
        &firewall,
        format!(
            "table inet lattice_overlay {{ }}\ndelete table inet lattice_overlay\n{}",
            gateway::render_nftables_ruleset(&net.interface_name, &net.overlay_cidr)
        )
        .as_bytes(),
    )
    .await
    .map_err(|_| GatewayError::Storage)?;
    let apply = async {
        runner
            .execute(GatewayCommand::EnsureInterface {
                interface: net.interface_name.clone(),
            })
            .await?;
        let snapshot = runner
            .execute(GatewayCommand::ShowConfig {
                interface: net.interface_name.clone(),
            })
            .await?;
        super::write_atomic(&rollback, &snapshot)
            .await
            .map_err(|_| GatewayError::Storage)?;
        runner
            .execute(GatewayCommand::SyncConfig {
                interface: net.interface_name.clone(),
                config_path: candidate.clone(),
            })
            .await?;
        runner
            .execute(GatewayCommand::EnsureAddress {
                interface: net.interface_name.clone(),
                address: config.address.clone(),
            })
            .await?;
        runner
            .execute(GatewayCommand::EnsureRoute {
                interface: net.interface_name.clone(),
                overlay: net.overlay_cidr.clone(),
            })
            .await?;
        runner.execute(GatewayCommand::EnableForwarding).await?;
        runner
            .execute(GatewayCommand::ApplyFirewall { path: firewall })
            .await?;
        super::write_atomic(&dir.join("gateway-applied.conf"), text.as_bytes())
            .await
            .map_err(|_| GatewayError::Storage)?;
        Ok::<_, GatewayError>(())
    }
    .await;
    if let Err(e) = apply {
        if rollback.is_file() {
            let _ = runner
                .execute(GatewayCommand::SyncConfig {
                    interface: net.interface_name.clone(),
                    config_path: rollback.clone(),
                })
                .await;
        }
        report.error_code = Some("gateway_apply_failed".into());
        *s.gateway_report.write().await = report;
        return Err(e);
    }
    report.applied_revision = Some(desired);
    report.error_code = None;
    *s.gateway_report.write().await = report.clone();
    Ok(report)
}
pub async fn run(s: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {_ = interval.tick()=>{},_ = s.gateway_notify.notified()=>{},_ = shutdown.changed()=>{if *shutdown.borrow(){return;}}}
        let _ = reconcile_once(&s, &SystemGatewayRunner).await;
    }
}
