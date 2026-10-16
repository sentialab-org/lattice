use crate::ValidatedGateway;
use serde::{Deserialize, Serialize};
use std::{future::Future, path::Path, pin::Pin};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedRoute {
    pub destination: String,
    pub interface: String,
    pub gateway: Option<String>,
    pub metric: Option<u32>,
    pub source: Option<String>,
    pub protocol: Option<String>,
    pub scope: Option<String>,
}
/// Contains private WireGuard configuration; never expose through IPC or logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkSnapshot {
    pub interface_name: String,
    pub overlay_cidr: String,
    pub existed: bool,
    pub link_up: bool,
    pub transport_public_key: Option<String>,
    pub wireguard_config: Option<String>,
    pub addresses: Vec<String>,
    pub route: Option<OwnedRoute>,
    pub forwarding: bool,
    pub owned_firewall: Option<String>,
}
pub enum NetworkCommand {
    CreateInterface {
        interface: String,
    },
    SyncWireguard {
        interface: String,
        config: String,
    },
    SetAddress {
        interface: String,
        address: String,
    },
    SetRoute {
        interface: String,
        overlay: String,
    },
    SetForwarding {
        enabled: bool,
    },
    ReplaceOwnedFirewall {
        rules: String,
    },
    Restore {
        snapshot: NetworkSnapshot,
        transport_public_key: String,
        applied_address: String,
    },
}
impl NetworkCommand {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::CreateInterface { .. } => "create",
            Self::SyncWireguard { .. } => "wireguard",
            Self::SetAddress { .. } => "address",
            Self::SetRoute { .. } => "route",
            Self::SetForwarding { .. } => "forwarding",
            Self::ReplaceOwnedFirewall { .. } => "firewall",
            Self::Restore { .. } => "restore",
        }
    }
}
pub type NetworkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;
pub trait NetworkRunner: Send + Sync {
    fn capture<'a>(
        &'a self,
        interface: &'a str,
        overlay: &'a str,
    ) -> NetworkFuture<'a, NetworkSnapshot>;
    fn execute<'a>(&'a self, command: NetworkCommand) -> NetworkFuture<'a, ()>;
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppliedNetwork {
    pub revision: u64,
    pub interface_name: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    network_id: String,
    interface_name: String,
    transport_public_key: String,
    overlay_cidr: String,
    revision: u64,
    applied_address: String,
    phase: Phase,
    before: NetworkSnapshot,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Committed,
    RolledBack,
}

pub fn write_atomic_private<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().ok_or("private state directory required")?;
    std::fs::create_dir_all(parent).map_err(|_| "private state directory unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::metadata(parent).map_err(|_| "private state directory unavailable")?;
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err("private state directory ownership rejected".into());
        }
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "private state directory protection failed")?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("private state path rejected".into());
        }
    }
    let temporary = parent.join(format!(
        ".network-state-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| "private state temporary file unavailable")?;
        let bytes = serde_json::to_vec(value).map_err(|_| "private state serialization failed")?;
        file.write_all(&bytes)
            .map_err(|_| "private state write failed")?;
        file.sync_all().map_err(|_| "private state sync failed")?;
        std::fs::rename(&temporary, path).map_err(|_| "private state commit failed")?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|_| "private state directory sync failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
fn load_journal(path: &Path) -> Result<Option<Journal>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("network transaction journal unavailable".into()),
    };
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8 * 1024 * 1024 {
        return Err("network transaction journal rejected".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("network transaction journal requires private ownership".into());
        }
    }
    serde_json::from_slice(
        &std::fs::read(path).map_err(|_| "network transaction journal unavailable")?,
    )
    .map(Some)
    .map_err(|_| "network transaction journal corrupt; preserve and restore it".into())
}
pub async fn recover_gateway_transaction(
    runner: &dyn NetworkRunner,
    path: &Path,
    network: &str,
    interface: &str,
    transport: &str,
    overlay: &str,
) -> Result<bool, String> {
    let Some(mut journal) = load_journal(path)? else {
        return Ok(false);
    };
    if journal.schema_version != 1
        || journal.network_id != network
        || journal.interface_name != interface
        || journal.transport_public_key != transport
        || journal.overlay_cidr != overlay
        || journal.before.interface_name != interface
        || journal.before.overlay_cidr != overlay
        || journal
            .before
            .transport_public_key
            .as_deref()
            .is_some_and(|k| k != transport)
        || journal
            .before
            .route
            .as_ref()
            .is_some_and(|r| r.interface != interface || r.destination != overlay)
    {
        return Err("network recovery binding rejected".into());
    }
    if journal.phase != Phase::Prepared {
        return Ok(false);
    }
    let current = runner.capture(interface, overlay).await?;
    if current
        .transport_public_key
        .as_deref()
        .is_some_and(|k| k != transport)
    {
        return Err("network recovery will not overwrite a different transport owner".into());
    }
    runner
        .execute(NetworkCommand::Restore {
            snapshot: journal.before.clone(),
            transport_public_key: transport.into(),
            applied_address: journal.applied_address.clone(),
        })
        .await
        .map_err(
            |_| "network rollback pending; previous state must be recovered before new work",
        )?;
    journal.phase = Phase::RolledBack;
    write_atomic_private(path, &journal)?;
    Ok(true)
}
pub async fn apply_gateway(
    runner: &dyn NetworkRunner,
    plan: &ValidatedGateway,
    private: &[u8; 32],
    owner_limit_bps: u64,
    path: &Path,
) -> Result<AppliedNetwork, String> {
    let p = plan.intent();
    let config = plan.wireguard_config(private)?;
    let rules = plan.firewall_rules(owner_limit_bps)?;
    recover_gateway_transaction(
        runner,
        path,
        &p.network_id,
        &p.interface_name,
        &p.transport_public_key,
        &p.overlay_cidr,
    )
    .await?;
    let before = runner.capture(&p.interface_name, &p.overlay_cidr).await?;
    if before.interface_name != p.interface_name
        || before.overlay_cidr != p.overlay_cidr
        || (before.existed
            && (before.transport_public_key.as_deref() != Some(p.transport_public_key.as_str())
                || before.wireguard_config.is_none()))
        || before
            .route
            .as_ref()
            .is_some_and(|r| r.interface != p.interface_name || r.destination != p.overlay_cidr)
    {
        return Err("interface or route belongs to another network owner".into());
    }
    let mut journal = Journal {
        schema_version: 1,
        network_id: p.network_id.clone(),
        interface_name: p.interface_name.clone(),
        transport_public_key: p.transport_public_key.clone(),
        overlay_cidr: p.overlay_cidr.clone(),
        revision: p.revision,
        applied_address: p.address.clone(),
        phase: Phase::Prepared,
        before,
    };
    write_atomic_private(path, &journal)?;
    let result = async {
        if !journal.before.existed {
            runner
                .execute(NetworkCommand::CreateInterface {
                    interface: p.interface_name.clone(),
                })
                .await?;
        }
        for command in [
            NetworkCommand::SyncWireguard {
                interface: p.interface_name.clone(),
                config,
            },
            NetworkCommand::SetAddress {
                interface: p.interface_name.clone(),
                address: p.address.clone(),
            },
            NetworkCommand::SetRoute {
                interface: p.interface_name.clone(),
                overlay: p.overlay_cidr.clone(),
            },
            NetworkCommand::SetForwarding { enabled: true },
            NetworkCommand::ReplaceOwnedFirewall { rules },
        ] {
            runner.execute(command).await?;
        }
        Ok::<_, String>(())
    }
    .await;
    if result.is_err() {
        // A failed commit is still pending until the complete previous state is restored.
        journal.phase = Phase::Prepared;
        if runner
            .execute(NetworkCommand::Restore {
                snapshot: journal.before.clone(),
                transport_public_key: p.transport_public_key.clone(),
                applied_address: p.address.clone(),
            })
            .await
            .is_err()
        {
            return Err("network apply failed; rollback pending before any new apply".into());
        }
        journal.phase = Phase::RolledBack;
        write_atomic_private(path, &journal)?;
        return Err("network apply failed; previous owned state restored".into());
    }
    // All OS effects succeeded. A commit write can fail after rename; do not start an
    // ambiguous rollback after that point. Recovery/reconciliation must inspect it.
    journal.phase = Phase::Committed;
    write_atomic_private(path, &journal)
        .map_err(|_| "network configuration applied; durable commit requires recovery")?;
    Ok(AppliedNetwork {
        revision: p.revision,
        interface_name: p.interface_name.clone(),
    })
}
