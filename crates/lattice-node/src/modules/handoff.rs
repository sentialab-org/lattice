//! Explicit gateway adoption preserves existing transport identity before managed module startup.
use crate::AppState;
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
};
pub(super) type HandoffFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;
pub(super) trait LegacyWriterStopper: Send + Sync {
    fn stop<'a>(&'a self) -> HandoffFuture<'a, ()>;
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdoptionRecord {
    schema_version: u32,
    node_id: String,
    source: PathBuf,
    network_id: String,
    interface: String,
    address: String,
    overlay: String,
    endpoint: String,
    transport: String,
    phase: String,
}
#[derive(Deserialize, PartialEq, Eq)]
struct PublicNetwork {
    network_id: String,
    interface_name: String,
    overlay_cidr: String,
    gateway_ipv4: String,
    gateway_endpoint: String,
    gateway_wireguard_public_key: String,
}
#[derive(Deserialize)]
struct TransportKey {
    private_key: String,
    public_key: String,
}
pub(super) fn private_bytes(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "protected handoff source unavailable")?;
    let meta = file
        .metadata()
        .map_err(|_| "handoff source metadata unavailable")?;
    if !meta.is_file() || meta.len() > limit {
        return Err("handoff source rejected".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("handoff source requires private ownership".into());
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "handoff source unreadable")?;
    Ok(bytes)
}
pub(super) async fn adopt_gateway(
    s: &AppState,
    source: &Path,
    stopper: &dyn LegacyWriterStopper,
) -> Result<(), String> {
    let manager = s.network_manager.lock().await;
    let source = source
        .canonicalize()
        .map_err(|_| "authority directory unavailable")?;
    let meta = std::fs::symlink_metadata(&source).map_err(|_| "authority directory unavailable")?;
    if !meta.is_dir() {
        return Err("authority directory rejected".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err("authority directory requires private ownership".into());
        }
    }
    let net: PublicNetwork = serde_json::from_slice(&private_bytes(
        &source.join("network.json"),
        16 * 1024 * 1024,
    )?)
    .map_err(|_| "public network descriptor corrupt")?;
    let key: TransportKey = serde_json::from_slice(&private_bytes(
        &source.join("gateway_wireguard.json"),
        16384,
    )?)
    .map_err(|_| "legacy transport key corrupt")?;
    let private = lattice_crypto::decode_wireguard_key(&key.private_key)?;
    let public =
        lattice_crypto::encode_wireguard_key(&lattice_crypto::wireguard_public_key(&private));
    if public != key.public_key || public != net.gateway_wireguard_public_key {
        return Err("legacy transport key pair or public descriptor mismatch".into());
    }
    let address = format!(
        "{}/{}",
        net.gateway_ipv4,
        net.overlay_cidr
            .split('/')
            .nth(1)
            .ok_or("overlay prefix required")?
    );
    lattice_network::validate_local_transport(
        &net.interface_name,
        &address,
        &net.overlay_cidr,
        &public,
        &net.gateway_endpoint,
    )?;
    if net.interface_name != crate::network::configured_interface_name() {
        return Err("configure the preserved interface name before adoption".into());
    }
    manager.check_adoption(&net.network_id, &net.interface_name, &address, &public)?;
    let identity = s.identity.read().await.identity().clone();
    let journal = crate::network::load_journal(&s.network_journal_path).await;
    if journal
        .virtual_ipv4
        .as_deref()
        .is_some_and(|a| a.split('/').next() != Some(net.gateway_ipv4.as_str()))
    {
        return Err("gateway adoption cannot replace an allocated Node address".into());
    }
    if let Some(cache) = s.offline_authority.lock().await.checked()? {
        if cache.network_id != net.network_id {
            return Err("gateway belongs to a different pinned network".into());
        }
    }
    let existing = match std::fs::symlink_metadata(&s.network_key_path) {
        Ok(_) => {
            let (current, _) =
                crate::network::load_or_create_wireguard_key(&s.network_key_path).await?;
            if current != private {
                return Err(
                    "gateway adoption cannot replace an existing Node transport key".into(),
                );
            }
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err("Node transport key metadata unavailable".into()),
    };
    let mut record = AdoptionRecord {
        schema_version: 1,
        node_id: identity.node_id,
        source,
        network_id: net.network_id.clone(),
        interface: net.interface_name.clone(),
        address: address.clone(),
        overlay: net.overlay_cidr.clone(),
        endpoint: net.gateway_endpoint.clone(),
        transport: public,
        phase: "prepared".into(),
    };
    let path = s.config_path.with_file_name("gateway-handoff.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let old: AdoptionRecord = serde_json::from_slice(&private_bytes(&path, 65536)?)
                .map_err(|_| "handoff record corrupt; recover it")?;
            let mut expected = old.clone();
            expected.phase = record.phase.clone();
            if expected != record {
                return Err(
                    "handoff record belongs to another gateway; preserve it for recovery".into(),
                );
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("handoff record unavailable".into()),
    }
    lattice_network::write_atomic_private(&path, &record)?;
    stopper.stop().await?;
    // Revalidate the transport source after the old writer is stopped.
    let stopped: TransportKey = serde_json::from_slice(&private_bytes(
        &record.source.join("gateway_wireguard.json"),
        16384,
    )?)
    .map_err(|_| "legacy transport key corrupt")?;
    if stopped.public_key != key.public_key || stopped.private_key != key.private_key {
        return Err("legacy transport changed during handoff; preserve and inspect it".into());
    }
    let stopped_network: PublicNetwork = serde_json::from_slice(&private_bytes(
        &record.source.join("network.json"),
        16 * 1024 * 1024,
    )?)
    .map_err(|_| "public network descriptor corrupt")?;
    if stopped_network != net {
        return Err("gateway binding changed during handoff; preserve and inspect it".into());
    }
    if !existing {
        crate::network::import_wireguard_key(&s.network_key_path, &private)?;
    }
    let mut preserved = journal;
    preserved.virtual_ipv4 = Some(address);
    preserved.overlay_cidr = Some(net.overlay_cidr);
    preserved.gateway_ipv4 = Some(net.gateway_ipv4);
    preserved.gateway_endpoint = Some(net.gateway_endpoint);
    preserved.gateway_wireguard_public_key = Some(record.transport.clone());
    crate::network::save_journal(&s.network_journal_path, &preserved).await?;
    record.phase = "imported".into();
    lattice_network::write_atomic_private(&path, &record)?;
    Ok(())
}

pub(super) struct SystemLegacyWriterStopper {
    pub checkpoint: PathBuf,
}
impl LegacyWriterStopper for SystemLegacyWriterStopper {
    fn stop<'a>(&'a self) -> HandoffFuture<'a, ()> {
        Box::pin(async move {
            #[cfg(target_os = "linux")]
            {
                stop_linux_legacy(&self.checkpoint).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = &self.checkpoint;
                Err("gateway service handoff currently requires Linux".into())
            }
        })
    }
}
#[cfg(target_os = "linux")]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyUnit {
    name: String,
    active: bool,
    enablement: String,
}
#[cfg(target_os = "linux")]
async fn service(args: &[&str]) -> Result<Vec<u8>, String> {
    use std::{os::unix::fs::MetadataExt, process::Stdio};
    let executable = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| {
                m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0
            })
        })
        .ok_or("protected service manager unavailable")?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::process::Command::new(executable)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "legacy service handoff timed out")?
    .map_err(|_| "legacy service manager unavailable")?;
    if !output.status.success() || output.stdout.len() > 65536 {
        return Err("legacy service handoff failed; preserve the checkpoint for rollback".into());
    }
    Ok(output.stdout)
}
#[cfg(target_os = "linux")]
async fn stop_linux_legacy(checkpoint: &Path) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("gateway service handoff requires administrator privileges".into());
    }
    let units = [
        "lattice-control.service",
        "lattice-bootstrapper.service",
        "lattice-master.service",
    ];
    let mut states = Vec::new();
    let own_cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| "Base Node service identity unavailable")?;
    for name in units {
        if own_cgroup
            .lines()
            .any(|line| line.split('/').any(|part| part == name))
        {
            return Err(
                "migrate the Base Node to its own service before legacy service handoff".into(),
            );
        }
        let output = service(&[
            "show",
            name,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            "--property=MainPID",
        ])
        .await?;
        let text = String::from_utf8(output).map_err(|_| "legacy service state invalid")?;
        if text.lines().any(|l| l == "LoadState=not-found") {
            continue;
        }
        let state = |prefix: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .unwrap_or("")
                .to_string()
        };
        if state("MainPID=").parse::<u32>().ok() == Some(std::process::id()) {
            return Err("legacy service handoff cannot stop the current Base Node".into());
        }
        states.push(LegacyUnit {
            name: name.into(),
            active: state("ActiveState=") != "inactive" && state("ActiveState=") != "failed",
            enablement: state("UnitFileState="),
        });
    }
    match std::fs::symlink_metadata(checkpoint) {
        Ok(_) => {
            let original: Vec<LegacyUnit> =
                serde_json::from_slice(&private_bytes(checkpoint, 65536)?)
                    .map_err(|_| "legacy service checkpoint corrupt")?;
            if original.iter().any(|s| !units.contains(&s.name.as_str())) {
                return Err("legacy service checkpoint rejected".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            lattice_network::write_atomic_private(checkpoint, &states)?
        }
        Err(_) => return Err("legacy service checkpoint unavailable".into()),
    }
    for state in &states {
        if state.enablement == "enabled-runtime" {
            service(&["disable", "--runtime", &state.name]).await?;
        } else if state.enablement == "enabled" {
            service(&["disable", &state.name]).await?;
        }
        if state.active {
            service(&["stop", &state.name]).await?;
        }
        let status = service(&["show", &state.name, "--property=ActiveState", "--value"]).await?;
        if !matches!(
            std::str::from_utf8(&status).unwrap_or("").trim(),
            "inactive" | "failed"
        ) {
            return Err("legacy service is still active".into());
        }
    }
    for entry in std::fs::read_dir("/proc").map_err(|_| "legacy process inventory unavailable")? {
        let entry = entry.map_err(|_| "legacy process inventory unavailable")?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let path = entry.path();
        let Ok(executable) = std::fs::read_link(path.join("exe")) else {
            continue;
        };
        let name = executable
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .trim_end_matches(" (deleted)");
        if !["lattice-control", "lattice-bootstrapper", "lattice-master"].contains(&name) {
            continue;
        }
        let status = std::fs::read_to_string(path.join("status"))
            .map_err(|_| "legacy process status unavailable; retry handoff")?;
        let parent = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .and_then(|v| v.trim().parse::<u32>().ok());
        if parent != Some(std::process::id()) {
            return Err(
                "legacy controller process still running; stop it before gateway adoption".into(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_crypto::{encode_wireguard_key, wireguard_public_key};
    fn key(seed: u8) -> String {
        encode_wireguard_key(&wireguard_public_key(&[seed; 32]))
    }
    fn source(root: &std::path::Path) {
        lattice_network::write_atomic_private(
            &root.join("gateway_wireguard.json"),
            &serde_json::json!({"private_key":encode_wireguard_key(&[4;32]),"public_key":key(4)}),
        )
        .unwrap();
        lattice_network::write_atomic_private(&root.join("network.json"),&serde_json::json!({"network_id":"network-test","interface_name":crate::network::configured_interface_name(),"overlay_cidr":"10.77.0.0/16","gateway_ipv4":"10.77.0.1","gateway_endpoint":"198.51.100.1:51820","gateway_wireguard_public_key":key(4),"allocations":{},"reserved_ipv4":["10.77.0.1"]})).unwrap();
        // Supervisor signing material is deliberately not a parseable key record.
        // Adoption must never inspect its contents or the owner's account hash.
        lattice_network::write_atomic_private(
            &root.join("control-identity.json"),
            &"unread Supervisor signing material",
        )
        .unwrap();
        lattice_network::write_atomic_private(&root.join("account.json"), &"unread owner account")
            .unwrap();
    }
    struct Stopper {
        calls: std::sync::atomic::AtomicUsize,
        fail: bool,
    }
    impl LegacyWriterStopper for Stopper {
        fn stop<'a>(&'a self) -> HandoffFuture<'a, ()> {
            Box::pin(async move {
                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if self.fail {
                    Err("legacy writer is still active".into())
                } else {
                    Ok(())
                }
            })
        }
    }
    #[tokio::test]
    async fn adoption_imports_the_exact_transport_only_after_stopping_legacy_writers() {
        let directory = tempfile::tempdir().unwrap();
        let authority = directory.path().join("authority");
        source(&authority);
        let node = crate::load_state_at(directory.path().join("node/node.json"))
            .await
            .unwrap();
        let identity = node.identity.read().await.identity().clone();
        let old = std::fs::read(authority.join("gateway_wireguard.json")).unwrap();
        let stopper = Stopper {
            calls: Default::default(),
            fail: false,
        };
        adopt_gateway(&node, &authority, &stopper).await.unwrap();
        let (private, public) =
            crate::network::load_or_create_wireguard_key(&node.network_key_path)
                .await
                .unwrap();
        assert!(
            private == [4; 32],
            "adoption must import the existing private transport key exactly"
        );
        assert_eq!(encode_wireguard_key(&public), key(4));
        let journal = crate::network::load_journal(&node.network_journal_path).await;
        assert_eq!(journal.virtual_ipv4.as_deref(), Some("10.77.0.1/16"));
        assert_eq!(
            journal.last_applied_revision, 0,
            "copying preserved metadata is not an OS apply acknowledgment"
        );
        assert_eq!(
            std::fs::read(authority.join("gateway_wireguard.json")).unwrap(),
            old
        );
        assert_eq!(node.identity.read().await.identity(), &identity);
        assert_eq!(stopper.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn a_foreign_node_key_or_ip_aborts_before_any_service_stop_or_replacement() {
        for foreign_key in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let authority = directory.path().join("authority");
            source(&authority);
            let node = crate::load_state_at(directory.path().join("node/node.json"))
                .await
                .unwrap();
            if foreign_key {
                crate::network::load_or_create_wireguard_key(&node.network_key_path)
                    .await
                    .unwrap();
            } else {
                let mut j = crate::network::NetworkJournal::default();
                j.virtual_ipv4 = Some("10.77.0.4/32".into());
                crate::network::save_journal(&node.network_journal_path, &j)
                    .await
                    .unwrap();
            }
            let old = std::fs::read(&node.network_key_path).ok();
            let stopper = Stopper {
                calls: Default::default(),
                fail: false,
            };
            assert!(adopt_gateway(&node, &authority, &stopper).await.is_err());
            assert_eq!(stopper.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(std::fs::read(&node.network_key_path).ok(), old);
        }
    }
    #[tokio::test]
    async fn an_unstopped_legacy_writer_cannot_be_bypassed_by_copying_its_key() {
        let directory = tempfile::tempdir().unwrap();
        let authority = directory.path().join("authority");
        source(&authority);
        let node = crate::load_state_at(directory.path().join("node/node.json"))
            .await
            .unwrap();
        let stopper = Stopper {
            calls: Default::default(),
            fail: true,
        };
        assert!(adopt_gateway(&node, &authority, &stopper).await.is_err());
        assert!(!node.network_key_path.exists());
        let marker: serde_json::Value = serde_json::from_slice(
            &std::fs::read(node.config_path.with_file_name("gateway-handoff.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(marker["phase"], "prepared");
    }
}
