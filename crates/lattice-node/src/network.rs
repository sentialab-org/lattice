use crate::AppState;
use crate::identity::unix_time_ms;
use lattice_crypto::{
    encode_wireguard_key, generate_wireguard_keypair, sign, verify, wireguard_public_key,
};
use lattice_protocol::{
    NETWORK_PROTOCOL_VERSION, NetworkAckClaim, NetworkAckRequest, NetworkDesiredConfig,
    NetworkNodeStatus, NetworkPeerEntry, NetworkPeersClaim, NetworkPeersRequest,
    NetworkPeersResponse, NetworkRegisterClaim, NetworkRegisterRequest, NetworkSyncClaim,
    NetworkSyncRequest, NetworkSyncResponse,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

static NEXT_NETWORK_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn next_sequence() -> u64 {
    let candidate = unix_time_ms()
        .saturating_mul(1_048_576)
        .saturating_add((Uuid::new_v4().as_u128() as u64) & 0x000f_ffff);
    let mut previous = NEXT_NETWORK_SEQ.load(Ordering::Relaxed);
    loop {
        let next = candidate.max(previous.saturating_add(1));
        match NEXT_NETWORK_SEQ.compare_exchange_weak(
            previous,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return next,
            Err(actual) => previous = actual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredWireguardKey {
    public_key: String,
    private_key_blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkJournal {
    #[serde(default)]
    pub gateway_ipv4: Option<String>,
    pub last_applied_revision: u64,
    pub virtual_ipv4: Option<String>,
    pub overlay_cidr: Option<String>,
    pub gateway_endpoint: Option<String>,
    pub gateway_wireguard_public_key: Option<String>,
    pub last_error: Option<String>,
    pub updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_conf: Option<String>,
    #[serde(default)]
    pub last_acked_revision: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkPeersCache {
    #[serde(default)]
    pub peers: Vec<NetworkPeerEntry>,
    #[serde(default)]
    pub path_policy: String,
    #[serde(default)]
    pub updated_at_ms: u64,
}

pub fn network_peers_path(config_path: &Path) -> PathBuf {
    crate::identity_path(config_path).with_file_name("network_peers.json")
}

pub async fn load_peers_cache(path: &Path) -> NetworkPeersCache {
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return NetworkPeersCache::default();
    };
    serde_json::from_str::<NetworkPeersCache>(&content).unwrap_or_default()
}

pub async fn save_peers_cache(path: &Path, cache: &NetworkPeersCache) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let content = serde_json::to_vec_pretty(cache).map_err(|e| e.to_string())?;
    write_atomic(path, &content).await
}

pub fn wireguard_key_path(config_path: &Path) -> PathBuf {
    crate::identity_path(config_path).with_file_name("network_wireguard.json")
}

pub fn network_journal_path(config_path: &Path) -> PathBuf {
    crate::identity_path(config_path).with_file_name("network_journal.json")
}

#[cfg(windows)]
fn protect_wireguard_key(private_key: &[u8; 32]) -> Result<String, String> {
    use base64::Engine;
    use std::ptr::null;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: private_key.len() as u32,
        pbData: private_key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let result = unsafe {
        CryptProtectData(
            &input,
            null(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };

    unsafe {
        LocalFree(output.pbData.cast());
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(&protected))
}

#[cfg(windows)]
fn unprotect_wireguard_key(value: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let mut protected = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| e.to_string())?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let mut description = null_mut();
    let result = unsafe {
        CryptUnprotectData(
            &input,
            &mut description,
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    let decrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };

    unsafe {
        LocalFree(output.pbData.cast());
        if !description.is_null() {
            LocalFree(description.cast());
        }
    }

    decrypted
        .try_into()
        .map_err(|_| "invalid DPAPI WireGuard private key length".to_string())
}

#[cfg(not(windows))]
fn protect_wireguard_key(private_key: &[u8; 32]) -> Result<String, String> {
    Ok(encode_wireguard_key(private_key))
}

#[cfg(not(windows))]
fn unprotect_wireguard_key(value: &str) -> Result<[u8; 32], String> {
    lattice_crypto::decode_wireguard_key(value)
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub async fn load_or_create_wireguard_key(path: &Path) -> Result<([u8; 32], [u8; 32]), String> {
    static KEY_ACCESS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _key_access = KEY_ACCESS.lock().await;
    let existed = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
                return Err("WireGuard key path rejected; preserve the existing state".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                    return Err("WireGuard key requires private ownership".into());
                }
            }
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => {
            return Err("WireGuard key metadata unavailable; no replacement generated".into());
        }
    };
    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            let stored: StoredWireguardKey = serde_json::from_str(&content)
                .map_err(|_| "WireGuard key state corrupt; no replacement generated")?;
            let priv_key = unprotect_wireguard_key(&stored.private_key_blob)?;
            let pub_key = wireguard_public_key(&priv_key);
            if stored.public_key != encode_wireguard_key(&pub_key) {
                return Err(
                    "WireGuard key pair mismatch; preserve and recover the existing state".into(),
                );
            }
            return Ok((priv_key, pub_key));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !existed => {}
        Err(_) => return Err("WireGuard key unavailable; no replacement generated".into()),
    }

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }

    let (priv_bytes, pub_bytes) = generate_wireguard_keypair();
    let blob = protect_wireguard_key(&priv_bytes)?;
    let stored = StoredWireguardKey {
        public_key: encode_wireguard_key(&pub_bytes),
        private_key_blob: blob,
    };

    let content = serde_json::to_vec_pretty(&stored).map_err(|e| e.to_string())?;
    write_atomic(path, &content).await?;

    Ok((priv_bytes, pub_bytes))
}

/// Import an explicitly adopted transport without replacing any existing file.
pub(crate) fn import_wireguard_key(path: &Path, private: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    let stored = StoredWireguardKey {
        public_key: encode_wireguard_key(&wireguard_public_key(private)),
        private_key_blob: protect_wireguard_key(private)?,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "adoption will not replace an existing transport key")?;
    file.write_all(
        &serde_json::to_vec(&stored).map_err(|_| "transport import serialization failed")?,
    )
    .map_err(|_| "transport import write failed")?;
    file.sync_all()
        .map_err(|_| "transport import sync failed")?;
    #[cfg(unix)]
    std::fs::File::open(path.parent().ok_or("transport directory required")?)
        .and_then(|d| d.sync_all())
        .map_err(|_| "transport import directory sync failed")?;
    Ok(())
}

pub async fn load_journal(path: &Path) -> NetworkJournal {
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return NetworkJournal::default();
    };
    serde_json::from_str::<NetworkJournal>(&content).unwrap_or_default()
}

pub async fn save_journal(path: &Path, journal: &NetworkJournal) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let content = serde_json::to_vec_pretty(journal).map_err(|e| e.to_string())?;
    write_atomic(path, &content).await
}

pub async fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");
    tokio::fs::write(&tmp_path, content)
        .await
        .map_err(|e| e.to_string())?;
    secure_file(&tmp_path)?;
    {
        let file = std::fs::File::open(&tmp_path).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
    }
    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|e| e.to_string())?;
    secure_file(path)
}

pub(crate) async fn clear_bootstrap_state(state: &AppState) -> Result<(), String> {
    crate::network_manager::disconnect(state, None).await?;
    save_journal(&state.network_journal_path, &NetworkJournal::default()).await?;
    save_peers_cache(&state.network_peers_path, &NetworkPeersCache::default()).await
}

pub fn configured_interface_name() -> String {
    std::env::var("LATTICE_NETWORK_INTERFACE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "wg-lattice".to_string())
}

pub fn active_interface_name() -> String {
    let logical = configured_interface_name();
    #[cfg(target_os = "macos")]
    if let Ok(name) = std::fs::read_to_string(format!("/var/run/wireguard/{logical}.name")) {
        let name = name.trim();
        if name
            .strip_prefix("utun")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            return name.into();
        }
    }
    logical
}

pub fn wg_quick_command() -> String {
    wg_quick_from(std::env::var("LATTICE_WG_QUICK").ok())
}

fn wg_quick_from(value: Option<String>) -> String {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "wg-quick".to_string())
}

pub fn interface_conf_path(config_dir: &Path, interface_name: &str) -> PathBuf {
    config_dir.join(format!("{interface_name}.conf"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coordinator {
    pub url: String,
    pub public_key: String,
}

pub fn select_coordinator(
    bootstrap: Option<(String, String)>,
    control: Option<(String, String)>,
) -> Option<Coordinator> {
    if let Some((url, public_key)) = bootstrap {
        return Some(Coordinator { url, public_key });
    }
    control.map(|(url, public_key)| Coordinator { url, public_key })
}

pub fn render_node_wireguard_config(
    virtual_ipv4: &str,
    private_key: &[u8; 32],
    gateway_pubkey: &str,
    gateway_endpoint: &str,
    overlay_cidr: &str,
    keepalive_secs: u16,
) -> String {
    render_direct_wireguard_config(
        virtual_ipv4,
        private_key,
        gateway_pubkey,
        gateway_endpoint,
        overlay_cidr,
        keepalive_secs,
        gateway_endpoint
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(""),
        &[],
    )
}

pub fn render_direct_wireguard_config(
    virtual_ipv4: &str,
    private_key: &[u8; 32],
    gateway_pubkey: &str,
    gateway_endpoint: &str,
    overlay_cidr: &str,
    keepalive_secs: u16,
    gateway_ipv4: &str,
    direct_peers: &[NetworkPeerEntry],
) -> String {
    let priv_b64 = encode_wireguard_key(private_key);
    let mut out = format!(
        r#"[Interface]
PrivateKey = {priv_b64}
Address = {virtual_ipv4}

[Peer]
PublicKey = {gateway_pubkey}
Endpoint = {gateway_endpoint}
AllowedIPs = {overlay_cidr}
PersistentKeepalive = {keepalive_secs}
"#
    );

    let desired = NetworkDesiredConfig {
        schema_version: 1,
        node_id: "render-local".into(),
        control_id: "render-control".into(),
        network_id: "render-network".into(),
        revision: 1,
        enabled: true,
        status: NetworkNodeStatus::Allocated,
        virtual_ipv4: Some(virtual_ipv4.into()),
        overlay_cidr: Some(overlay_cidr.into()),
        gateway_ipv4: Some(gateway_ipv4.into()),
        gateway_endpoint: Some(gateway_endpoint.into()),
        gateway_wireguard_public_key: Some(gateway_pubkey.into()),
        allowed_overlay_routes: vec![overlay_cidr.into()],
        keepalive_seconds: keepalive_secs,
        issued_at_ms: 0,
    };
    let mut sorted = direct_peers.to_vec();
    sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let mut keys = std::collections::BTreeSet::new();
    let mut addresses = std::collections::BTreeSet::new();
    let own_key = encode_wireguard_key(&wireguard_public_key(private_key));
    for peer in sorted {
        if !lattice_network::valid_direct_peer(&desired, &peer)
            || peer.wireguard_public_key == own_key
            || !keys.insert(peer.wireguard_public_key.clone())
            || !addresses.insert(peer.virtual_ipv4.clone())
        {
            continue;
        }
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("# NodeId = {}\n", peer.node_id));
        out.push_str(&format!("PublicKey = {}\n", peer.wireguard_public_key));
        if let Some(endpoint) = peer.endpoint_candidates.first() {
            out.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        out.push_str(&format!("AllowedIPs = {}\n", peer.virtual_ipv4));
        out.push_str(&format!("PersistentKeepalive = {keepalive_secs}\n"));
    }

    out
}

pub fn discover_endpoint_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(raw) = std::env::var("LATTICE_NETWORK_ADVERTISED_ENDPOINT") {
        for entry in raw.split(',') {
            let value = entry.trim();
            if !value.is_empty() && value.contains(':') && value.len() <= 256 {
                if !candidates.contains(&value.to_string()) {
                    candidates.push(value.to_string());
                }
            }
            if candidates.len() >= 8 {
                break;
            }
        }
    }
    candidates
}

pub fn parse_wg_handshakes(output: &str) -> Vec<(String, u64)> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let key = parts.next()?.to_string();
            let handshake = parts.next()?.parse::<u64>().ok()?;
            Some((key, handshake))
        })
        .collect()
}

pub fn parse_wg_dump(output: &str) -> (Option<u64>, u64, u64, usize) {
    let mut latest_secs = 0u64;
    let mut total_rx = 0u64;
    let mut total_tx = 0u64;
    let mut peer_lines = 0usize;
    for (index, line) in output.lines().enumerate() {
        if index == 0 && !line.contains('\t') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 7 {
            continue;
        }
        if index == 0 && parts.len() == 4 {
            continue;
        }
        peer_lines += 1;
        if let Ok(handshake) = parts[4].trim().parse::<u64>() {
            latest_secs = latest_secs.max(handshake);
        }
        total_rx = total_rx.saturating_add(parts[5].trim().parse::<u64>().unwrap_or(0));
        total_tx = total_tx.saturating_add(parts[6].trim().parse::<u64>().unwrap_or(0));
    }
    let latest_ms = if latest_secs == 0 {
        None
    } else {
        Some(latest_secs.saturating_mul(1000))
    };
    (latest_ms, total_rx, total_tx, peer_lines)
}

pub fn handshake_is_fresh(handshake_epoch: u64, now_epoch: u64) -> bool {
    if handshake_epoch == 0 {
        return false;
    }
    now_epoch.saturating_sub(handshake_epoch) <= 180
}

pub fn select_gateway_endpoint(primary: &str, relays: &[String], failure_count: u32) -> String {
    if failure_count == 0 || relays.is_empty() {
        return primary.to_string();
    }
    let index = ((failure_count as usize) - 1) % relays.len();
    relays[index].clone()
}

pub async fn punch_peer_endpoints(candidates: &[String]) {
    for endpoint in candidates.iter().take(16) {
        if let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            let _ = socket.send_to(b"lattice-punch", endpoint).await;
        }
    }
}

pub(crate) async fn refresh_wireguard_telemetry(state: &Arc<AppState>) -> bool {
    let interface_name = active_interface_name();
    let output = tokio::process::Command::new("wg")
        .args(["show", interface_name.as_str(), "dump"])
        .output()
        .await;
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let (latest_ms, total_rx, total_tx, _) = parse_wg_dump(&text);
    let mut status = state.network_status.write().await;
    if latest_ms.is_some() {
        status.last_handshake_ms = latest_ms;
    }
    status.bytes_rx = total_rx;
    status.bytes_tx = total_tx;
    status.interface_name = Some(interface_name);
    true
}

pub fn strip_wg_quick_only_directives(rendered_conf: &str) -> String {
    rendered_conf
        .lines()
        .filter(|line| {
            let key = line.split('=').next().unwrap_or("").trim().to_lowercase();
            key != "address" && key != "dns"
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

pub fn parse_ip_addr_show(output: &str) -> Vec<(String, u8, String)> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _index = parts.next()?;
            let iface = parts.next()?.to_string();
            if parts.next()? != "inet" {
                return None;
            }
            let addr = parts.next()?;
            let (ip, prefix) = addr.split_once('/')?;
            let prefix: u8 = prefix.parse().ok()?;
            Some((ip.to_string(), prefix, iface))
        })
        .collect()
}

pub fn overlay_contains_ip(overlay_cidr: &str, ip_str: &str) -> bool {
    let Some((net_str, prefix_str)) = overlay_cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(prefix)) = (
        net_str.parse::<std::net::Ipv4Addr>(),
        prefix_str.parse::<u8>(),
    ) else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

pub fn find_conflicting_overlay_addrs(
    ip_addr_output: &str,
    overlay_cidr: &str,
    interface_name: &str,
) -> Vec<String> {
    parse_ip_addr_show(ip_addr_output)
        .into_iter()
        .filter(|(ip, _, iface)| iface != interface_name && overlay_contains_ip(overlay_cidr, ip))
        .map(|(ip, prefix, iface)| format!("{ip}/{prefix} on {iface}"))
        .collect()
}

pub fn validate_desired_config(config: &NetworkDesiredConfig) -> Result<(), String> {
    lattice_network::validate_base_desired_config(config)
}

pub async fn render_current_config(
    desired: &NetworkDesiredConfig,
    private_key: &[u8; 32],
    peers_path: &Path,
) -> Result<(String, Vec<NetworkPeerEntry>), String> {
    validate_desired_config(desired)?;

    let virtual_ip = desired.virtual_ipv4.as_deref().unwrap_or_default();
    let gw_pub = desired
        .gateway_wireguard_public_key
        .as_deref()
        .unwrap_or_default();
    let gw_ep = desired.gateway_endpoint.as_deref().unwrap_or_default();
    let overlay_cidr = desired.overlay_cidr.as_deref().unwrap_or_default();
    let keepalive = desired.keepalive_seconds;

    let peers_cache = load_peers_cache(peers_path).await;
    let direct_peers = if peers_cache.path_policy == "direct" {
        peers_cache.peers.clone()
    } else {
        Vec::new()
    };

    let rendered = render_direct_wireguard_config(
        virtual_ip,
        private_key,
        gw_pub,
        gw_ep,
        overlay_cidr,
        keepalive,
        desired.gateway_ipv4.as_deref().unwrap_or_default(),
        &direct_peers,
    );
    lattice_network::validate_base_configuration(
        desired,
        &configured_interface_name(),
        &encode_wireguard_key(&wireguard_public_key(private_key)),
        &rendered,
    )?;
    Ok((rendered, direct_peers))
}

pub async fn existing_conf_matches(rendered: &str, journal: &NetworkJournal) -> bool {
    #[cfg(not(target_os = "macos"))]
    let _ = journal;
    #[cfg(any(target_os = "linux", windows))]
    let interface_name = configured_interface_name();

    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from("/etc/wireguard").join(format!("{interface_name}.conf"));
        let Ok(existing) = tokio::fs::read_to_string(&path).await else {
            return false;
        };
        return existing == strip_wg_quick_only_directives(rendered);
    }

    #[cfg(windows)]
    {
        let root = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Lattice");
        let path = root.join(format!("{interface_name}.conf"));
        let Ok(existing) = tokio::fs::read_to_string(&path).await else {
            return false;
        };
        return existing == rendered;
    }

    #[cfg(target_os = "macos")]
    {
        let Some(conf) = journal.interface_conf.as_deref() else {
            return false;
        };
        let Ok(existing) = tokio::fs::read_to_string(conf).await else {
            return false;
        };
        return existing == rendered;
    }

    #[allow(unreachable_code)]
    {
        let _ = (rendered, journal);
        false
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) async fn apply_network_config(
    desired: &NetworkDesiredConfig,
    private_key: &[u8; 32],
    peers_path: &Path,
    conf_path: &Path,
) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    let _ = conf_path;

    let (rendered_conf, direct_peers) =
        render_current_config(desired, private_key, peers_path).await?;

    #[cfg(any(target_os = "linux", windows))]
    let overlay_cidr = desired.overlay_cidr.as_deref().unwrap_or_default();
    let punch_targets = direct_peers
        .iter()
        .flat_map(|peer| peer.endpoint_candidates.clone())
        .take(16)
        .collect::<Vec<_>>();
    if !punch_targets.is_empty() {
        punch_peer_endpoints(&punch_targets).await;
    }

    #[cfg(windows)]
    {
        apply_windows_interface(&configured_interface_name(), &rendered_conf, overlay_cidr).await?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        apply_macos_interface(conf_path, &rendered_conf).await?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        let _ = rendered_conf;
        let _ = conf_path;
        Err("WireGuard overlay is not yet supported on this platform".to_string())
    }
}

#[cfg(windows)]
async fn apply_windows_interface(
    interface_name: &str,
    rendered_conf: &str,
    overlay_cidr: &str,
) -> Result<(), String> {
    let root = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Lattice");
    let _ = tokio::fs::create_dir_all(&root).await;
    let conf_path = root.join(format!("{interface_name}.conf"));

    tokio::fs::write(&conf_path, rendered_conf)
        .await
        .map_err(|e| e.to_string())?;

    let conf_path_str = conf_path
        .to_str()
        .ok_or_else(|| "config path is not valid UTF-8".to_string())?;

    let wireguard_exe = PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe");
    if !wireguard_exe.exists() {
        return Err("wireguard.exe not found at expected path".to_string());
    }

    if let Ok(existing) = tokio::fs::read_to_string(&conf_path).await {
        if existing == rendered_conf && tunnel_service_present(interface_name).await {
            apply_windows_firewall_exception(interface_name, overlay_cidr).await?;
            return Ok(());
        }
    }

    let _ = tokio::process::Command::new(&wireguard_exe)
        .args(["/uninstalltunnelservice", interface_name])
        .output()
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let mut attempt = 0u32;
    loop {
        let install_output = tokio::process::Command::new(&wireguard_exe)
            .args(["/installtunnelservice", conf_path_str])
            .output()
            .await
            .map_err(|e| format!("failed to execute wireguard.exe: {e}"))?;

        if install_output.status.success() {
            apply_windows_firewall_exception(interface_name, overlay_cidr).await?;
            return Ok(());
        }

        attempt += 1;
        if attempt >= 3 {
            let stderr = String::from_utf8_lossy(&install_output.stderr);
            return Err(format!(
                "wireguard.exe /installtunnelservice failed: {stderr}"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(windows)]
async fn apply_windows_firewall_exception(
    interface_name: &str,
    overlay_cidr: &str,
) -> Result<(), String> {
    let rule_name = format!("Lattice Overlay ({interface_name})");

    let _ = tokio::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            format!("name={rule_name}").as_str(),
        ])
        .output()
        .await;

    let output = tokio::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            format!("name={rule_name}").as_str(),
            "dir=in",
            "action=allow",
            format!("remoteip={overlay_cidr}").as_str(),
            "description=Lattice overlay peer traffic",
        ])
        .output()
        .await
        .map_err(|e| format!("failed to execute netsh: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "netsh overlay firewall exception failed (node needs administrator rights): {stderr}"
        ));
    }

    Ok(())
}

#[cfg(windows)]
async fn tunnel_service_present(interface_name: &str) -> bool {
    let service = format!("WireGuardTunnel${interface_name}");
    tokio::process::Command::new("sc")
        .args(["query", service.as_str()])
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn can_sync_live_config(previous: &str, next: &str, alive: bool) -> bool {
    let address = |text: &str| {
        text.lines().find_map(|line| {
            let (k, v) = line.split_once('=')?;
            (k.trim() == "Address").then(|| v.trim().to_string())
        })
    };
    alive && address(previous).is_some() && address(previous) == address(next)
}
#[cfg(target_os = "macos")]
async fn force_stop_live_interface(active: &str) -> bool {
    let _ = tokio::process::Command::new("ifconfig")
        .args([active, "down"])
        .output()
        .await;
    let _ = tokio::process::Command::new("pkill")
        .args(["-f", &format!("wireguard-go.*{active}")])
        .output()
        .await;
    let _ = tokio::fs::remove_file(format!(
        "/var/run/wireguard/{}.name",
        configured_interface_name()
    ))
    .await;
    !tokio::process::Command::new("wg")
        .args(["show", active])
        .output()
        .await
        .is_ok_and(|r| r.status.success())
}

#[cfg(target_os = "macos")]
async fn apply_macos_interface(conf_path: &Path, rendered_conf: &str) -> Result<(), String> {
    let previous = tokio::fs::read_to_string(conf_path)
        .await
        .unwrap_or_default();
    let active = active_interface_name();
    let alive = tokio::process::Command::new("wg")
        .args(["show", &active])
        .output()
        .await
        .is_ok_and(|r| r.status.success());
    if can_sync_live_config(&previous, rendered_conf, alive) {
        let sync_path = conf_path.with_extension("sync.conf");
        write_atomic(
            &sync_path,
            strip_wg_quick_only_directives(rendered_conf).as_bytes(),
        )
        .await?;
        let result = tokio::process::Command::new("wg")
            .arg("syncconf")
            .arg(&active)
            .arg(&sync_path)
            .output()
            .await
            .map_err(|_| "WireGuard sync failed")?;
        let _ = tokio::fs::remove_file(sync_path).await;
        if !result.status.success() {
            return Err("WireGuard sync rejected".into());
        }
        return write_atomic(conf_path, rendered_conf.as_bytes()).await;
    }
    if alive {
        if previous.is_empty() {
            // A live interface without a local configuration belongs to an earlier
            // installation or a rolled-back setup. Materialize the target file first so
            // wg-quick has a path it can stop, then recreate the interface below.
            if let Some(parent) = conf_path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            write_atomic(conf_path, rendered_conf.as_bytes()).await?;
        }
        let stopped = tokio::process::Command::new(wg_quick_command())
            .arg("down")
            .arg(conf_path)
            .output()
            .await
            .map_err(|_| "WireGuard stop failed")?;
        if !stopped.status.success() && !force_stop_live_interface(&active).await {
            return Err("WireGuard stop rejected".into());
        }
    }
    if let Some(parent) = conf_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }
    write_atomic(conf_path, rendered_conf.as_bytes()).await?;
    let result = tokio::process::Command::new(wg_quick_command())
        .arg("up")
        .arg(conf_path)
        .output()
        .await;
    if !result.is_ok_and(|r| r.status.success()) {
        if !previous.is_empty() {
            write_atomic(conf_path, previous.as_bytes()).await?;
            if alive {
                let _ = tokio::process::Command::new(wg_quick_command())
                    .arg("up")
                    .arg(conf_path)
                    .output()
                    .await;
            }
        }
        return Err("managed wg-quick startup failed".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) async fn teardown_network_interface(journal_path: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    let _ = journal_path;

    #[cfg(windows)]
    {
        let interface_name = configured_interface_name();
        let wireguard_exe = PathBuf::from(r"C:\Program Files\WireGuard\wireguard.exe");
        if wireguard_exe.exists() {
            let _ = tokio::process::Command::new(wireguard_exe)
                .args(["/uninstalltunnelservice", interface_name.as_str()])
                .output()
                .await;
        }
    }

    #[cfg(target_os = "macos")]
    {
        let journal = load_journal(journal_path).await;
        let conf_path = journal.interface_conf.and_then(|value| {
            let path = PathBuf::from(&value);
            if path.is_absolute() { Some(path) } else { None }
        });
        if let Some(conf_path) = conf_path {
            let conf_path_str = conf_path.to_string_lossy().to_string();
            let _ = tokio::process::Command::new(wg_quick_command())
                .args(["down", conf_path_str.as_str()])
                .output()
                .await;
        }
    }

    Ok(())
}

pub(crate) async fn run(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let base_interval_secs = std::env::var("LATTICE_NETWORK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(2, 300);

    let max_interval_secs = 300u64;
    let mut consecutive_failures = 0u32;

    loop {
        let success = reconcile(&state).await;
        if success {
            consecutive_failures = 0;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
        }

        let factor = 2u64.saturating_pow(consecutive_failures.min(5));
        let backoff_secs = (base_interval_secs.saturating_mul(factor)).min(max_interval_secs);
        let jitter_ms = (Uuid::new_v4().as_u128() as u64) % (backoff_secs * 200 + 1);
        let sleep_duration = Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_ms);

        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {}
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() {
                    // Retain the last authorized plane during a daemon restart.
                    return;
                }
            }
        }
    }
}

pub(crate) async fn send_ack(
    state: &Arc<AppState>,
    node_id: &str,
    node_priv_key: &[u8; 32],
    coordinator_url: &str,
    desired: &NetworkDesiredConfig,
    ack_success: bool,
    ack_error: Option<String>,
) {
    let now_ack = unix_time_ms();
    let ack_seq = next_sequence();
    let ack_claim = NetworkAckClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node_id.to_string(),
        sequence: ack_seq,
        applied_revision: desired.revision,
        success: ack_success,
        error_code: ack_error,
        interface_name: Some(configured_interface_name()),
        assigned_virtual_ipv4: desired.virtual_ipv4.clone(),
        issued_at_ms: now_ack,
    };

    if let Ok(ack_sig) = sign(node_priv_key, &ack_claim) {
        let ack_req = NetworkAckRequest {
            claim: ack_claim,
            signature: ack_sig,
        };
        let _ = state
            .http
            .post(format!("{coordinator_url}/api/v1/network/ack"))
            .json(&ack_req)
            .send()
            .await;
    }
}

pub(crate) async fn reconcile(state: &Arc<AppState>) -> bool {
    let enabled = state.config.read().await.network.enabled;
    if enabled {
        if let Err(error) = crate::network_manager::restore_cached_base(state, None).await {
            let mut status = state.network_status.write().await;
            status.status = NetworkNodeStatus::Degraded;
            status.last_error = Some(error);
            status.error_code = Some("CACHED_NETWORK_APPLY_FAILED".into());
            return false;
        }
    }
    let coordinator = {
        let identity = state.identity.read().await;
        select_coordinator(
            identity.bootstrap().map(|trust| {
                (
                    trust.bootstrap_url.clone(),
                    trust.bootstrap_public_key.clone(),
                )
            }),
            identity
                .trust()
                .map(|trust| (trust.control_url.clone(), trust.control_public_key.clone())),
        )
    };

    let Some(coordinator) = coordinator else {
        let mut status = state.network_status.write().await;
        status.enabled = enabled;
        status.status = NetworkNodeStatus::Unconfigured;
        status.error_code = Some("NOT_ENROLLED".to_string());
        return true;
    };

    if !enabled {
        let mut journal = load_journal(&state.network_journal_path).await;
        if journal.virtual_ipv4.is_some() {
            if let Err(error) = crate::network_manager::disconnect(state, None).await {
                let mut status = state.network_status.write().await;
                status.status = NetworkNodeStatus::Degraded;
                status.last_error = Some(error);
                status.error_code = Some("NETWORK_DISCONNECT_PENDING".into());
                return false;
            }
            journal.virtual_ipv4 = None;
            journal.updated_at_ms = unix_time_ms();
            let _ = save_journal(&state.network_journal_path, &journal).await;
        }
        let mut status = state.network_status.write().await;
        status.enabled = false;
        status.status = NetworkNodeStatus::Disabled;
        status.virtual_ipv4 = None;
        return true;
    }

    let pub_wg_key = match crate::network_manager::transport_public_key(state).await {
        Ok(keys) => keys,
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.status = NetworkNodeStatus::Degraded;
            status.last_error = Some(format!("failed to load wireguard keys: {e}"));
            status.error_code = Some("APPLY_FAILED".to_string());
            return false;
        }
    };

    let wg_pub_str = encode_wireguard_key(&pub_wg_key);

    let (node_id, node_priv_key) = {
        let id_guard = state.identity.read().await;
        (id_guard.identity().node_id.clone(), *id_guard.private_key())
    };

    let mut journal = load_journal(&state.network_journal_path).await;

    let now = unix_time_ms();
    let reg_seq = next_sequence();
    let reg_claim = NetworkRegisterClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node_id.clone(),
        sequence: reg_seq,
        wireguard_public_key: wg_pub_str.clone(),
        local_opt_in: true,
        issued_at_ms: now,
    };

    let reg_sig = match sign(&node_priv_key, &reg_claim) {
        Ok(s) => s,
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("failed to sign register claim: {e}"));
            status.error_code = Some("APPLY_FAILED".to_string());
            return false;
        }
    };

    let reg_req = NetworkRegisterRequest {
        claim: reg_claim,
        signature: reg_sig,
    };

    let reg_resp = state
        .http
        .post(format!("{}/api/v1/network/register", coordinator.url))
        .json(&reg_req)
        .send()
        .await;

    match reg_resp {
        Ok(resp) if !resp.status().is_success() => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("register HTTP error {}", resp.status()));
            status.error_code = Some("ENDPOINT_UNREACHABLE".to_string());
            return false;
        }
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("register request failed: {e}"));
            status.error_code = Some("ENDPOINT_UNREACHABLE".to_string());
            return false;
        }
        _ => {}
    }

    let now_sync = unix_time_ms();
    let sync_seq = next_sequence();
    let sync_claim = NetworkSyncClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node_id.clone(),
        sequence: sync_seq,
        last_applied_revision: journal.last_applied_revision,
        issued_at_ms: now_sync,
    };

    let sync_sig = match sign(&node_priv_key, &sync_claim) {
        Ok(s) => s,
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("failed to sign sync claim: {e}"));
            status.error_code = Some("APPLY_FAILED".to_string());
            return false;
        }
    };

    let sync_req = NetworkSyncRequest {
        claim: sync_claim,
        signature: sync_sig,
    };

    let sync_resp_raw = match state
        .http
        .post(format!("{}/api/v1/network/sync", coordinator.url))
        .json(&sync_req)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("sync request failed: {e}"));
            status.error_code = Some("ENDPOINT_UNREACHABLE".to_string());
            return false;
        }
    };

    if !sync_resp_raw.status().is_success() {
        let mut status = state.network_status.write().await;
        status.last_error = Some(format!("sync HTTP error {}", sync_resp_raw.status()));
        status.error_code = Some("ENDPOINT_UNREACHABLE".to_string());
        return false;
    }

    let sync_resp: NetworkSyncResponse = match sync_resp_raw.json().await {
        Ok(r) => r,
        Err(e) => {
            let mut status = state.network_status.write().await;
            status.last_error = Some(format!("failed to parse sync response: {e}"));
            status.error_code = Some("APPLY_FAILED".to_string());
            return false;
        }
    };

    let desired_signed = &sync_resp.desired_config;
    if let Err(e) = verify(
        &coordinator.public_key,
        &desired_signed.signature,
        &desired_signed.config,
    ) {
        let mut status = state.network_status.write().await;
        status.status = NetworkNodeStatus::Degraded;
        status.last_error = Some(format!("tampered desired config signature: {e}"));
        status.error_code = Some("ACL_DENIED".to_string());
        return false;
    }

    let desired = &desired_signed.config;
    if desired.node_id != node_id {
        let mut status = state.network_status.write().await;
        status.status = NetworkNodeStatus::Degraded;
        status.last_error = Some("mismatched node_id in desired config".to_string());
        status.error_code = Some("ACL_DENIED".to_string());
        return false;
    }

    let forwarding_enabled = { state.modules.lock().await.forwarding_budget().is_some() };
    if forwarding_enabled {
        if let Some(intent) = sync_resp.gateway_intent.clone() {
            if let Err(error) = crate::network_manager::submit_gateway(
                state,
                intent,
                &lattice_network::SystemRunner,
            )
            .await
            {
                let mut status = state.network_status.write().await;
                status.status = NetworkNodeStatus::Degraded;
                status.last_error = Some(error);
                status.error_code = Some("RELAY_APPLY_FAILED".into());
                return false;
            }
        }
    }

    if desired.revision < journal.last_applied_revision {
        let mut status = state.network_status.write().await;
        status.status = NetworkNodeStatus::Degraded;
        status.last_error = Some(format!(
            "revision downgrade rejected: desired {} < applied {}",
            desired.revision, journal.last_applied_revision
        ));
        return false;
    }

    if !desired.enabled {
        if let Err(error) = crate::network_manager::remember_disabled(
            state,
            desired_signed,
            &coordinator.public_key,
        )
        .await
        {
            state.network_status.write().await.last_error = Some(error);
            return false;
        }
        if journal.virtual_ipv4.is_some() {
            if let Err(error) = crate::network_manager::disconnect(state, None).await {
                let mut status = state.network_status.write().await;
                status.status = NetworkNodeStatus::Degraded;
                status.last_error = Some(error);
                status.error_code = Some("NETWORK_DISCONNECT_PENDING".into());
                return false;
            }
            journal.virtual_ipv4 = None;
            journal.last_applied_revision = desired.revision;
            journal.updated_at_ms = unix_time_ms();
            let _ = save_journal(&state.network_journal_path, &journal).await;
        }

        let mut status = state.network_status.write().await;
        status.status = desired.status.clone();
        status.assigned_revision = desired.revision;
        status.virtual_ipv4 = None;
        status.last_error = None;
        return true;
    }

    {
        let mut status = state.network_status.write().await;
        status.assigned_revision = desired.revision;
        status.status = NetworkNodeStatus::Applying;
    }

    report_endpoint_candidates(state, &node_id, &node_priv_key, &coordinator.url).await;

    let conf_path = state
        .network_journal_path
        .parent()
        .map(|parent| interface_conf_path(parent, &configured_interface_name()))
        .unwrap_or_else(|| PathBuf::from("wg-lattice.conf"));
    let apply_res = crate::network_manager::apply_base_configuration(
        state,
        desired_signed,
        &coordinator.public_key,
        None,
    )
    .await;
    let ack_success = apply_res.is_ok();
    let ack_error = apply_res.err();

    send_ack(
        state,
        &node_id,
        &node_priv_key,
        &coordinator.url,
        desired,
        ack_success,
        ack_error.clone(),
    )
    .await;

    if ack_success {
        journal.last_applied_revision = desired.revision;
        journal.last_acked_revision = desired.revision;
        journal.virtual_ipv4 = desired.virtual_ipv4.clone();
        journal.overlay_cidr = desired.overlay_cidr.clone();
        journal.gateway_ipv4 = desired.gateway_ipv4.clone();
        journal.gateway_endpoint = desired.gateway_endpoint.clone();
        journal.gateway_wireguard_public_key = desired.gateway_wireguard_public_key.clone();
        journal.last_error = None;
        journal.interface_conf = conf_path.to_str().map(|value| value.to_string());
        journal.updated_at_ms = unix_time_ms();
        let _ = save_journal(&state.network_journal_path, &journal).await;

        refresh_peers_cache(
            state,
            &node_id,
            &node_priv_key,
            &coordinator.url,
            &coordinator.public_key,
        )
        .await;

        let peers_cache = load_peers_cache(&state.network_peers_path).await;
        {
            let mut status = state.network_status.write().await;
            status.status = NetworkNodeStatus::Connected;
            status.applied_revision = desired.revision;
            status.virtual_ipv4 = desired.virtual_ipv4.clone();
            status.last_error = None;
            status.error_code = None;
            status.peer_count = peers_cache.peers.len() as u64;
            status.path_policy = peers_cache.path_policy.clone();
            status.interface_name = Some(configured_interface_name());
            status.gateway_endpoint = desired.gateway_endpoint.clone();
        }
        refresh_wireguard_telemetry(state).await;
        {
            let status = state.network_status.read().await;
            if status.status == NetworkNodeStatus::Connected
                && status.last_handshake_ms.is_none()
                && status.bytes_rx == 0
                && status.bytes_tx == 0
            {
                drop(status);
                let mut status = state.network_status.write().await;
                status.error_code = Some("HANDSHAKE_STALE".to_string());
            }
        }
        true
    } else {
        journal.last_error = ack_error.clone();
        journal.updated_at_ms = unix_time_ms();
        let _ = save_journal(&state.network_journal_path, &journal).await;

        let mut status = state.network_status.write().await;
        status.status = NetworkNodeStatus::Degraded;
        status.last_error = ack_error;
        status.error_code = Some("APPLY_FAILED".to_string());
        false
    }
}

pub(crate) async fn report_endpoint_candidates(
    state: &Arc<AppState>,
    node_id: &str,
    node_priv_key: &[u8; 32],
    control_url: &str,
) {
    use lattice_protocol::{NetworkCandidatesClaim, NetworkCandidatesRequest};

    let candidates = discover_endpoint_candidates();
    if candidates.is_empty() {
        return;
    }
    let now = unix_time_ms();
    let sequence = next_sequence();
    let claim = NetworkCandidatesClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node_id.to_string(),
        sequence,
        endpoint_candidates: candidates,
        issued_at_ms: now,
    };
    let signature = match sign(node_priv_key, &claim) {
        Ok(value) => value,
        Err(_) => return,
    };
    let _ = state
        .http
        .post(format!("{control_url}/api/v1/network/candidates"))
        .json(&NetworkCandidatesRequest { claim, signature })
        .send()
        .await;
}

pub(crate) async fn refresh_peers_cache(
    state: &Arc<AppState>,
    node_id: &str,
    node_priv_key: &[u8; 32],
    control_url: &str,
    coordinator_key: &str,
) {
    let now = unix_time_ms();
    let sequence = next_sequence();
    let claim = NetworkPeersClaim {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: Uuid::new_v4().to_string(),
        node_id: node_id.to_string(),
        sequence,
        issued_at_ms: now,
    };
    let signature = match sign(node_priv_key, &claim) {
        Ok(value) => value,
        Err(_) => return,
    };
    let request = NetworkPeersRequest { claim, signature };
    let response = state
        .http
        .post(format!("{control_url}/api/v1/network/peers"))
        .json(&request)
        .send()
        .await;
    let response = match response {
        Ok(value) => value,
        Err(_) => return,
    };
    if !response.status().is_success() {
        return;
    }
    let peers: NetworkPeersResponse = match response.json().await {
        Ok(value) => value,
        Err(_) => return,
    };
    let control_key = coordinator_key.to_string();
    if verify(&control_key, &peers.signature, &peers.signature_data()).is_err()
        && verify(&control_key, &peers.signature, &peers.receipt).is_err()
    {
        return;
    }
    if peers.receipt.node_id != node_id {
        return;
    }
    let cache = NetworkPeersCache {
        peers: peers.peers,
        path_policy: peers.path_policy,
        updated_at_ms: unix_time_ms(),
    };
    let _ = save_peers_cache(&state.network_peers_path, &cache).await;
    let mut status = state.network_status.write().await;
    status.peer_count = cache.peers.len() as u64;
    status.path_policy = cache.path_policy.clone();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_node_wireguard_config_format() {
        let priv_key = [7u8; 32];
        let gw_pub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let rendered = render_node_wireguard_config(
            "10.240.0.2/32",
            &priv_key,
            gw_pub,
            "198.51.100.1:51820",
            "10.240.0.0/16",
            25,
        );

        assert!(rendered.contains("[Interface]"));
        assert!(rendered.contains("Address = 10.240.0.2/32"));
        assert!(rendered.contains("[Peer]"));
        assert!(rendered.contains("Endpoint = 198.51.100.1:51820"));
        assert!(rendered.contains("AllowedIPs = 10.240.0.0/16"));
        assert!(rendered.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn desired_config_validation_rules() {
        let mut config = NetworkDesiredConfig {
            schema_version: 1,
            node_id: "test-node".to_string(),
            control_id: "test-control".to_string(),
            network_id: "lattice-main".to_string(),
            revision: 1,
            enabled: true,
            status: NetworkNodeStatus::Allocated,
            virtual_ipv4: Some("10.240.0.5/32".to_string()),
            overlay_cidr: Some("10.240.0.0/16".to_string()),
            gateway_ipv4: Some("10.240.0.1".to_string()),
            gateway_endpoint: Some("198.51.100.1:51820".to_string()),
            gateway_wireguard_public_key: Some(encode_wireguard_key(&wireguard_public_key(
                &[6; 32],
            ))),
            allowed_overlay_routes: vec!["10.240.0.0/16".to_string()],
            keepalive_seconds: 25,
            issued_at_ms: unix_time_ms(),
        };

        assert!(validate_desired_config(&config).is_ok());

        config.virtual_ipv4 = Some("invalid-ip".to_string());
        assert!(validate_desired_config(&config).is_err());

        config.virtual_ipv4 = Some("10.240.0.5/32".to_string());
        config.gateway_wireguard_public_key = Some("invalid-base64".to_string());
        assert!(validate_desired_config(&config).is_err());
    }

    #[test]
    fn interface_name_defaults_to_wg_lattice() {
        unsafe {
            std::env::remove_var("LATTICE_NETWORK_INTERFACE");
        }
        assert_eq!(configured_interface_name(), "wg-lattice");
    }

    #[test]
    fn direct_wireguard_config_adds_specific_peer_routes() {
        let priv_key = [9u8; 32];
        let peer = NetworkPeerEntry {
            node_id: "node-b".to_string(),
            virtual_ipv4: "10.77.0.3/32".to_string(),
            wireguard_public_key: encode_wireguard_key(&[5u8; 32]),
            status: NetworkNodeStatus::Connected,
            revision: 2,
            updated_at_ms: 1000,
            endpoint_candidates: vec!["203.0.113.10:51820".to_string()],
        };
        let rendered = render_direct_wireguard_config(
            "10.77.0.2/32",
            &priv_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "10.77.0.1:51820",
            "10.77.0.0/16",
            25,
            "10.77.0.1",
            &[peer],
        );
        assert!(rendered.contains("AllowedIPs = 10.77.0.0/16"));
        assert!(rendered.contains("AllowedIPs = 10.77.0.3/32"));
        assert!(rendered.contains("Endpoint = 203.0.113.10:51820"));
        assert!(rendered.contains("# NodeId = node-b"));
    }

    #[test]
    fn direct_peer_metadata_cannot_inject_configuration_or_override_the_gateway() {
        let peer = NetworkPeerEntry {
            node_id: "node-b\nPostUp = unwanted-command".into(),
            virtual_ipv4: "10.77.0.3/32".into(),
            wireguard_public_key: encode_wireguard_key(&[5; 32]),
            status: NetworkNodeStatus::Connected,
            revision: 1,
            updated_at_ms: 1000,
            endpoint_candidates: vec!["203.0.113.1:51820".into()],
        };
        for case in 0..4 {
            let mut bad = peer.clone();
            match case {
                0 => {}
                1 => {
                    bad.node_id = "node-b".into();
                    bad.virtual_ipv4 = "0.0.0.0/0".into();
                }
                2 => {
                    bad.node_id = "node-b".into();
                    bad.endpoint_candidates =
                        vec!["203.0.113.1:51820\nPostUp = unwanted-command".into()];
                }
                _ => {
                    bad.node_id = "node-b".into();
                    bad.virtual_ipv4 = "10.77.0.1/32".into();
                }
            }
            let text = render_direct_wireguard_config(
                "10.77.0.2/32",
                &[9; 32],
                &encode_wireguard_key(&[7; 32]),
                "10.77.0.1:51820",
                "10.77.0.0/16",
                25,
                "10.77.0.1",
                &[bad],
            );
            assert_eq!(
                text.matches("[Peer]").count(),
                1,
                "invalid peer case {case} must be excluded"
            );
            assert!(!text.contains("PostUp"));
        }
    }

    #[test]
    fn handshake_parsing_and_freshness_rules() {
        let output = "PUBKEY1== 1700000000\nPUBKEY2== 0\n";
        let parsed = parse_wg_handshakes(output);
        assert_eq!(parsed.len(), 2);
        assert!(handshake_is_fresh(1700000000, 1700000100));
        assert!(!handshake_is_fresh(0, 1700000100));
        assert!(!handshake_is_fresh(1700000000, 1700000500));
    }

    #[test]
    fn gateway_selection_falls_back_to_relays() {
        let relays = vec!["relay1:51820".to_string(), "relay2:51820".to_string()];
        assert_eq!(
            select_gateway_endpoint("primary:51820", &relays, 0),
            "primary:51820"
        );
        assert_eq!(
            select_gateway_endpoint("primary:51820", &relays, 1),
            "relay1:51820"
        );
        assert_eq!(
            select_gateway_endpoint("primary:51820", &relays, 2),
            "relay2:51820"
        );
        assert_eq!(
            select_gateway_endpoint("primary:51820", &relays, 3),
            "relay1:51820"
        );
    }

    #[test]
    fn wg_dump_parsing_sums_transfers_and_latest_handshake() {
        let output = "priv\tpub\t51820\toff\nPEER1==\t-\t1.2.3.4:51820\t10.77.0.3/32\t1700000000\t1024\t2048\toff\nPEER2==\t-\t5.6.7.8:51820\t10.77.0.4/32\t1700000100\t512\t256\toff\n";
        let (latest_ms, rx, tx, peers) = parse_wg_dump(output);
        assert_eq!(latest_ms, Some(1700000100 * 1000));
        assert_eq!(rx, 1536);
        assert_eq!(tx, 2304);
        assert_eq!(peers, 2);
    }

    #[test]
    fn wg_dump_with_no_handshake_reports_none() {
        let output = "priv\tpub\t51820\toff\nPEER1==\t-\t-\t10.77.0.3/32\t0\t0\t0\toff\n";
        let (latest_ms, rx, tx, peers) = parse_wg_dump(output);
        assert_eq!(latest_ms, None);
        assert_eq!(rx, 0);
        assert_eq!(tx, 0);
        assert_eq!(peers, 1);
    }

    #[tokio::test]
    async fn wireguard_key_persistence_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("lattice-node-key-test-{}", Uuid::new_v4()));
        let key_path = temp_dir.join("network_wireguard.json");

        let (priv1, pub1) = load_or_create_wireguard_key(&key_path).await.unwrap();
        assert_eq!(wireguard_public_key(&priv1), pub1);

        let (priv2, pub2) = load_or_create_wireguard_key(&key_path).await.unwrap();
        assert_eq!(priv1, priv2);
        assert_eq!(pub1, pub2);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn journal_persistence_roundtrip() {
        let temp_dir =
            std::env::temp_dir().join(format!("lattice-node-journal-test-{}", Uuid::new_v4()));
        let journal_path = temp_dir.join("network_journal.json");

        let initial = load_journal(&journal_path).await;
        assert_eq!(initial.last_applied_revision, 0);

        let updated = NetworkJournal {
            last_applied_revision: 5,
            virtual_ipv4: Some("10.240.0.12/32".to_string()),
            ..Default::default()
        };
        save_journal(&journal_path, &updated).await.unwrap();

        let loaded = load_journal(&journal_path).await;
        assert_eq!(loaded.last_applied_revision, 5);
        assert_eq!(loaded.virtual_ipv4, Some("10.240.0.12/32".to_string()));

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn network_sequences_are_strictly_monotonic() {
        let first = next_sequence();
        for _ in 0..100 {
            let next = next_sequence();
            assert!(next > first);
        }
        let mut previous = next_sequence();
        for _ in 0..100 {
            let next = next_sequence();
            assert!(next > previous);
            previous = next;
        }
    }

    #[test]
    fn coordinator_prefers_bootstrap_over_control() {
        let bootstrap = Some(("https://boot.test".to_string(), "BOOTKEY".to_string()));
        let control = Some(("https://master.test".to_string(), "MASTERKEY".to_string()));
        let selected = select_coordinator(bootstrap, control).unwrap();
        assert_eq!(selected.url, "https://boot.test");
        assert_eq!(selected.public_key, "BOOTKEY");

        let fallback = select_coordinator(
            None,
            Some(("https://master.test".to_string(), "K".to_string())),
        )
        .unwrap();
        assert_eq!(fallback.url, "https://master.test");

        assert!(select_coordinator(None, None).is_none());
    }

    #[test]
    fn setconf_input_strips_wg_quick_only_directives() {
        let rendered = "[Interface]\nPrivateKey = ABC=\nAddress = 10.77.0.4/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = XYZ=\nEndpoint = 192.168.2.240:51820\nAllowedIPs = 10.77.0.0/16\nPersistentKeepalive = 25\n";
        let stripped = strip_wg_quick_only_directives(rendered);
        assert!(stripped.contains("PrivateKey = ABC="));
        assert!(stripped.contains("PublicKey = XYZ="));
        assert!(stripped.contains("Endpoint = 192.168.2.240:51820"));
        assert!(!stripped.contains("Address"));
        assert!(!stripped.contains("DNS"));
    }

    #[test]
    fn overlay_conflict_detection_ignores_own_interface() {
        let output = "1: lo    inet 127.0.0.1/8 scope host lo valid_lft forever preferred_lft forever\n4: lattice0    inet 10.77.0.1/16 scope global lattice0 valid_lft forever preferred_lft forever\n5: wg-lattice    inet 10.77.0.6/32 scope global wg-lattice valid_lft forever preferred_lft forever\n6: enp1s0    inet 192.168.2.240/24 brd 192.168.2.255 scope global dynamic enp1s0 valid_lft forever preferred_lft forever\n";
        let conflicts = find_conflicting_overlay_addrs(output, "10.77.0.0/16", "wg-lattice");
        assert_eq!(conflicts, vec!["10.77.0.1/16 on lattice0".to_string()]);

        let clean = find_conflicting_overlay_addrs(output, "10.77.0.0/16", "lattice0");
        assert!(clean.iter().any(|entry| entry.contains("10.77.0.6/32")));

        let none = find_conflicting_overlay_addrs(
            "1: lo    inet 127.0.0.1/8 scope host lo valid_lft forever\n",
            "10.77.0.0/16",
            "wg-lattice",
        );
        assert!(none.is_empty());
    }

    #[test]
    fn overlay_cidr_membership_checks_bounds() {
        assert!(overlay_contains_ip("10.77.0.0/16", "10.77.0.4"));
        assert!(overlay_contains_ip("10.77.0.0/16", "10.77.255.9"));
        assert!(!overlay_contains_ip("10.77.0.0/16", "10.78.0.1"));
        assert!(!overlay_contains_ip("10.77.0.0/16", "192.168.2.1"));
        assert!(!overlay_contains_ip("10.77.0.0/16", "not-an-ip"));
        assert!(!overlay_contains_ip("broken", "10.77.0.1"));
        assert!(!overlay_contains_ip("10.77.0.0/33", "10.77.0.1"));
    }

    #[test]
    fn wg_quick_command_supports_env_override() {
        assert_eq!(wg_quick_from(None), "wg-quick");
        assert_eq!(wg_quick_from(Some(String::new())), "wg-quick");
        assert_eq!(wg_quick_from(Some("   ".to_string())), "wg-quick");
        assert_eq!(
            wg_quick_from(Some("custom-wg-quick".to_string())),
            "custom-wg-quick"
        );
    }

    #[tokio::test]
    #[cfg(not(any(target_os = "linux", windows)))]
    async fn apply_network_config_uses_wg_quick_on_macos() {
        let temp_dir = std::env::temp_dir().join(format!("lattice-macos-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let config = NetworkDesiredConfig {
            schema_version: 1,
            node_id: "test-node".to_string(),
            control_id: "test-control".to_string(),
            network_id: "lattice-main".to_string(),
            revision: 1,
            enabled: true,
            status: NetworkNodeStatus::Allocated,
            virtual_ipv4: Some("10.240.0.5/32".to_string()),
            overlay_cidr: Some("10.240.0.0/16".to_string()),
            gateway_ipv4: Some("10.240.0.1".to_string()),
            gateway_endpoint: Some("198.51.100.1:51820".to_string()),
            gateway_wireguard_public_key: Some(encode_wireguard_key(&wireguard_public_key(
                &[6; 32],
            ))),
            allowed_overlay_routes: vec!["10.240.0.0/16".to_string()],
            keepalive_seconds: 25,
            issued_at_ms: unix_time_ms(),
        };
        let priv_key = [1u8; 32];
        let peers_path = temp_dir.join("peers.json");
        let conf_path = temp_dir.join("wg-lattice.conf");
        let previous = std::env::var("LATTICE_WG_QUICK").ok();
        unsafe {
            std::env::set_var("LATTICE_WG_QUICK", "/nonexistent-wg-quick-binary");
        }
        let res = apply_network_config(&config, &priv_key, &peers_path, &conf_path).await;
        unsafe {
            if let Some(value) = previous {
                std::env::set_var("LATTICE_WG_QUICK", value);
            } else {
                std::env::remove_var("LATTICE_WG_QUICK");
            }
        }
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("wg-quick"));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
    #[tokio::test]
    async fn wireguard_key_mismatch_never_changes_or_replaces_the_existing_secret() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wireguard.json");
        load_or_create_wireguard_key(&path).await.unwrap();
        let mut stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        stored["public_key"] =
            serde_json::json!(encode_wireguard_key(&wireguard_public_key(&[9; 32])));
        let damaged = serde_json::to_vec(&stored).unwrap();
        std::fs::write(&path, &damaged).unwrap();
        assert!(
            load_or_create_wireguard_key(&path).await.is_err(),
            "inconsistent key metadata must fail closed"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            damaged,
            "failure must retain the exact file for recovery"
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn unreadable_or_linked_wireguard_keys_never_trigger_implicit_key_generation() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wireguard.json");
        load_or_create_wireguard_key(&path).await.unwrap();
        let before = std::fs::read(&path).unwrap();
        let linked = directory.path().join("linked.json");
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert!(
            load_or_create_wireguard_key(&linked).await.is_err(),
            "key files must not follow a symlink"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let rejected = load_or_create_wireguard_key(&path).await.is_err();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(rejected, "read failure must not generate a replacement key");
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
