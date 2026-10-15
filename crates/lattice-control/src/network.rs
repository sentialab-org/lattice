use crate::{ApiResponseError, AppState, secure_file, unix_time_ms};
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use lattice_crypto::{decode_key, is_valid_wireguard_key, sign, verify};
use lattice_protocol::{
    NETWORK_PROTOCOL_VERSION, NetworkAckReceipt, NetworkAckRequest, NetworkAckResponse,
    NetworkCandidatesReceipt, NetworkCandidatesRequest, NetworkCandidatesResponse,
    NetworkDesiredConfig, NetworkNodeStatus, NetworkPeersRequest, NetworkPeersResponse,
    NetworkRegisterReceipt, NetworkRegisterRequest, NetworkRegisterResponse, NetworkSyncRequest,
    NetworkSyncResponse, OperatorNetworkAssignRequest, OperatorNetworkNode,
    OperatorNetworkRevokeRequest, SignedNetworkDesiredConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

pub mod gateway;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllocation {
    pub node_id: String,
    pub virtual_ipv4: String,
    #[serde(default)]
    pub wireguard_public_key: Option<String>,
    pub revision: u64,
    pub enabled: bool,
    pub status: NetworkNodeStatus,
    #[serde(default)]
    pub last_applied_revision: u64,
    #[serde(default)]
    pub last_sequence: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub endpoint_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_endpoint_override: Option<String>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub network_id: String,
    pub overlay_cidr: String,
    pub gateway_ipv4: String,
    pub gateway_endpoint: String,
    pub gateway_wireguard_public_key: String,
    pub keepalive_seconds: u16,
    #[serde(default = "default_interface_name")]
    pub interface_name: String,
    #[serde(default)]
    pub reserved_ipv4: Vec<String>,
    #[serde(default)]
    pub relays: Vec<RelayEntry>,
    #[serde(default = "default_path_policy")]
    pub path_policy: String,
    pub next_ip_offset: u32,
    pub allocations: BTreeMap<String, NetworkAllocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEntry {
    pub relay_id: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_public_key: Option<String>,
}

pub fn default_path_policy() -> String {
    std::env::var("LATTICE_NETWORK_PATH_POLICY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "hub".to_string())
}

pub fn default_interface_name() -> String {
    std::env::var("LATTICE_NETWORK_INTERFACE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "wg-lattice".to_string())
}

pub fn configured_interface_name() -> String {
    default_interface_name()
}

fn parse_reserved_ips() -> Vec<String> {
    std::env::var("LATTICE_NETWORK_RESERVED_IPS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_relays() -> Vec<RelayEntry> {
    let raw = std::env::var("LATTICE_NETWORK_RELAYS").unwrap_or_default();
    raw.split(',')
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .enumerate()
        .map(|(index, entry)| {
            let mut parts = entry.splitn(2, '=');
            let first = parts.next().unwrap_or("").trim();
            let second = parts.next().map(|value| value.trim());
            if let Some(endpoint) = second {
                RelayEntry {
                    relay_id: first.to_string(),
                    endpoint: endpoint.to_string(),
                    wireguard_public_key: None,
                }
            } else {
                RelayEntry {
                    relay_id: format!("relay-{}", index + 1),
                    endpoint: first.to_string(),
                    wireguard_public_key: None,
                }
            }
        })
        .collect()
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            network_id: "lattice-main".to_string(),
            overlay_cidr: "10.240.0.0/16".to_string(),
            gateway_ipv4: "10.240.0.1".to_string(),
            gateway_endpoint: "127.0.0.1:51820".to_string(),
            gateway_wireguard_public_key: String::new(),
            keepalive_seconds: 25,
            interface_name: default_interface_name(),
            reserved_ipv4: Vec::new(),
            relays: Vec::new(),
            path_policy: default_path_policy(),
            next_ip_offset: 2,
            allocations: BTreeMap::new(),
        }
    }
}

pub async fn load_or_create(
    data_dir: &Path,
) -> Result<(PathBuf, NetworkState), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join("network.json");
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let state: NetworkState = serde_json::from_str(&content)?;
            Ok((path, state))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tokio::fs::create_dir_all(data_dir).await?;
            let network_id = std::env::var("LATTICE_CLUSTER_ID")
                .or_else(|_| std::env::var("LATTICE_NETWORK_ID"))
                .unwrap_or_else(|_| "lattice-main".to_string());
            let overlay_cidr = std::env::var("LATTICE_NETWORK_CIDR")
                .unwrap_or_else(|_| "10.240.0.0/16".to_string());
            let gateway_ipv4 = std::env::var("LATTICE_NETWORK_GATEWAY_IP")
                .unwrap_or_else(|_| "10.240.0.1".to_string());
            let gateway_endpoint = std::env::var("LATTICE_NETWORK_GATEWAY_ENDPOINT")
                .unwrap_or_else(|_| "127.0.0.1:51820".to_string());
            let keepalive_seconds = std::env::var("LATTICE_NETWORK_KEEPALIVE_SECS")
                .ok()
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(25);
            let interface_name = configured_interface_name();
            let reserved_ipv4 = parse_reserved_ips();

            let gateway_keys = match std::env::var("LATTICE_NETWORK_GATEWAY_KEY") {
                Ok(key) if is_valid_wireguard_key(&key) => (String::new(), key),
                _ => {
                    let key_path = data_dir.join("gateway_wireguard.json");
                    load_or_create_gateway_keys(&key_path).await?
                }
            };

            let state = NetworkState {
                network_id,
                overlay_cidr,
                gateway_ipv4,
                gateway_endpoint,
                gateway_wireguard_public_key: gateway_keys.1,
                keepalive_seconds,
                interface_name,
                reserved_ipv4,
                relays: parse_relays(),
                path_policy: default_path_policy(),
                next_ip_offset: 2,
                allocations: BTreeMap::new(),
            };

            let content = serde_json::to_vec_pretty(&state)?;
            tokio::fs::write(&path, content).await?;
            secure_file(&path)?;
            Ok((path, state))
        }
        Err(error) => Err(error.into()),
    }
}

pub async fn save(path: &Path, state: &NetworkState) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
    write_atomic(path, &content).await
}

pub async fn write_atomic(path: &Path, content: &[u8]) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");
    tokio::fs::write(&tmp_path, content)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(&tmp_path)?;
    {
        let file = std::fs::File::open(&tmp_path).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
    }
    tokio::fs::rename(&tmp_path, path)
        .await
        .map_err(|error| error.to_string())?;
    secure_file(path)
}

#[derive(Serialize, Deserialize)]
struct GatewayWireguardIdentity {
    private_key: String,
    public_key: String,
}

async fn load_or_create_gateway_keys(
    path: &Path,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => {
            let identity: GatewayWireguardIdentity = serde_json::from_str(&content)?;
            Ok((identity.private_key, identity.public_key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (priv_bytes, pub_bytes) = lattice_crypto::generate_wireguard_keypair();
            let identity = GatewayWireguardIdentity {
                private_key: lattice_crypto::encode_wireguard_key(&priv_bytes),
                public_key: lattice_crypto::encode_wireguard_key(&pub_bytes),
            };
            let content = serde_json::to_vec_pretty(&identity)?;
            tokio::fs::write(path, content).await?;
            secure_file(path)?;
            Ok((identity.private_key, identity.public_key))
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalGatewayFiles {
    pub interface_name: String,
    pub listen_port: u16,
    pub address: String,
    pub overlay_cidr: String,
    pub wireguard_config: String,
    pub nftables_ruleset: String,
    pub nftables_rollback: String,
    pub sysctl_requirements: String,
}

pub async fn local_gateway_files(
    data_dir: &Path,
) -> Result<LocalGatewayFiles, Box<dyn std::error::Error + Send + Sync>> {
    let (_, state) = load_or_create(data_dir).await?;
    let key_path = data_dir.join("gateway_wireguard.json");
    let (private_key, _) = load_or_create_gateway_keys(&key_path).await?;
    if private_key.is_empty() {
        return Err("gateway private key is not stored locally; refusing to render".into());
    }
    let listen_port = gateway_listen_port(&state.gateway_endpoint);
    let config =
        gateway::build_gateway_config(&state, &private_key, listen_port, &state.interface_name);
    Ok(LocalGatewayFiles {
        interface_name: state.interface_name.clone(),
        listen_port,
        address: config.address.clone(),
        overlay_cidr: state.overlay_cidr.clone(),
        wireguard_config: gateway::render_wireguard_config(&config),
        nftables_ruleset: gateway::render_nftables_ruleset(
            &state.interface_name,
            &state.overlay_cidr,
        ),
        nftables_rollback: gateway::render_nftables_rollback(),
        sysctl_requirements: gateway::render_sysctl_requirements().to_string(),
    })
}

pub fn allocate_next_virtual_ip(state: &mut NetworkState) -> Result<String, String> {
    let (base_ip, prefix) = parse_cidr(&state.overlay_cidr)?;
    if prefix > 30 {
        return Err("overlay prefix too small".to_string());
    }

    let mask = !((1u32 << (32 - prefix)) - 1);
    let net_start = u32::from(base_ip) & mask;
    let net_broadcast = net_start | (!mask);
    let gateway_num = u32::from(
        state
            .gateway_ipv4
            .parse::<Ipv4Addr>()
            .map_err(|e| e.to_string())?,
    );

    let assigned_ips: std::collections::BTreeSet<u32> = state
        .allocations
        .values()
        .filter_map(|alloc| {
            alloc
                .virtual_ipv4
                .split('/')
                .next()
                .and_then(|ip_str| ip_str.parse::<Ipv4Addr>().ok())
                .map(u32::from)
        })
        .collect();

    let reserved_nums: std::collections::BTreeSet<u32> = state
        .reserved_ipv4
        .iter()
        .filter_map(|entry| {
            entry
                .split('/')
                .next()
                .and_then(|ip_str| ip_str.trim().parse::<Ipv4Addr>().ok())
                .map(u32::from)
        })
        .collect();

    let mut offset = state.next_ip_offset.max(2);
    let max_offset = !mask;

    while offset < max_offset {
        let candidate = net_start + offset;
        let last_octet = candidate & 0xff;

        if candidate != gateway_num
            && candidate < net_broadcast
            && last_octet != 0
            && last_octet != 255
            && !assigned_ips.contains(&candidate)
            && !reserved_nums.contains(&candidate)
        {
            state.next_ip_offset = offset + 1;
            let ip = Ipv4Addr::from(candidate);
            return Ok(format!("{ip}/32"));
        }
        offset += 1;
    }

    Err("overlay address pool exhausted".to_string())
}

pub fn gateway_listen_port(endpoint: &str) -> u16 {
    endpoint
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(51820)
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let mut parts = cidr.split('/');
    let ip_str = parts.next().ok_or("missing IP in CIDR")?;
    let prefix_str = parts.next().ok_or("missing prefix in CIDR")?;
    let ip: Ipv4Addr = ip_str
        .parse()
        .map_err(|e: std::net::AddrParseError| e.to_string())?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    Ok((ip, prefix))
}

pub fn wireguard_key_conflict(
    allocations: &BTreeMap<String, NetworkAllocation>,
    node_id: &str,
    wireguard_public_key: &str,
) -> bool {
    allocations.values().any(|alloc| {
        alloc.node_id != node_id
            && alloc.wireguard_public_key.as_deref() == Some(wireguard_public_key)
    })
}

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<NetworkRegisterRequest>,
) -> Result<Json<NetworkRegisterResponse>, ApiResponseError> {
    if request.claim.protocol_version != NETWORK_PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported network protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_network_request",
            "network register request timestamp outside window",
        ));
    }

    if !is_valid_wireguard_key(&request.claim.wireguard_public_key) {
        return Err(ApiResponseError::bad_request(
            "invalid_wireguard_key",
            "wireguard public key must be valid 32-byte base64",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "network register signature is invalid",
        )
    })?;

    {
        let net = state.network.read().await;
        if wireguard_key_conflict(
            &net.allocations,
            &request.claim.node_id,
            &request.claim.wireguard_public_key,
        ) {
            return Err(ApiResponseError::conflict(
                "wireguard_key_in_use",
                "wireguard public key is already bound to another node; one key maps to exactly one virtual IP",
            ));
        }
    }

    let receipt = {
        let mut net = state.network.write().await;
        let current_alloc = net.allocations.get_mut(&request.claim.node_id);

        let status = if let Some(alloc) = current_alloc {
            if request.claim.sequence <= alloc.last_sequence {
                return Err(ApiResponseError::conflict(
                    "replayed_network_request",
                    "network register sequence already observed",
                ));
            }
            alloc.last_sequence = request.claim.sequence;
            if alloc.wireguard_public_key.as_deref() != Some(&request.claim.wireguard_public_key) {
                alloc.wireguard_public_key = Some(request.claim.wireguard_public_key.clone());
                alloc.revision += 1;
            }
            alloc.updated_at_ms = now;
            alloc.status.clone()
        } else {
            let alloc = NetworkAllocation {
                node_id: request.claim.node_id.clone(),
                virtual_ipv4: String::new(),
                wireguard_public_key: Some(request.claim.wireguard_public_key.clone()),
                revision: 1,
                enabled: false,
                status: NetworkNodeStatus::PendingApproval,
                last_applied_revision: 0,
                last_sequence: request.claim.sequence,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: now,
            };
            net.allocations.insert(request.claim.node_id.clone(), alloc);
            NetworkNodeStatus::PendingApproval
        };

        save(&state.network_path, &net)
            .await
            .map_err(ApiResponseError::internal)?;

        NetworkRegisterReceipt {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: request.claim.request_id,
            node_id: request.claim.node_id,
            control_id: state.control.control_id.clone(),
            status,
            issued_at_ms: now,
        }
    };

    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(NetworkRegisterResponse { receipt, signature }))
}

pub async fn sync(
    State(state): State<AppState>,
    Json(request): Json<NetworkSyncRequest>,
) -> Result<Json<NetworkSyncResponse>, ApiResponseError> {
    if request.claim.protocol_version != NETWORK_PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported network protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_network_request",
            "network sync request timestamp outside window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "network sync signature is invalid",
        )
    })?;

    let desired_config = {
        let mut net = state.network.write().await;
        let default_endpoint = net.gateway_endpoint.clone();
        let alloc = net.allocations.get_mut(&request.claim.node_id);

        let (revision, enabled, status, virtual_ipv4, gateway_endpoint) = if let Some(alloc) = alloc
        {
            if request.claim.sequence <= alloc.last_sequence {
                return Err(ApiResponseError::conflict(
                    "replayed_network_request",
                    "network sync sequence already observed",
                ));
            }
            alloc.last_sequence = request.claim.sequence;
            alloc.updated_at_ms = now;

            let ip = if alloc.enabled && !alloc.virtual_ipv4.is_empty() {
                Some(alloc.virtual_ipv4.clone())
            } else {
                None
            };
            let endpoint = alloc
                .gateway_endpoint_override
                .clone()
                .unwrap_or(default_endpoint);
            (
                alloc.revision,
                alloc.enabled && ip.is_some(),
                alloc.status.clone(),
                ip,
                endpoint,
            )
        } else {
            (
                0,
                false,
                NetworkNodeStatus::Unconfigured,
                None,
                default_endpoint,
            )
        };

        save(&state.network_path, &net)
            .await
            .map_err(ApiResponseError::internal)?;

        NetworkDesiredConfig {
            schema_version: 1,
            node_id: request.claim.node_id,
            control_id: state.control.control_id.clone(),
            network_id: net.network_id.clone(),
            revision,
            enabled,
            status,
            virtual_ipv4,
            overlay_cidr: Some(net.overlay_cidr.clone()),
            gateway_ipv4: Some(net.gateway_ipv4.clone()),
            gateway_endpoint: Some(gateway_endpoint),
            gateway_wireguard_public_key: Some(net.gateway_wireguard_public_key.clone()),
            allowed_overlay_routes: vec![net.overlay_cidr.clone()],
            keepalive_seconds: net.keepalive_seconds,
            issued_at_ms: now,
        }
    };

    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &desired_config).map_err(ApiResponseError::internal)?;

    Ok(Json(NetworkSyncResponse {
        desired_config: SignedNetworkDesiredConfig {
            config: desired_config,
            signature,
        },
    }))
}

pub async fn ack(
    State(state): State<AppState>,
    Json(request): Json<NetworkAckRequest>,
) -> Result<Json<NetworkAckResponse>, ApiResponseError> {
    if request.claim.protocol_version != NETWORK_PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported network protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_network_request",
            "network ack request timestamp outside window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized("invalid_node_signature", "network ack signature is invalid")
    })?;

    let receipt = {
        let mut net = state.network.write().await;
        let alloc = net
            .allocations
            .get_mut(&request.claim.node_id)
            .ok_or_else(|| {
                ApiResponseError::bad_request("unallocated_node", "node has no network allocation")
            })?;

        if request.claim.sequence <= alloc.last_sequence {
            return Err(ApiResponseError::conflict(
                "replayed_network_request",
                "network ack sequence already observed",
            ));
        }

        alloc.last_sequence = request.claim.sequence;
        alloc.last_applied_revision = request.claim.applied_revision;
        alloc.updated_at_ms = now;

        if request.claim.success {
            alloc.status = if alloc.enabled {
                NetworkNodeStatus::Connected
            } else {
                NetworkNodeStatus::Disabled
            };
            alloc.last_error = None;
        } else {
            alloc.status = NetworkNodeStatus::Degraded;
            alloc.last_error = request.claim.error_code;
        }

        let revision = alloc.revision;

        save(&state.network_path, &net)
            .await
            .map_err(ApiResponseError::internal)?;

        NetworkAckReceipt {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: request.claim.request_id,
            node_id: request.claim.node_id,
            control_id: state.control.control_id.clone(),
            revision,
            issued_at_ms: now,
        }
    };

    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(NetworkAckResponse { receipt, signature }))
}

pub async fn operator_list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<OperatorNetworkNode>>, ApiResponseError> {
    crate::operator::authorize(&state, &headers)?;

    let net = state.network.read().await;
    let nodes = net
        .allocations
        .values()
        .map(|alloc| OperatorNetworkNode {
            node_id: alloc.node_id.clone(),
            virtual_ipv4: if alloc.virtual_ipv4.is_empty() {
                None
            } else {
                Some(alloc.virtual_ipv4.clone())
            },
            wireguard_public_key: alloc.wireguard_public_key.clone(),
            revision: alloc.revision,
            enabled: alloc.enabled,
            status: alloc.status.clone(),
            last_applied_revision: alloc.last_applied_revision,
            last_error: alloc.last_error.clone(),
            updated_at_ms: alloc.updated_at_ms,
            endpoint_candidates: alloc.endpoint_candidates.clone(),
            gateway_endpoint_override: alloc.gateway_endpoint_override.clone(),
        })
        .collect();

    Ok(Json(nodes))
}

pub async fn operator_assign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OperatorNetworkAssignRequest>,
) -> Result<Json<OperatorNetworkNode>, ApiResponseError> {
    crate::operator::authorize(&state, &headers)?;

    {
        let registry = state.registry.read().await;
        if !registry.nodes.contains_key(&request.node_id) {
            return Err(ApiResponseError::bad_request(
                "unknown_node",
                "node must be enrolled before assigning network lease",
            ));
        }
    }

    let now = unix_time_ms();
    let mut net = state.network.write().await;

    let target_ip = if let Some(ip) = request.virtual_ipv4 {
        let (ip_addr, _) =
            parse_cidr(&ip).map_err(|e| ApiResponseError::bad_request("invalid_cidr", &e))?;
        let ip_num = u32::from(ip_addr);
        let for_other = net.allocations.iter().any(|(nid, a)| {
            if nid == &request.node_id {
                return false;
            }
            a.virtual_ipv4
                .split('/')
                .next()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
                .map(|existing| u32::from(existing) == ip_num)
                .unwrap_or(false)
        });
        if for_other {
            return Err(ApiResponseError::conflict(
                "ip_already_assigned",
                "requested virtual IP is already assigned to another node",
            ));
        }
        let (base_ip, prefix) = parse_cidr(&net.overlay_cidr)
            .map_err(|e| ApiResponseError::bad_request("invalid_overlay_cidr", &e))?;
        let mask = !((1u32 << (32 - prefix)) - 1);
        let net_start = u32::from(base_ip) & mask;
        let net_broadcast = net_start | (!mask);
        let gateway_num =
            u32::from(net.gateway_ipv4.parse::<Ipv4Addr>().map_err(|e| {
                ApiResponseError::bad_request("invalid_gateway_ip", &e.to_string())
            })?);
        if ip_num <= net_start || ip_num >= net_broadcast || ip_num == gateway_num {
            return Err(ApiResponseError::bad_request(
                "invalid_ip_range",
                "requested IP is out of overlay range or equals gateway",
            ));
        }
        format!("{ip_addr}/32")
    } else if let Some(existing) = net.allocations.get(&request.node_id)
        && !existing.virtual_ipv4.is_empty()
    {
        existing.virtual_ipv4.clone()
    } else {
        allocate_next_virtual_ip(&mut net)
            .map_err(|e| ApiResponseError::conflict("ipam_exhausted", &e))?
    };

    if let Some(endpoint) = request.gateway_endpoint.as_deref() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() || !endpoint.contains(':') || endpoint.len() > 256 {
            return Err(ApiResponseError::bad_request(
                "invalid_gateway_endpoint",
                "gateway endpoint override must be host:port",
            ));
        }
    }

    let alloc = net
        .allocations
        .entry(request.node_id.clone())
        .and_modify(|a| {
            if a.virtual_ipv4 != target_ip || !a.enabled {
                a.revision += 1;
            }
            a.virtual_ipv4 = target_ip.clone();
            if let Some(endpoint) = request.gateway_endpoint.as_deref() {
                let endpoint = endpoint.trim().to_string();
                if a.gateway_endpoint_override.as_deref() != Some(endpoint.as_str()) {
                    a.gateway_endpoint_override = Some(endpoint);
                    a.revision += 1;
                }
            }
            a.enabled = true;
            a.status = NetworkNodeStatus::Allocated;
            a.updated_at_ms = now;
        })
        .or_insert_with(|| NetworkAllocation {
            node_id: request.node_id.clone(),
            virtual_ipv4: target_ip.clone(),
            wireguard_public_key: None,
            revision: 1,
            enabled: true,
            status: NetworkNodeStatus::Allocated,
            last_applied_revision: 0,
            last_sequence: 0,
            last_error: None,
            endpoint_candidates: Vec::new(),
            gateway_endpoint_override: request
                .gateway_endpoint
                .as_deref()
                .map(|value| value.trim().to_string()),
            updated_at_ms: now,
        });

    let result = OperatorNetworkNode {
        node_id: alloc.node_id.clone(),
        virtual_ipv4: Some(alloc.virtual_ipv4.clone()),
        wireguard_public_key: alloc.wireguard_public_key.clone(),
        revision: alloc.revision,
        enabled: alloc.enabled,
        status: alloc.status.clone(),
        last_applied_revision: alloc.last_applied_revision,
        last_error: alloc.last_error.clone(),
        updated_at_ms: alloc.updated_at_ms,
        endpoint_candidates: alloc.endpoint_candidates.clone(),
        gateway_endpoint_override: alloc.gateway_endpoint_override.clone(),
    };

    save(&state.network_path, &net)
        .await
        .map_err(ApiResponseError::internal)?;

    Ok(Json(result))
}

pub async fn operator_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OperatorNetworkRevokeRequest>,
) -> Result<Json<OperatorNetworkNode>, ApiResponseError> {
    crate::operator::authorize(&state, &headers)?;

    let now = unix_time_ms();
    let mut net = state.network.write().await;

    let alloc = net.allocations.get_mut(&request.node_id).ok_or_else(|| {
        ApiResponseError::bad_request("unknown_node", "node has no network allocation")
    })?;

    alloc.enabled = false;
    alloc.revision += 1;
    alloc.status = NetworkNodeStatus::Revoked;
    alloc.last_error = request.reason;
    alloc.updated_at_ms = now;

    let result = OperatorNetworkNode {
        node_id: alloc.node_id.clone(),
        virtual_ipv4: if alloc.virtual_ipv4.is_empty() {
            None
        } else {
            Some(alloc.virtual_ipv4.clone())
        },
        wireguard_public_key: alloc.wireguard_public_key.clone(),
        revision: alloc.revision,
        enabled: alloc.enabled,
        status: alloc.status.clone(),
        last_applied_revision: alloc.last_applied_revision,
        last_error: alloc.last_error.clone(),
        updated_at_ms: alloc.updated_at_ms,
        endpoint_candidates: alloc.endpoint_candidates.clone(),
        gateway_endpoint_override: alloc.gateway_endpoint_override.clone(),
    };

    save(&state.network_path, &net)
        .await
        .map_err(ApiResponseError::internal)?;

    Ok(Json(result))
}

pub async fn operator_gateway_view(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<gateway::OperatorGatewayView>, ApiResponseError> {
    crate::operator::authorize(&state, &headers)?;
    let net = state.network.read().await;
    let listen_port = gateway_listen_port(&net.gateway_endpoint);
    let config = gateway::build_gateway_config(
        &net,
        "REDACTED_USE_LOCAL_KEY",
        listen_port,
        &net.interface_name,
    );
    let wireguard_config = gateway::render_wireguard_config(&config);
    let nftables_ruleset = gateway::render_nftables_ruleset(&net.interface_name, &net.overlay_cidr);
    let nftables_rollback = gateway::render_nftables_rollback();
    let sysctl_requirements = gateway::render_sysctl_requirements().to_string();

    Ok(Json(gateway::OperatorGatewayView {
        interface_name: net.interface_name.clone(),
        listen_port,
        address: config.address,
        public_key: net.gateway_wireguard_public_key.clone(),
        peer_count: config.peers.len(),
        wireguard_config,
        nftables_ruleset,
        nftables_rollback,
        sysctl_requirements,
        network_id: net.network_id.clone(),
        overlay_cidr: net.overlay_cidr.clone(),
        path_policy: net.path_policy.clone(),
        relays: net
            .relays
            .iter()
            .map(|relay| gateway::RelayView {
                relay_id: relay.relay_id.clone(),
                endpoint: relay.endpoint.clone(),
            })
            .collect(),
    }))
}

pub async fn peers(
    State(state): State<AppState>,
    Json(request): Json<NetworkPeersRequest>,
) -> Result<Json<NetworkPeersResponse>, ApiResponseError> {
    use lattice_protocol::{
        NetworkPeerEntry, NetworkPeersReceipt, NetworkPeersSignatureData, NetworkRelayDescriptor,
    };

    if request.claim.protocol_version != NETWORK_PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported network protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_network_request",
            "network peers request timestamp outside window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "network peers signature is invalid",
        )
    })?;

    let (peers, relays, path_policy, network_id) = {
        let mut net = state.network.write().await;
        let alloc = net.allocations.get_mut(&request.claim.node_id);
        if let Some(alloc) = alloc {
            if request.claim.sequence <= alloc.last_sequence {
                return Err(ApiResponseError::conflict(
                    "replayed_network_request",
                    "network peers sequence already observed",
                ));
            }
            alloc.last_sequence = request.claim.sequence;
            alloc.updated_at_ms = now;
            save(&state.network_path, &net)
                .await
                .map_err(ApiResponseError::internal)?;
        }

        let mut peers = net
            .allocations
            .values()
            .filter(|alloc| alloc.node_id != request.claim.node_id)
            .filter(|alloc| alloc.enabled)
            .filter(|alloc| !alloc.virtual_ipv4.is_empty())
            .filter(|alloc| alloc.wireguard_public_key.is_some())
            .filter(|alloc| {
                !matches!(
                    alloc.status,
                    NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
                )
            })
            .map(|alloc| NetworkPeerEntry {
                node_id: alloc.node_id.clone(),
                virtual_ipv4: alloc.virtual_ipv4.clone(),
                wireguard_public_key: alloc.wireguard_public_key.clone().unwrap_or_default(),
                status: alloc.status.clone(),
                revision: alloc.revision,
                updated_at_ms: alloc.updated_at_ms,
                endpoint_candidates: sanitize_endpoint_candidates(&alloc.endpoint_candidates),
            })
            .collect::<Vec<_>>();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        let relays = net
            .relays
            .iter()
            .map(|relay| NetworkRelayDescriptor {
                relay_id: relay.relay_id.clone(),
                endpoint: relay.endpoint.clone(),
                wireguard_public_key: relay.wireguard_public_key.clone(),
            })
            .collect::<Vec<_>>();

        (
            peers,
            relays,
            net.path_policy.clone(),
            net.network_id.clone(),
        )
    };

    let receipt = NetworkPeersReceipt {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: request.claim.request_id.clone(),
        node_id: request.claim.node_id.clone(),
        control_id: state.control.control_id.clone(),
        network_id,
        peer_count: peers.len() as u64,
        issued_at_ms: now,
    };

    let signature_data = NetworkPeersSignatureData {
        receipt: receipt.clone(),
        peers: peers.clone(),
        relays: relays.clone(),
        path_policy: path_policy.clone(),
    };

    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &signature_data).map_err(ApiResponseError::internal)?;

    Ok(Json(NetworkPeersResponse {
        receipt,
        signature,
        peers,
        relays,
        path_policy,
    }))
}

pub fn sanitize_endpoint_candidates(candidates: &[String]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for entry in candidates {
        let value = entry.trim();
        if value.is_empty() || value.len() > 256 || !value.contains(':') {
            continue;
        }
        if seen.insert(value.to_string()) {
            out.push(value.to_string());
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
}

pub async fn candidates(
    State(state): State<AppState>,
    Json(request): Json<NetworkCandidatesRequest>,
) -> Result<Json<NetworkCandidatesResponse>, ApiResponseError> {
    if request.claim.protocol_version != NETWORK_PROTOCOL_VERSION {
        return Err(ApiResponseError::bad_request(
            "protocol_version_mismatch",
            "unsupported network protocol version",
        ));
    }

    let now = unix_time_ms();
    if now.abs_diff(request.claim.issued_at_ms) > 120_000 {
        return Err(ApiResponseError::bad_request(
            "stale_network_request",
            "network candidates request timestamp outside window",
        ));
    }

    let public_key = {
        let registry = state.registry.read().await;
        let node = registry.nodes.get(&request.claim.node_id).ok_or_else(|| {
            ApiResponseError::unauthorized("unknown_node", "node is not enrolled")
        })?;
        node.public_key.clone()
    };

    verify(&public_key, &request.signature, &request.claim).map_err(|_| {
        ApiResponseError::unauthorized(
            "invalid_node_signature",
            "network candidates signature is invalid",
        )
    })?;

    let sanitized = sanitize_endpoint_candidates(&request.claim.endpoint_candidates);

    let (candidate_count, network_id) = {
        let mut net = state.network.write().await;
        let alloc = net
            .allocations
            .get_mut(&request.claim.node_id)
            .ok_or_else(|| {
                ApiResponseError::bad_request("unallocated_node", "node has no network allocation")
            })?;

        if request.claim.sequence <= alloc.last_sequence {
            return Err(ApiResponseError::conflict(
                "replayed_network_request",
                "network candidates sequence already observed",
            ));
        }

        alloc.last_sequence = request.claim.sequence;
        alloc.endpoint_candidates = sanitized.clone();
        alloc.updated_at_ms = now;

        save(&state.network_path, &net)
            .await
            .map_err(ApiResponseError::internal)?;

        (sanitized.len() as u64, net.network_id.clone())
    };

    let receipt = NetworkCandidatesReceipt {
        protocol_version: NETWORK_PROTOCOL_VERSION,
        request_id: request.claim.request_id.clone(),
        node_id: request.claim.node_id.clone(),
        control_id: state.control.control_id.clone(),
        network_id,
        candidate_count,
        issued_at_ms: now,
    };

    let private_key =
        decode_key::<32>(&state.control.private_key).map_err(ApiResponseError::internal)?;
    let signature = sign(&private_key, &receipt).map_err(ApiResponseError::internal)?;

    Ok(Json(NetworkCandidatesResponse { receipt, signature }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::{NetworkAckClaim, NetworkRegisterClaim, NetworkSyncClaim};

    #[test]
    fn ipam_allocation_is_stable_and_unique() {
        let mut state = NetworkState::default();
        let ip1 = allocate_next_virtual_ip(&mut state).unwrap();
        assert_eq!(ip1, "10.240.0.2/32");

        state.allocations.insert(
            "node-1".to_string(),
            NetworkAllocation {
                node_id: "node-1".to_string(),
                virtual_ipv4: ip1.clone(),
                wireguard_public_key: None,
                revision: 1,
                enabled: true,
                status: NetworkNodeStatus::Allocated,
                last_applied_revision: 0,
                last_sequence: 0,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 0,
            },
        );

        let ip2 = allocate_next_virtual_ip(&mut state).unwrap();
        assert_eq!(ip2, "10.240.0.3/32");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn ipam_skips_network_broadcast_and_gateway() {
        let mut state = NetworkState {
            overlay_cidr: "10.240.0.0/24".to_string(),
            gateway_ipv4: "10.240.0.1".to_string(),
            next_ip_offset: 254,
            ..Default::default()
        };

        let ip = allocate_next_virtual_ip(&mut state).unwrap();
        assert_eq!(ip, "10.240.0.254/32");
        assert!(allocate_next_virtual_ip(&mut state).is_err());
    }

    #[test]
    fn ipam_skips_reserved_nbi_addresses() {
        let mut state = NetworkState {
            overlay_cidr: "10.77.0.0/16".to_string(),
            gateway_ipv4: "10.77.0.1".to_string(),
            reserved_ipv4: vec!["10.77.0.2".to_string(), "10.77.0.3".to_string()],
            next_ip_offset: 2,
            ..Default::default()
        };

        let ip = allocate_next_virtual_ip(&mut state).unwrap();
        assert_eq!(ip, "10.77.0.4/32");
    }

    #[test]
    fn gateway_listen_port_parses_endpoint() {
        assert_eq!(gateway_listen_port("10.77.0.1:51820"), 51820);
        assert_eq!(gateway_listen_port("vpn.example.net:51821"), 51821);
        assert_eq!(gateway_listen_port("invalid-endpoint"), 51820);
    }

    #[tokio::test]
    async fn network_state_persistence_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!(
            "lattice_net_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let (path, mut state) = load_or_create(&temp_dir).await.unwrap();
        assert_eq!(state.allocations.len(), 0);

        let ip = allocate_next_virtual_ip(&mut state).unwrap();
        state.allocations.insert(
            "node-alpha".to_string(),
            NetworkAllocation {
                node_id: "node-alpha".to_string(),
                virtual_ipv4: ip.clone(),
                wireguard_public_key: Some("dGVzdA==".to_string()),
                revision: 1,
                enabled: true,
                status: NetworkNodeStatus::Allocated,
                last_applied_revision: 0,
                last_sequence: 1,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 1000,
            },
        );
        save(&path, &state).await.unwrap();

        let (_, loaded) = load_or_create(&temp_dir).await.unwrap();
        assert_eq!(loaded.allocations.len(), 1);
        let node_alloc = loaded.allocations.get("node-alpha").unwrap();
        assert_eq!(node_alloc.virtual_ipv4, ip);
        assert_eq!(node_alloc.revision, 1);
        assert!(node_alloc.enabled);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn wireguard_key_validation_enforces_curve25519() {
        let (_priv, pubkey) = lattice_crypto::generate_wireguard_keypair();
        let encoded = lattice_crypto::encode_wireguard_key(&pubkey);
        assert!(lattice_crypto::is_valid_wireguard_key(&encoded));
        assert!(!lattice_crypto::is_valid_wireguard_key("not-a-key"));
        assert!(!lattice_crypto::is_valid_wireguard_key(""));
    }

    #[tokio::test]
    async fn end_to_end_network_protocol_and_lifecycle() {
        use crate::{ControlIdentity, EnrolledNode, NodeRegistry};
        use lattice_protocol::{Architecture, Platform, PolicySnapshot};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let temp_dir =
            std::env::temp_dir().join(format!("lattice_e2e_net_{}", uuid::Uuid::new_v4().simple()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let control_priv = lattice_crypto::generate_private_key();
        let control_pub = lattice_crypto::encode_key(&lattice_crypto::public_key(&control_priv));
        let control = Arc::new(ControlIdentity {
            control_id: "control-test-01".to_string(),
            private_key: lattice_crypto::encode_key(&control_priv),
            public_key: control_pub.clone(),
            created_at_ms: 1000,
        });

        let node_priv = lattice_crypto::generate_private_key();
        let node_pub = lattice_crypto::encode_key(&lattice_crypto::public_key(&node_priv));
        let node_id = "node-test-01".to_string();

        let mut nodes_map = BTreeMap::new();
        nodes_map.insert(
            node_id.clone(),
            EnrolledNode {
                node_id: node_id.clone(),
                node_name: "test-node".to_string(),
                public_key: node_pub.clone(),
                platform: Platform::Linux,
                architecture: Architecture::X86_64,
                client_version: "0.1.0".to_string(),
                enrolled_at_ms: 1000,
                last_seen_ms: Some(1000),
                online_until_ms: Some(50000),
                last_sequence: 1,
                capabilities: None,
                health: None,
                effective_policy: None,
            },
        );

        let registry = Arc::new(RwLock::new(NodeRegistry { nodes: nodes_map }));
        let registry_path = Arc::new(temp_dir.join("nodes.json"));
        let (network_path, network) = load_or_create(&temp_dir).await.unwrap();
        let network_state = Arc::new(RwLock::new(network));
        let (jobs_path, jobs) = crate::jobs::load_or_create(&temp_dir).await.unwrap();
        let (artifacts_path, artifacts) =
            crate::artifacts::load_or_create(&temp_dir).await.unwrap();
        let (_, releases) = crate::releases::load_or_create(&temp_dir).await.unwrap();
        let (runtimes_path, runtimes) = crate::runtimes::load_or_create(&temp_dir).await.unwrap();

        let state = AppState {
            control: control.clone(),
            control_role: Arc::new("combined".to_string()),
            enrollment_token: Arc::new("enroll-token".to_string()),
            registry,
            registry_path,
            policy: Arc::new(PolicySnapshot::default()),
            jobs: Arc::new(RwLock::new(jobs)),
            jobs_path: Arc::new(jobs_path),
            artifacts: Arc::new(RwLock::new(artifacts)),
            artifacts_path: Arc::new(artifacts_path),
            content_dir: Arc::new(temp_dir.join("content")),
            operator_token: Some(Arc::new("operator-secret-token".to_string())),
            public_url: Arc::new("http://127.0.0.1:7443".to_string()),
            releases: Arc::new(releases),
            runtimes: Arc::new(RwLock::new(runtimes)),
            runtimes_path: Arc::new(runtimes_path),
            network: network_state.clone(),
            network_path: Arc::new(network_path),
        };

        let (_wg_priv, wg_pub) = lattice_crypto::generate_wireguard_keypair();
        let wg_pub_str = lattice_crypto::encode_wireguard_key(&wg_pub);

        let now = unix_time_ms();
        let reg_claim = NetworkRegisterClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "req-1".to_string(),
            node_id: node_id.clone(),
            sequence: 10,
            wireguard_public_key: wg_pub_str.clone(),
            local_opt_in: true,
            issued_at_ms: now,
        };
        let reg_sig = lattice_crypto::sign(&node_priv, &reg_claim).unwrap();
        let reg_resp = register(
            axum::extract::State(state.clone()),
            Json(NetworkRegisterRequest {
                claim: reg_claim.clone(),
                signature: reg_sig.clone(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(reg_resp.receipt.status, NetworkNodeStatus::PendingApproval);
        lattice_crypto::verify(&control_pub, &reg_resp.signature, &reg_resp.receipt).unwrap();

        let replay_res = register(
            axum::extract::State(state.clone()),
            Json(NetworkRegisterRequest {
                claim: reg_claim,
                signature: reg_sig,
            }),
        )
        .await;
        assert!(replay_res.is_err());

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer operator-secret-token".parse().unwrap(),
        );
        let assign_resp = operator_assign(
            axum::extract::State(state.clone()),
            headers.clone(),
            Json(OperatorNetworkAssignRequest {
                node_id: node_id.clone(),
                virtual_ipv4: None,
                gateway_endpoint: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(assign_resp.status, NetworkNodeStatus::Allocated);
        assert!(assign_resp.enabled);
        assert_eq!(assign_resp.virtual_ipv4, Some("10.240.0.2/32".to_string()));

        let sync_claim = NetworkSyncClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "req-2".to_string(),
            node_id: node_id.clone(),
            sequence: 11,
            last_applied_revision: 0,
            issued_at_ms: unix_time_ms(),
        };
        let sync_sig = lattice_crypto::sign(&node_priv, &sync_claim).unwrap();
        let sync_resp = sync(
            axum::extract::State(state.clone()),
            Json(NetworkSyncRequest {
                claim: sync_claim,
                signature: sync_sig,
            }),
        )
        .await
        .unwrap();

        let desired = sync_resp.desired_config.config.clone();
        assert!(desired.enabled);
        assert_eq!(desired.virtual_ipv4, Some("10.240.0.2/32".to_string()));
        lattice_crypto::verify(&control_pub, &sync_resp.desired_config.signature, &desired)
            .unwrap();

        let ack_claim = NetworkAckClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "req-3".to_string(),
            node_id: node_id.clone(),
            sequence: 12,
            applied_revision: desired.revision,
            success: true,
            error_code: None,
            interface_name: Some("wg-lattice".to_string()),
            assigned_virtual_ipv4: desired.virtual_ipv4.clone(),
            issued_at_ms: unix_time_ms(),
        };
        let ack_sig = lattice_crypto::sign(&node_priv, &ack_claim).unwrap();
        let ack_resp = ack(
            axum::extract::State(state.clone()),
            Json(NetworkAckRequest {
                claim: ack_claim,
                signature: ack_sig,
            }),
        )
        .await
        .unwrap();

        assert_eq!(ack_resp.receipt.revision, desired.revision);
        {
            let net = state.network.read().await;
            assert_eq!(
                net.allocations.get(&node_id).unwrap().status,
                NetworkNodeStatus::Connected
            );
        }

        let gw_view = operator_gateway_view(axum::extract::State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(gw_view.peer_count, 1);
        assert!(
            gw_view
                .wireguard_config
                .contains(&format!("# NodeId = {node_id}"))
        );
        assert!(
            gw_view
                .nftables_ruleset
                .contains("table inet lattice_overlay")
        );

        let revoke_resp = operator_revoke(
            axum::extract::State(state.clone()),
            headers.clone(),
            Json(OperatorNetworkRevokeRequest {
                node_id: node_id.clone(),
                reason: Some("security check".to_string()),
            }),
        )
        .await
        .unwrap();

        let gw_view_after = operator_gateway_view(axum::extract::State(state.clone()), headers)
            .await
            .unwrap()
            .0;
        assert_eq!(gw_view_after.peer_count, 0);

        assert_eq!(revoke_resp.status, NetworkNodeStatus::Revoked);
        assert!(!revoke_resp.enabled);

        let sync_claim2 = NetworkSyncClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "req-4".to_string(),
            node_id: node_id.clone(),
            sequence: 13,
            last_applied_revision: desired.revision,
            issued_at_ms: unix_time_ms(),
        };
        let sync_sig2 = lattice_crypto::sign(&node_priv, &sync_claim2).unwrap();
        let sync_resp2 = sync(
            axum::extract::State(state.clone()),
            Json(NetworkSyncRequest {
                claim: sync_claim2,
                signature: sync_sig2,
            }),
        )
        .await
        .unwrap();

        assert!(!sync_resp2.desired_config.config.enabled);
        assert_eq!(sync_resp2.desired_config.config.virtual_ipv4, None);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn wireguard_key_binds_exactly_one_node() {
        let mut allocations = BTreeMap::new();
        allocations.insert(
            "node-a".to_string(),
            NetworkAllocation {
                node_id: "node-a".to_string(),
                virtual_ipv4: "10.77.0.4/32".to_string(),
                wireguard_public_key: Some("KEY_A==".to_string()),
                revision: 1,
                enabled: true,
                status: NetworkNodeStatus::Connected,
                last_applied_revision: 1,
                last_sequence: 10,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 1000,
            },
        );

        assert!(!wireguard_key_conflict(&allocations, "node-a", "KEY_A=="));
        assert!(!wireguard_key_conflict(
            &allocations,
            "node-a",
            "KEY_ROTATED=="
        ));
        assert!(wireguard_key_conflict(&allocations, "node-b", "KEY_A=="));
        assert!(!wireguard_key_conflict(&allocations, "node-b", "KEY_B=="));
    }

    #[test]
    fn relay_env_parsing_supports_named_and_plain_endpoints() {
        let relays = parse_relays();
        let _ = relays;
        assert_eq!(gateway_listen_port("relay.example.net:51821"), 51821);
    }

    #[tokio::test]
    async fn local_gateway_files_render_real_private_key() {
        let temp_dir = std::env::temp_dir().join(format!(
            "lattice_gw_local_{}",
            uuid::Uuid::new_v4().simple()
        ));
        let files = local_gateway_files(&temp_dir).await.unwrap();
        assert!(!files.wireguard_config.contains("REDACTED"));
        assert!(files.wireguard_config.contains("PrivateKey = "));
        assert!(files.wireguard_config.contains("ListenPort = "));
        assert!(!files.address.is_empty());
        assert!(files.nftables_ruleset.contains("lattice_overlay"));
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn peers_endpoint_returns_signed_peer_list_and_relays() {
        use crate::{ControlIdentity, EnrolledNode, NodeRegistry};
        use lattice_protocol::{
            Architecture, NetworkPeersClaim, NetworkPeersRequest, Platform, PolicySnapshot,
        };
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let temp_dir = std::env::temp_dir().join(format!(
            "lattice_peers_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let control_priv = lattice_crypto::generate_private_key();
        let control_pub = lattice_crypto::encode_key(&lattice_crypto::public_key(&control_priv));
        let control = Arc::new(ControlIdentity {
            control_id: "control-peers-01".to_string(),
            private_key: lattice_crypto::encode_key(&control_priv),
            public_key: control_pub.clone(),
            created_at_ms: 1000,
        });

        let node_priv_a = lattice_crypto::generate_private_key();
        let node_pub_a = lattice_crypto::encode_key(&lattice_crypto::public_key(&node_priv_a));
        let node_priv_b = lattice_crypto::generate_private_key();
        let node_pub_b = lattice_crypto::encode_key(&lattice_crypto::public_key(&node_priv_b));

        let mut nodes_map = BTreeMap::new();
        for (node_id, pubkey) in [
            ("node-a".to_string(), node_pub_a),
            ("node-b".to_string(), node_pub_b),
        ] {
            nodes_map.insert(
                node_id.clone(),
                EnrolledNode {
                    node_id: node_id.clone(),
                    node_name: node_id.clone(),
                    public_key: pubkey,
                    platform: Platform::Linux,
                    architecture: Architecture::X86_64,
                    client_version: "0.1.0".to_string(),
                    enrolled_at_ms: 1000,
                    last_seen_ms: Some(1000),
                    online_until_ms: Some(50000),
                    last_sequence: 1,
                    capabilities: None,
                    health: None,
                    effective_policy: None,
                },
            );
        }

        let registry = Arc::new(RwLock::new(NodeRegistry { nodes: nodes_map }));
        let registry_path = Arc::new(temp_dir.join("nodes.json"));
        let (network_path, mut network) = load_or_create(&temp_dir).await.unwrap();
        network.relays = vec![RelayEntry {
            relay_id: "relay-1".to_string(),
            endpoint: "relay.example.net:51820".to_string(),
            wireguard_public_key: None,
        }];
        network.path_policy = "hub".to_string();
        let network_state = Arc::new(RwLock::new(network));
        let (jobs_path, jobs) = crate::jobs::load_or_create(&temp_dir).await.unwrap();
        let (artifacts_path, artifacts) =
            crate::artifacts::load_or_create(&temp_dir).await.unwrap();
        let (_, releases) = crate::releases::load_or_create(&temp_dir).await.unwrap();
        let (runtimes_path, runtimes) = crate::runtimes::load_or_create(&temp_dir).await.unwrap();

        let state = AppState {
            control: control.clone(),
            control_role: Arc::new("combined".to_string()),
            enrollment_token: Arc::new("enroll-token".to_string()),
            registry,
            registry_path,
            policy: Arc::new(PolicySnapshot::default()),
            jobs: Arc::new(RwLock::new(jobs)),
            jobs_path: Arc::new(jobs_path),
            artifacts: Arc::new(RwLock::new(artifacts)),
            artifacts_path: Arc::new(artifacts_path),
            content_dir: Arc::new(temp_dir.join("content")),
            operator_token: Some(Arc::new("operator-secret-token".to_string())),
            public_url: Arc::new("http://127.0.0.1:7443".to_string()),
            releases: Arc::new(releases),
            runtimes: Arc::new(RwLock::new(runtimes)),
            runtimes_path: Arc::new(runtimes_path),
            network: network_state.clone(),
            network_path: Arc::new(network_path),
        };

        let (_priv_a, pub_a) = lattice_crypto::generate_wireguard_keypair();
        let (_priv_b, pub_b) = lattice_crypto::generate_wireguard_keypair();
        {
            let mut net = state.network.write().await;
            net.allocations.insert(
                "node-a".to_string(),
                NetworkAllocation {
                    node_id: "node-a".to_string(),
                    virtual_ipv4: "10.77.0.2/32".to_string(),
                    wireguard_public_key: Some(lattice_crypto::encode_wireguard_key(&pub_a)),
                    revision: 2,
                    enabled: true,
                    status: NetworkNodeStatus::Connected,
                    last_applied_revision: 2,
                    last_sequence: 20,
                    last_error: None,
                    endpoint_candidates: Vec::new(),
                    gateway_endpoint_override: None,
                    updated_at_ms: 2000,
                },
            );
            net.allocations.insert(
                "node-b".to_string(),
                NetworkAllocation {
                    node_id: "node-b".to_string(),
                    virtual_ipv4: "10.77.0.3/32".to_string(),
                    wireguard_public_key: Some(lattice_crypto::encode_wireguard_key(&pub_b)),
                    revision: 2,
                    enabled: true,
                    status: NetworkNodeStatus::Connected,
                    last_applied_revision: 2,
                    last_sequence: 20,
                    last_error: None,
                    endpoint_candidates: Vec::new(),
                    gateway_endpoint_override: None,
                    updated_at_ms: 2000,
                },
            );
        }

        let claim = NetworkPeersClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "peers-req-1".to_string(),
            node_id: "node-a".to_string(),
            sequence: 21,
            issued_at_ms: unix_time_ms(),
        };
        let signature = lattice_crypto::sign(&node_priv_a, &claim).unwrap();
        let response = peers(
            axum::extract::State(state.clone()),
            Json(NetworkPeersRequest { claim, signature }),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(response.receipt.peer_count, 1);
        assert_eq!(response.peers.len(), 1);
        assert_eq!(response.peers[0].node_id, "node-b");
        assert_eq!(response.peers[0].virtual_ipv4, "10.77.0.3/32");
        assert_eq!(response.relays.len(), 1);
        assert_eq!(response.path_policy, "hub");
        lattice_crypto::verify(
            &control_pub,
            &response.signature,
            &response.signature_data(),
        )
        .unwrap();

        let replay_claim = NetworkPeersClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "peers-req-2".to_string(),
            node_id: "node-a".to_string(),
            sequence: 21,
            issued_at_ms: unix_time_ms(),
        };
        let replay_sig = lattice_crypto::sign(&node_priv_a, &replay_claim).unwrap();
        let replay = peers(
            axum::extract::State(state.clone()),
            Json(NetworkPeersRequest {
                claim: replay_claim,
                signature: replay_sig,
            }),
        )
        .await;
        assert!(replay.is_err());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn assign_override_serves_per_node_gateway_endpoint() {
        use crate::{ControlIdentity, EnrolledNode, NodeRegistry};
        use lattice_protocol::{
            Architecture, NetworkSyncClaim, NetworkSyncRequest, Platform, PolicySnapshot,
        };
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let temp_dir = std::env::temp_dir().join(format!(
            "lattice_override_{}",
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let control_priv = lattice_crypto::generate_private_key();
        let control_pub = lattice_crypto::encode_key(&lattice_crypto::public_key(&control_priv));
        let control = Arc::new(ControlIdentity {
            control_id: "control-override-01".to_string(),
            private_key: lattice_crypto::encode_key(&control_priv),
            public_key: control_pub,
            created_at_ms: 1000,
        });

        let node_priv = lattice_crypto::generate_private_key();
        let node_pub = lattice_crypto::encode_key(&lattice_crypto::public_key(&node_priv));

        let mut nodes_map = BTreeMap::new();
        nodes_map.insert(
            "node-override".to_string(),
            EnrolledNode {
                node_id: "node-override".to_string(),
                node_name: "node-override".to_string(),
                public_key: node_pub,
                platform: Platform::Linux,
                architecture: Architecture::X86_64,
                client_version: "0.1.0".to_string(),
                enrolled_at_ms: 1000,
                last_seen_ms: Some(1000),
                online_until_ms: Some(50000),
                last_sequence: 1,
                capabilities: None,
                health: None,
                effective_policy: None,
            },
        );

        let registry = Arc::new(RwLock::new(NodeRegistry { nodes: nodes_map }));
        let registry_path = Arc::new(temp_dir.join("nodes.json"));
        let (network_path, network) = load_or_create(&temp_dir).await.unwrap();
        let network_state = Arc::new(RwLock::new(network));
        let (jobs_path, jobs) = crate::jobs::load_or_create(&temp_dir).await.unwrap();
        let (artifacts_path, artifacts) =
            crate::artifacts::load_or_create(&temp_dir).await.unwrap();
        let (_, releases) = crate::releases::load_or_create(&temp_dir).await.unwrap();
        let (runtimes_path, runtimes) = crate::runtimes::load_or_create(&temp_dir).await.unwrap();

        let state = AppState {
            control: control.clone(),
            control_role: Arc::new("combined".to_string()),
            enrollment_token: Arc::new("enroll-token".to_string()),
            registry,
            registry_path,
            policy: Arc::new(PolicySnapshot::default()),
            jobs: Arc::new(RwLock::new(jobs)),
            jobs_path: Arc::new(jobs_path),
            artifacts: Arc::new(RwLock::new(artifacts)),
            artifacts_path: Arc::new(artifacts_path),
            content_dir: Arc::new(temp_dir.join("content")),
            operator_token: Some(Arc::new("operator-secret-token".to_string())),
            public_url: Arc::new("http://127.0.0.1:7443".to_string()),
            releases: Arc::new(releases),
            runtimes: Arc::new(RwLock::new(runtimes)),
            runtimes_path: Arc::new(runtimes_path),
            network: network_state.clone(),
            network_path: Arc::new(network_path),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer operator-secret-token".parse().unwrap(),
        );
        let assign = operator_assign(
            axum::extract::State(state.clone()),
            headers,
            Json(OperatorNetworkAssignRequest {
                node_id: "node-override".to_string(),
                virtual_ipv4: None,
                gateway_endpoint: Some("203.0.113.1:51820".to_string()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            assign.gateway_endpoint_override,
            Some("203.0.113.1:51820".to_string())
        );

        let bad = operator_assign(
            axum::extract::State(state.clone()),
            {
                let mut headers = HeaderMap::new();
                headers.insert(
                    "authorization",
                    "Bearer operator-secret-token".parse().unwrap(),
                );
                headers
            },
            Json(OperatorNetworkAssignRequest {
                node_id: "node-override".to_string(),
                virtual_ipv4: None,
                gateway_endpoint: Some("not-an-endpoint".to_string()),
            }),
        )
        .await;
        assert!(bad.is_err());

        let sync_claim = NetworkSyncClaim {
            protocol_version: NETWORK_PROTOCOL_VERSION,
            request_id: "sync-override-1".to_string(),
            node_id: "node-override".to_string(),
            sequence: 30,
            last_applied_revision: 0,
            issued_at_ms: unix_time_ms(),
        };
        let sync_sig = lattice_crypto::sign(&node_priv, &sync_claim).unwrap();
        let sync = sync(
            axum::extract::State(state.clone()),
            Json(NetworkSyncRequest {
                claim: sync_claim,
                signature: sync_sig,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            sync.desired_config.config.gateway_endpoint,
            Some("203.0.113.1:51820".to_string())
        );

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
