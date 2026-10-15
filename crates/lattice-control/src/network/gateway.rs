use super::NetworkState;
use lattice_protocol::NetworkNodeStatus;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayPeerConfig {
    pub node_id: String,
    pub public_key: String,
    pub allowed_ips: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayWireguardConfig {
    pub interface_name: String,
    pub listen_port: u16,
    pub private_key: String,
    pub address: String,
    pub peers: Vec<GatewayPeerConfig>,
    pub keepalive_seconds: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorGatewayView {
    pub interface_name: String,
    pub listen_port: u16,
    pub address: String,
    pub public_key: String,
    pub peer_count: usize,
    pub wireguard_config: String,
    pub nftables_ruleset: String,
    pub nftables_rollback: String,
    pub sysctl_requirements: String,
    #[serde(default)]
    pub network_id: String,
    #[serde(default)]
    pub overlay_cidr: String,
    #[serde(default)]
    pub path_policy: String,
    #[serde(default)]
    pub relays: Vec<RelayView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayView {
    pub relay_id: String,
    pub endpoint: String,
}

pub fn render_wireguard_config(config: &GatewayWireguardConfig) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", config.private_key));
    out.push_str(&format!("ListenPort = {}\n", config.listen_port));

    for peer in &config.peers {
        out.push_str("\n[Peer]\n");
        out.push_str(&format!("# NodeId = {}\n", peer.node_id));
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips));
        out.push_str(&format!(
            "PersistentKeepalive = {}\n",
            config.keepalive_seconds
        ));
    }

    out
}

pub fn render_nftables_ruleset(interface_name: &str, overlay_cidr: &str) -> String {
    format!(
        r#"table inet lattice_overlay {{
    chain forward {{
        type filter hook forward priority 0; policy drop;

        iifname "{interface_name}" oifname "{interface_name}" ip saddr {overlay_cidr} ip daddr {overlay_cidr} accept
        ct state established,related accept

        drop
    }}
}}
"#
    )
}

pub fn render_nftables_rollback() -> String {
    r#"table inet lattice_overlay { }
delete table inet lattice_overlay
"#
    .to_string()
}

pub fn render_sysctl_requirements() -> &'static str {
    "net.ipv4.ip_forward = 1\nnet.ipv4.conf.all.rp_filter = 2\n"
}

pub fn build_gateway_config(
    state: &NetworkState,
    gateway_private_key: &str,
    listen_port: u16,
    interface_name: &str,
) -> GatewayWireguardConfig {
    let mut peers = Vec::new();

    for (node_id, alloc) in &state.allocations {
        if !alloc.enabled {
            continue;
        }
        if matches!(
            alloc.status,
            NetworkNodeStatus::Revoked | NetworkNodeStatus::Disabled
        ) {
            continue;
        }
        let Some(ref pub_key) = alloc.wireguard_public_key else {
            continue;
        };

        peers.push(GatewayPeerConfig {
            node_id: node_id.clone(),
            public_key: pub_key.clone(),
            allowed_ips: alloc.virtual_ipv4.clone(),
        });
    }

    peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let address = if state.gateway_ipv4.contains('/') {
        state.gateway_ipv4.clone()
    } else {
        let prefix = state.overlay_cidr.split('/').nth(1).unwrap_or("16");
        format!("{}/{}", state.gateway_ipv4, prefix)
    };

    GatewayWireguardConfig {
        interface_name: interface_name.to_string(),
        listen_port,
        private_key: gateway_private_key.to_string(),
        address,
        peers,
        keepalive_seconds: state.keepalive_seconds,
    }
}

#[allow(dead_code)]
pub async fn write_gateway_config_atomic(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| e.to_string())?;
    }
    let temp_path = path.with_extension("tmp");
    tokio::fs::write(&temp_path, content)
        .await
        .map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600));
    }

    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NetworkAllocation;
    use std::collections::BTreeMap;

    #[test]
    fn gateway_wireguard_config_rendering() {
        let config = GatewayWireguardConfig {
            interface_name: "wg-lattice".to_string(),
            listen_port: 51820,
            private_key: "PRIVATE_KEY_EXAMPLE==".to_string(),
            address: "10.240.0.1/16".to_string(),
            keepalive_seconds: 25,
            peers: vec![
                GatewayPeerConfig {
                    node_id: "node-1".to_string(),
                    public_key: "PUBKEY_1==".to_string(),
                    allowed_ips: "10.240.0.2/32".to_string(),
                },
                GatewayPeerConfig {
                    node_id: "node-2".to_string(),
                    public_key: "PUBKEY_2==".to_string(),
                    allowed_ips: "10.240.0.3/32".to_string(),
                },
            ],
        };

        let rendered = render_wireguard_config(&config);
        assert!(rendered.contains("ListenPort = 51820"));
        assert!(rendered.contains("PrivateKey = PRIVATE_KEY_EXAMPLE=="));
        assert!(!rendered.contains("Address = "));
        assert!(rendered.contains("# NodeId = node-1"));
        assert!(rendered.contains("PublicKey = PUBKEY_1=="));
        assert!(rendered.contains("AllowedIPs = 10.240.0.2/32"));
        assert!(rendered.contains("PersistentKeepalive = 25"));
        assert!(rendered.contains("# NodeId = node-2"));
        assert!(rendered.contains("PublicKey = PUBKEY_2=="));
        assert!(rendered.contains("AllowedIPs = 10.240.0.3/32"));
    }

    #[test]
    fn gateway_builder_filters_revoked_and_disabled_peers() {
        let mut allocations = BTreeMap::new();
        allocations.insert(
            "active-node".to_string(),
            NetworkAllocation {
                node_id: "active-node".to_string(),
                virtual_ipv4: "10.240.0.2/32".to_string(),
                wireguard_public_key: Some("KEY_ACTIVE==".to_string()),
                revision: 1,
                enabled: true,
                status: NetworkNodeStatus::Connected,
                last_applied_revision: 1,
                last_sequence: 1,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 1000,
            },
        );
        allocations.insert(
            "revoked-node".to_string(),
            NetworkAllocation {
                node_id: "revoked-node".to_string(),
                virtual_ipv4: "10.240.0.3/32".to_string(),
                wireguard_public_key: Some("KEY_REVOKED==".to_string()),
                revision: 2,
                enabled: false,
                status: NetworkNodeStatus::Revoked,
                last_applied_revision: 1,
                last_sequence: 2,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 2000,
            },
        );
        allocations.insert(
            "disabled-node".to_string(),
            NetworkAllocation {
                node_id: "disabled-node".to_string(),
                virtual_ipv4: "10.240.0.4/32".to_string(),
                wireguard_public_key: Some("KEY_DISABLED==".to_string()),
                revision: 3,
                enabled: false,
                status: NetworkNodeStatus::Disabled,
                last_applied_revision: 2,
                last_sequence: 3,
                last_error: None,
                endpoint_candidates: Vec::new(),
                gateway_endpoint_override: None,
                updated_at_ms: 3000,
            },
        );

        let state = NetworkState {
            network_id: "lattice-test".to_string(),
            overlay_cidr: "10.240.0.0/16".to_string(),
            gateway_ipv4: "10.240.0.1".to_string(),
            gateway_endpoint: "1.2.3.4:51820".to_string(),
            gateway_wireguard_public_key: "GW_PUBKEY==".to_string(),
            keepalive_seconds: 25,
            interface_name: "wg-lattice".to_string(),
            reserved_ipv4: Vec::new(),
            relays: Vec::new(),
            path_policy: "hub".to_string(),
            next_ip_offset: 5,
            allocations,
        };

        let gw_config = build_gateway_config(&state, "GW_PRIVKEY==", 51820, "wg-lattice");
        assert_eq!(gw_config.peers.len(), 1);
        assert_eq!(gw_config.peers[0].node_id, "active-node");
        assert_eq!(gw_config.peers[0].public_key, "KEY_ACTIVE==");
        assert_eq!(gw_config.peers[0].allowed_ips, "10.240.0.2/32");
    }

    #[test]
    fn nftables_ruleset_enforces_isolated_intra_overlay_forwarding() {
        let ruleset = render_nftables_ruleset("wg-lattice", "10.240.0.0/16");
        assert!(ruleset.contains("table inet lattice_overlay"));
        assert!(ruleset.contains("policy drop;"));
        assert!(ruleset.contains(r#"iifname "wg-lattice" oifname "wg-lattice" ip saddr 10.240.0.0/16 ip daddr 10.240.0.0/16 accept"#));
        assert!(ruleset.contains("ct state established,related accept"));
        assert!(!ruleset.contains("masquerade"));
        assert!(!ruleset.contains("snat"));

        let rollback = render_nftables_rollback();
        assert!(rollback.contains("delete table inet lattice_overlay"));
    }

    #[tokio::test]
    async fn atomic_config_write() {
        let temp_dir =
            std::env::temp_dir().join(format!("lattice-gw-test-{}", uuid::Uuid::new_v4()));
        let config_path = temp_dir.join("wg-lattice.conf");
        let content = "[Interface]\nAddress = 10.240.0.1/16\n";

        write_gateway_config_atomic(&config_path, content)
            .await
            .unwrap();

        let read_back = tokio::fs::read_to_string(&config_path).await.unwrap();
        assert_eq!(read_back, content);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn gateway_address_derives_prefix_from_overlay_cidr() {
        let state = NetworkState {
            overlay_cidr: "10.240.50.0/24".to_string(),
            gateway_ipv4: "10.240.50.1".to_string(),
            ..Default::default()
        };
        let gw_config = build_gateway_config(&state, "KEY", 51820, "wg-lattice");
        assert_eq!(gw_config.address, "10.240.50.1/24");
    }
}
