use crate::intent::{address, endpoint, identifier, inside};
use lattice_crypto::{decode_wireguard_key, encode_wireguard_key, wireguard_public_key};
use lattice_protocol::{NetworkDesiredConfig, NetworkPeerEntry};
use std::collections::{BTreeMap, BTreeSet};

/// A constrained Base Node plan. Private configuration is never exposed over IPC.
pub struct ValidatedBase {
    pub(crate) desired: NetworkDesiredConfig,
    pub(crate) interface: String,
    pub(crate) transport: String,
    config: String,
}
impl ValidatedBase {
    pub fn wireguard_config(&self) -> &str {
        &self.config
    }
    pub fn firewall_rules(&self) -> String {
        base_firewall(&self.interface)
    }
}
pub(crate) fn base_firewall(interface: &str) -> String {
    format!(
        "table inet lattice_overlay {{\n chain forward {{\n  type filter hook forward priority 0; policy accept;\n  iifname \"{interface}\" drop\n  oifname \"{interface}\" drop\n }}\n}}\n"
    )
}
pub(crate) fn interface_valid(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= 15
        && interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn public_key(value: &str) -> bool {
    decode_wireguard_key(value).is_ok_and(|k| k != [0; 32] && encode_wireguard_key(&k) == value)
}
pub fn validate_base_desired_config(d: &NetworkDesiredConfig) -> Result<(), String> {
    if d.schema_version != 1
        || !identifier(&d.node_id)
        || !identifier(&d.control_id)
        || !identifier(&d.network_id)
        || d.revision == 0
    {
        return Err("invalid Base Node plan identity".into());
    }
    if !d.enabled {
        return Ok(());
    }
    let cidr = d.overlay_cidr.as_deref().ok_or("overlay required")?;
    let (network, prefix) = address(cidr)?;
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let (own, own_prefix) = address(d.virtual_ipv4.as_deref().ok_or("node address required")?)?;
    let gateway = d
        .gateway_ipv4
        .as_deref()
        .ok_or("gateway address required")?
        .parse()
        .map_err(|_| "invalid gateway address")?;
    if !(8..=30).contains(&prefix)
        || !network.is_private()
        || u32::from(network) & mask != u32::from(network)
        || own_prefix != 32
        || !inside(own, network, prefix)
        || own == network
        || u32::from(own) == u32::from(network) | !mask
        || !inside(gateway, network, prefix)
        || gateway == network
        || u32::from(gateway) == u32::from(network) | !mask
        || gateway == own
        || !d
            .gateway_wireguard_public_key
            .as_deref()
            .is_some_and(public_key)
        || !d.gateway_endpoint.as_deref().is_some_and(endpoint)
        || d.allowed_overlay_routes != [cidr]
        || d.keepalive_seconds > 600
    {
        return Err("invalid Base Node overlay binding".into());
    }
    Ok(())
}
pub fn valid_direct_peer(d: &NetworkDesiredConfig, p: &NetworkPeerEntry) -> bool {
    let Some(cidr) = d.overlay_cidr.as_deref() else {
        return false;
    };
    let Ok((network, prefix)) = address(cidr) else {
        return false;
    };
    let Ok((ip, bits)) = address(&p.virtual_ipv4) else {
        return false;
    };
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    identifier(&p.node_id)
        && p.node_id != d.node_id
        && public_key(&p.wireguard_public_key)
        && Some(p.wireguard_public_key.as_str()) != d.gateway_wireguard_public_key.as_deref()
        && bits == 32
        && inside(ip, network, prefix)
        && ip != network
        && u32::from(ip) != u32::from(network) | !mask
        && Some(p.virtual_ipv4.as_str()) != d.virtual_ipv4.as_deref()
        && Some(ip.to_string().as_str()) != d.gateway_ipv4.as_deref()
        && p.endpoint_candidates.iter().all(|e| endpoint(e))
}
pub fn validate_base_configuration(
    d: &NetworkDesiredConfig,
    interface: &str,
    transport: &str,
    text: &str,
) -> Result<ValidatedBase, String> {
    validate_base_desired_config(d)?;
    if !d.enabled
        || !interface_valid(interface)
        || !public_key(transport)
        || text.len() > 4 * 1024 * 1024
    {
        return Err("invalid Base Node configuration binding".into());
    }
    let mut sections: Vec<(&str, BTreeMap<&str, &str>)> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if (sections.is_empty() && line != "[Interface]")
                || (!sections.is_empty() && line != "[Peer]")
                || sections.len() > 4096
            {
                return Err("unexpected WireGuard section".into());
            }
            sections.push((line, BTreeMap::new()));
            continue;
        }
        let section = sections.last_mut().ok_or("WireGuard section required")?;
        let (key, value) = line.split_once('=').ok_or("invalid WireGuard directive")?;
        let (key, value) = (key.trim(), value.trim());
        let allowed = if section.0 == "[Interface]" {
            ["PrivateKey", "Address"].contains(&key)
        } else {
            ["PublicKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"].contains(&key)
        };
        if !allowed || section.1.insert(key, value).is_some() {
            return Err("unsupported or repeated WireGuard directive".into());
        }
    }
    let local = &sections.first().ok_or("interface required")?.1;
    let private = decode_wireguard_key(local.get("PrivateKey").ok_or("private key required")?)?;
    if local.get("Address").copied() != d.virtual_ipv4.as_deref()
        || encode_wireguard_key(&wireguard_public_key(&private)) != transport
    {
        return Err("Base Node transport ownership rejected".into());
    }
    let mut gateway_seen = false;
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for (_, peer) in sections.iter().skip(1) {
        let key = *peer.get("PublicKey").ok_or("peer key required")?;
        let route = *peer.get("AllowedIPs").ok_or("peer address required")?;
        if !public_key(key)
            || key == transport
            || !keys.insert(key)
            || !addresses.insert(route)
            || peer.get("Endpoint").is_some_and(|e| !endpoint(e))
            || peer
                .get("PersistentKeepalive")
                .is_some_and(|k| k.parse::<u16>().ok() != Some(d.keepalive_seconds))
        {
            return Err("invalid or conflicting Base Node peer".into());
        }
        if Some(key) == d.gateway_wireguard_public_key.as_deref() {
            if Some(route) != d.overlay_cidr.as_deref()
                || peer.get("Endpoint").copied() != d.gateway_endpoint.as_deref()
            {
                return Err("gateway binding rejected".into());
            }
            gateway_seen = true;
        } else {
            let candidate = NetworkPeerEntry {
                node_id: "validated-peer".into(),
                wireguard_public_key: key.into(),
                virtual_ipv4: route.into(),
                endpoint_candidates: peer
                    .get("Endpoint")
                    .map(|e| vec![(*e).into()])
                    .unwrap_or_default(),
                status: lattice_protocol::NetworkNodeStatus::Allocated,
                revision: 1,
                updated_at_ms: 0,
            };
            if !valid_direct_peer(d, &candidate) {
                return Err("direct peer route rejected".into());
            }
        }
    }
    if !gateway_seen {
        return Err("gateway peer required".into());
    }
    let config = text
        .lines()
        .filter(|line| !line.trim().starts_with("Address"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    Ok(ValidatedBase {
        desired: d.clone(),
        interface: interface.into(),
        transport: transport.into(),
        config,
    })
}
