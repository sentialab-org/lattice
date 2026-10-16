use lattice_crypto::{
    authority_cache::AuthorityCache, encode_wireguard_key, verify_domain, wireguard_public_key,
};
use lattice_protocol::*;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub struct NetworkBinding<'a> {
    pub node_id: &'a str,
    pub node_public_key: &'a str,
    pub transport_public_key: &'a str,
    pub interface_name: &'a str,
    pub address: Option<&'a str>,
    pub overlay_cidr: Option<&'a str>,
}

/// Constructible only after signature, capability and local ownership validation.
pub struct ValidatedGateway {
    intent: GatewayIntent,
    authority: AuthorityCache,
    bandwidth_limit_bps: u64,
}
impl ValidatedGateway {
    pub fn intent(&self) -> &GatewayIntent {
        &self.intent
    }
    pub fn authority(&self) -> &AuthorityCache {
        &self.authority
    }
    pub fn wireguard_config(&self, private: &[u8; 32]) -> Result<String, String> {
        if encode_wireguard_key(&wireguard_public_key(private)) != self.intent.transport_public_key
        {
            return Err("transport private key does not belong to this plan".into());
        }
        let mut text = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\n",
            encode_wireguard_key(private),
            self.intent.listen_port
        );
        for peer in &self.intent.peers {
            text.push_str(&format!(
                "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
                peer.public_key, peer.allowed_ipv4
            ));
            if let Some(endpoint) = &peer.endpoint {
                text.push_str(&format!("Endpoint = {endpoint}\n"));
            }
        }
        Ok(text)
    }
    pub fn firewall_rules(&self, owner_limit_bps: u64) -> Result<String, String> {
        if owner_limit_bps == 0 {
            return Err("owner forwarding limit is zero".into());
        }
        let bytes_per_second = (self.bandwidth_limit_bps.min(owner_limit_bps) / 8).max(1);
        let i = &self.intent.interface_name;
        let cidr = &self.intent.overlay_cidr;
        Ok(format!(
            "table inet lattice_overlay {{\n chain forward {{\n  type filter hook forward priority 0; policy accept;\n  iifname \"{i}\" oifname \"{i}\" ip saddr {cidr} ip daddr {cidr} limit rate over {bytes_per_second} bytes/second drop\n  iifname \"{i}\" oifname \"{i}\" ip saddr {cidr} ip daddr {cidr} accept\n  iifname \"{i}\" drop\n  oifname \"{i}\" drop\n }}\n}}\n"
        ))
    }
}
pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub(crate) fn address(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip, prefix) = value.split_once('/').ok_or("IPv4 prefix required")?;
    let ip = ip.parse::<Ipv4Addr>().map_err(|_| "invalid IPv4 address")?;
    let prefix = prefix.parse::<u8>().map_err(|_| "invalid IPv4 prefix")?;
    if prefix > 32 || value != format!("{ip}/{prefix}") {
        return Err("noncanonical IPv4 address".into());
    }
    Ok((ip, prefix))
}
pub(crate) fn inside(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
}
pub(crate) fn endpoint(value: &str) -> bool {
    if value.len() > 280
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    if let Ok(a) = value.parse::<SocketAddr>() {
        return a.port() > 0 && !a.ip().is_unspecified() && !a.ip().is_multicast();
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if !port.parse::<u16>().is_ok_and(|p| p > 0) || host.len() > 253 {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return !ip.is_unspecified() && !ip.is_multicast();
    }
    host.split('.').all(|part| {
        !part.is_empty()
            && part.len() <= 63
            && !part.starts_with('-')
            && !part.ends_with('-')
            && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
pub fn validate_gateway_intent(
    cache: &AuthorityCache,
    signed: &SignedGatewayIntent,
    b: &NetworkBinding<'_>,
    now: u64,
) -> Result<ValidatedGateway, String> {
    let p = &signed.intent;
    verify_domain(
        &cache.supervisor_key,
        NETWORK_INTENT_DOMAIN,
        &signed.signature,
        p,
    )?;
    if p.schema_version != AUTHORITY_VERSION
        || p.network_id != cache.network_id
        || p.target_node_id != b.node_id
        || p.revision == 0
        || p.interface_name != b.interface_name
        || p.interface_name.is_empty()
        || p.interface_name.len() > 15
        || !p
            .interface_name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || p.transport_public_key != b.transport_public_key
        || p.listen_port == 0
        || p.peers.len() > 4096
        || b.address.is_some_and(|a| a != p.address)
        || b.overlay_cidr.is_some_and(|a| a != p.overlay_cidr)
    {
        return Err("network intent does not match local ownership".into());
    }
    let (overlay, prefix) = address(&p.overlay_cidr)?;
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    let (own, own_prefix) = address(&p.address)?;
    if !(8..=30).contains(&prefix)
        || u32::from(overlay) & mask != u32::from(overlay)
        || !overlay.is_private()
        || !inside(own, overlay, prefix)
        || own == overlay
        || u32::from(own) == u32::from(overlay) | !mask
        || (own_prefix != 32 && own_prefix != prefix)
    {
        return Err("invalid managed overlay address".into());
    }
    let mut authority = cache.clone();
    authority.ingest_presented(
        &AuthorityContext {
            relay_certificate: Some(signed.certificate.clone()),
            ..Default::default()
        },
        now,
    )?;
    authority.require_membership(b.node_id, b.node_public_key, now)?;
    let certificate = authority.require_relay(b.node_id, b.node_public_key, now)?;
    let bandwidth = match &certificate.certificate.subject {
        CertificateSubject::Relay {
            transport_public_key,
            overlay_ipv4,
            endpoint: e,
            bandwidth_limit_bps,
            ..
        } if transport_public_key == b.transport_public_key
            && overlay_ipv4 == &own.to_string()
            && e.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok())
                == Some(p.listen_port) =>
        {
            *bandwidth_limit_bps
        }
        _ => return Err("relay capability does not own the transport binding".into()),
    };
    let mut nodes = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    for peer in &p.peers {
        let (ip, bits) = address(&peer.allowed_ipv4)?;
        let public = lattice_crypto::decode_wireguard_key(&peer.public_key)?;
        if !identifier(&peer.node_id)
            || peer.node_id == p.target_node_id
            || bits != 32
            || !inside(ip, overlay, prefix)
            || ip == own
            || ip == overlay
            || u32::from(ip) == u32::from(overlay) | !mask
            || public == [0; 32]
            || peer.public_key == p.transport_public_key
            || !nodes.insert(&peer.node_id)
            || !keys.insert(&peer.public_key)
            || !addresses.insert(ip)
            || peer.endpoint.as_deref().is_some_and(|e| !endpoint(e))
        {
            return Err("invalid or conflicting managed peer".into());
        }
    }
    Ok(ValidatedGateway {
        intent: p.clone(),
        authority,
        bandwidth_limit_bps: bandwidth,
    })
}
