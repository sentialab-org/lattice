use lattice_crypto::{authority::issue_certificate, authority_cache::AuthorityCache, *};
use lattice_network::{NetworkBinding, validate_gateway_intent};
use lattice_protocol::*;
use std::collections::BTreeSet;
pub fn signing(seed: u8) -> String {
    encode_key(&public_key(&[seed; 32]))
}
pub fn transport(seed: u8) -> String {
    encode_wireguard_key(&wireguard_public_key(&[seed; 32]))
}
pub fn fixture() -> (AuthorityCache, SignedGatewayIntent) {
    let mut cache = AuthorityCache::new(signing(1), "network-test".into());
    let member = issue_certificate(
        &[1; 32],
        "network-test",
        CertificateSubject::Membership {
            node_id: "node-host".into(),
            node_public_key: signing(2),
            terms_version: "1".into(),
            terms_sha256: "0".repeat(64),
        },
        BTreeSet::new(),
        1,
        1000,
    )
    .unwrap();
    cache
        .ingest(
            &AuthorityContext {
                membership_certificate: Some(member),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
    let certificate = issue_certificate(
        &[1; 32],
        "network-test",
        CertificateSubject::Relay {
            node_id: "node-host".into(),
            node_public_key: signing(2),
            transport_public_key: transport(4),
            overlay_ipv4: "10.77.0.4".into(),
            endpoint: "198.51.100.1:51820".into(),
            bandwidth_limit_bps: 8_000_000,
        },
        BTreeSet::from([CommandScope::NetworkForwarding]),
        1,
        1000,
    )
    .unwrap();
    let intent = GatewayIntent {
        schema_version: AUTHORITY_VERSION,
        network_id: "network-test".into(),
        target_node_id: "node-host".into(),
        revision: 1,
        interface_name: "lattice0".into(),
        address: "10.77.0.4/32".into(),
        overlay_cidr: "10.77.0.0/16".into(),
        listen_port: 51820,
        transport_public_key: transport(4),
        peers: vec![NetworkPeerIntent {
            node_id: "node-worker".into(),
            public_key: transport(5),
            allowed_ipv4: "10.77.0.6/32".into(),
            endpoint: Some("198.51.100.2:51820".into()),
        }],
    };
    let signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &intent).unwrap();
    (
        cache,
        SignedGatewayIntent {
            intent,
            certificate,
            signature,
        },
    )
}
pub fn check(
    cache: &AuthorityCache,
    intent: &SignedGatewayIntent,
) -> Result<lattice_network::ValidatedGateway, String> {
    validate_gateway_intent(
        cache,
        intent,
        &NetworkBinding {
            node_id: "node-host",
            node_public_key: &signing(2),
            transport_public_key: &transport(4),
            interface_name: "lattice0",
            address: Some("10.77.0.4/32"),
            overlay_cidr: Some("10.77.0.0/16"),
        },
        31_536_001_000,
    )
}
