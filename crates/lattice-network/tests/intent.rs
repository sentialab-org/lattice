mod support;
use lattice_crypto::*;
use lattice_protocol::*;
use std::collections::BTreeMap;
use support::*;
#[test]
fn issued_intent_verifies_offline_and_only_renders_owned_network_rules() {
    let (cache, intent) = fixture();
    let plan = check(&cache, &intent).unwrap();
    let wg = plan.wireguard_config(&[4; 32]).unwrap();
    assert!(wg.contains("AllowedIPs = 10.77.0.6/32"));
    assert!(!wg.contains("0.0.0.0/0"));
    assert!(plan.wireguard_config(&[6; 32]).is_err());
    let rules = plan.firewall_rules(4_000_000).unwrap();
    assert!(rules.contains("table inet lattice_overlay"));
    assert!(rules.contains("500000 bytes/second"));
    assert!(!rules.contains("flush ruleset"));
    assert!(!rules.contains("policy drop"));
    assert!(!rules.contains("table inet other"));
}
#[test]
fn signed_intent_cannot_escape_device_key_interface_address_or_peer_routes() {
    let (cache, original) = fixture();
    let mut cases = Vec::new();
    for change in 0..9 {
        let mut s = original.clone();
        match change {
            0 => s.intent.target_node_id = "other-device".into(),
            1 => s.intent.interface_name = "eth0".into(),
            2 => s.intent.address = "10.77.0.8/32".into(),
            3 => s.intent.peers[0].allowed_ipv4 = "0.0.0.0/0".into(),
            4 => s.intent.peers.push(s.intent.peers[0].clone()),
            5 => s.intent.peers[0].endpoint = Some("host:51820\nPostUp=sh".into()),
            6 => s.intent.transport_public_key = transport(9),
            7 => s.intent.network_id = "other-network".into(),
            _ => s.intent.revision = 0,
        }
        s.signature = sign_domain(&[1; 32], NETWORK_INTENT_DOMAIN, &s.intent).unwrap();
        cases.push(s);
    }
    for (i, s) in cases.iter().enumerate() {
        assert!(check(&cache, s).is_err(), "invalid intent case {i}");
    }
    let mut forged = original.clone();
    forged.signature = sign_domain(&[9; 32], NETWORK_INTENT_DOMAIN, &forged.intent).unwrap();
    assert!(check(&cache, &forged).is_err());
}
#[test]
fn known_revocation_prevents_replaying_an_authentic_relay_plan() {
    let (mut cache, s) = fixture();
    let snapshot = AuthoritySnapshot {
        schema_version: AUTHORITY_VERSION,
        network_id: "network-test".into(),
        issuer_key_id: fingerprint(&signing(1)).unwrap(),
        authority_epoch: 1,
        revision: 1,
        issued_at_ms: 1000,
        certificates: vec![],
        revocations: BTreeMap::from([("relay/node-host".into(), 1)]),
    };
    let signed = SignedAuthoritySnapshot {
        signature: sign_domain(&[1; 32], SNAPSHOT_DOMAIN, &snapshot).unwrap(),
        snapshot,
    };
    cache
        .ingest(
            &AuthorityContext {
                snapshot: Some(signed),
                ..Default::default()
            },
            1000,
        )
        .unwrap();
    assert!(check(&cache, &s).is_err());
}
