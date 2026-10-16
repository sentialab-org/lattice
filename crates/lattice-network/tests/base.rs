use lattice_crypto::*;
use lattice_network::{validate_base_configuration, validate_base_desired_config};
use lattice_protocol::*;
fn desired() -> NetworkDesiredConfig {
    NetworkDesiredConfig {
        schema_version: 1,
        node_id: "node-test".into(),
        control_id: "root-test".into(),
        network_id: "network-test".into(),
        revision: 1,
        enabled: true,
        status: NetworkNodeStatus::Allocated,
        virtual_ipv4: Some("10.77.0.4/32".into()),
        overlay_cidr: Some("10.77.0.0/16".into()),
        gateway_ipv4: Some("10.77.0.1".into()),
        gateway_endpoint: Some("198.51.100.1:51820".into()),
        gateway_wireguard_public_key: Some(encode_wireguard_key(&wireguard_public_key(&[5; 32]))),
        allowed_overlay_routes: vec!["10.77.0.0/16".into()],
        keepalive_seconds: 25,
        issued_at_ms: 1000,
    }
}
fn rendered(d: &NetworkDesiredConfig) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        encode_wireguard_key(&[4; 32]),
        d.virtual_ipv4.as_ref().unwrap(),
        d.gateway_wireguard_public_key.as_ref().unwrap(),
        d.gateway_endpoint.as_ref().unwrap(),
        d.overlay_cidr.as_ref().unwrap()
    )
}
#[test]
fn base_node_accepts_only_constrained_overlay_configuration() {
    let d = desired();
    validate_base_desired_config(&d).unwrap();
    let base = validate_base_configuration(
        &d,
        "lattice0",
        &encode_wireguard_key(&wireguard_public_key(&[4; 32])),
        &rendered(&d),
    )
    .unwrap();
    assert!(base.firewall_rules().contains("iifname \"lattice0\" drop"));
    assert!(!base.firewall_rules().contains("net.ipv4.ip_forward"));
    assert!(!base.wireguard_config().contains("Address ="));
}
#[test]
fn signed_metadata_cannot_inject_hooks_default_routes_or_foreign_transport_keys() {
    let original = desired();
    for i in 0..4 {
        let mut d = original.clone();
        match i {
            0 => {
                d.gateway_endpoint =
                    Some("198.51.100.1:51820\n[Interface]\nPostUp = unwanted-command".into())
            }
            1 => d.virtual_ipv4 = Some("10.77.0.4/32\nPostUp = unwanted-command".into()),
            2 => d.overlay_cidr = Some("0.0.0.0/0".into()),
            _ => d.allowed_overlay_routes.push("0.0.0.0/0".into()),
        }
        assert!(validate_base_desired_config(&d).is_err(), "case {i}");
    }
    let text = rendered(&original) + "PostUp = unwanted-command\n";
    let public = encode_wireguard_key(&wireguard_public_key(&[4; 32]));
    assert!(validate_base_configuration(&original, "lattice0", &public, &text).is_err());
    assert!(
        validate_base_configuration(
            &original,
            "lattice0",
            &encode_wireguard_key(&wireguard_public_key(&[9; 32])),
            &rendered(&original)
        )
        .is_err()
    );
}
