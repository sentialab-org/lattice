use lattice_crypto::authority::{issue_certificate, verify_certificate, verify_snapshot};
use lattice_crypto::{encode_key, public_key, sign_domain};
use lattice_protocol::*;
use std::collections::{BTreeMap, BTreeSet};

fn master() -> CertificateSubject {
    CertificateSubject::Master {
        node_id: "node-a".into(),
        node_public_key: encode_key(&public_key(&[8; 32])),
        control_id: "master-a".into(),
        control_public_key: encode_key(&public_key(&[9; 32])),
        overlay_ipv4: "10.77.0.4".into(),
    }
}
#[test]
fn issued_master_remains_verifiable_without_recent_supervisor_contact() {
    let root = encode_key(&public_key(&[7; 32]));
    let c = issue_certificate(
        &[7; 32],
        "network-a",
        master(),
        BTreeSet::from([CommandScope::Workloads]),
        1,
        1000,
    )
    .unwrap();
    verify_certificate(&root, "network-a", &c, 31_536_000_000).unwrap();
    assert!(verify_certificate(&root, "network-b", &c, 2000).is_err());
    assert!(verify_certificate(&encode_key(&public_key(&[6; 32])), "network-a", &c, 2000).is_err());
    let mut changed = c.clone();
    if let CertificateSubject::Master {
        control_public_key, ..
    } = &mut changed.certificate.subject
    {
        *control_public_key = encode_key(&public_key(&[5; 32]));
    }
    assert!(verify_certificate(&root, "network-a", &changed, 2000).is_err());
}
#[test]
fn relay_scope_cannot_become_workload_authority() {
    let relay = CertificateSubject::Relay {
        node_id: "relay-a".into(),
        node_public_key: encode_key(&public_key(&[8; 32])),
        transport_public_key: lattice_crypto::encode_wireguard_key(
            &lattice_crypto::wireguard_public_key(&[3; 32]),
        ),
        overlay_ipv4: "10.77.0.1".into(),
        endpoint: "relay.example.test:51820".into(),
        bandwidth_limit_bps: 10_000_000,
    };
    assert!(
        issue_certificate(
            &[7; 32],
            "network-a",
            relay.clone(),
            BTreeSet::from([CommandScope::Workloads]),
            1,
            1000
        )
        .is_err()
    );
    let c = issue_certificate(
        &[7; 32],
        "network-a",
        relay,
        BTreeSet::from([CommandScope::NetworkForwarding]),
        1,
        1000,
    )
    .unwrap();
    verify_certificate(
        &encode_key(&public_key(&[7; 32])),
        "network-a",
        &c,
        100_000_000,
    )
    .unwrap();
}
#[test]
fn signed_snapshot_binds_revocations_and_accepts_old_issued_credentials() {
    let key = encode_key(&public_key(&[7; 32]));
    let c = issue_certificate(
        &[7; 32],
        "network-a",
        master(),
        BTreeSet::from([CommandScope::Workloads]),
        1,
        1000,
    )
    .unwrap();
    let snapshot = AuthoritySnapshot {
        schema_version: AUTHORITY_VERSION,
        network_id: "network-a".into(),
        issuer_key_id: lattice_crypto::fingerprint(&key).unwrap(),
        authority_epoch: 1,
        revision: 2,
        issued_at_ms: 1000,
        certificates: vec![c],
        revocations: BTreeMap::from([("master/other".into(), 1)]),
    };
    let signed = SignedAuthoritySnapshot {
        signature: sign_domain(&[7; 32], SNAPSHOT_DOMAIN, &snapshot).unwrap(),
        snapshot,
    };
    verify_snapshot(&key, "network-a", &signed, 31_536_000_000).unwrap();
    let mut changed = signed.clone();
    changed.snapshot.revocations.clear();
    assert!(verify_snapshot(&key, "network-a", &changed, 2000).is_err());
    changed = signed.clone();
    changed.snapshot.network_id = "network-b".into();
    assert!(verify_snapshot(&key, "network-a", &changed, 2000).is_err());
}
#[test]
fn explicit_signed_expiry_and_issuance_restrictions_are_enforced() {
    let key = encode_key(&public_key(&[7; 32]));
    let mut c = issue_certificate(
        &[7; 32],
        "network-a",
        master(),
        BTreeSet::from([CommandScope::Workloads]),
        1,
        1000,
    )
    .unwrap();
    c.certificate.expires_at_ms = Some(2000);
    c.signature = sign_domain(&[7; 32], CERTIFICATE_DOMAIN, &c.certificate).unwrap();
    verify_certificate(&key, "network-a", &c, 1999).unwrap();
    assert!(verify_certificate(&key, "network-a", &c, 2000).is_err());
    c.certificate.issuer_key_id = "substituted-issuer".into();
    c.signature = sign_domain(&[7; 32], CERTIFICATE_DOMAIN, &c.certificate).unwrap();
    assert!(verify_certificate(&key, "network-a", &c, 1500).is_err());
}
