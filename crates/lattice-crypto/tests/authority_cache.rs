use lattice_crypto::{authority::issue_certificate, authority_cache::*, *};
use lattice_protocol::*;
use std::collections::{BTreeMap, BTreeSet};

const THEN: u64 = 10_000;
const LATER: u64 = 31_536_010_000;
fn key(seed: u8) -> String {
    encode_key(&public_key(&[seed; 32]))
}
fn master(revision: u64) -> SignedCertificate {
    issue_certificate(
        &[1; 32],
        "network-test",
        CertificateSubject::Master {
            node_id: "node-master".into(),
            node_public_key: key(2),
            control_id: "master-one".into(),
            control_public_key: key(3),
            overlay_ipv4: "10.44.0.2".into(),
        },
        BTreeSet::from([CommandScope::Workloads, CommandScope::Inventory]),
        revision,
        THEN,
    )
    .unwrap()
}
fn snapshot(
    revision: u64,
    certificates: Vec<SignedCertificate>,
    revoked: u64,
) -> SignedAuthoritySnapshot {
    let snapshot = AuthoritySnapshot {
        schema_version: AUTHORITY_VERSION,
        network_id: "network-test".into(),
        issuer_key_id: fingerprint(&key(1)).unwrap(),
        authority_epoch: 1,
        revision,
        issued_at_ms: THEN,
        certificates,
        revocations: if revoked > 0 {
            BTreeMap::from([("master/master-one".into(), revoked)])
        } else {
            BTreeMap::new()
        },
    };
    SignedAuthoritySnapshot {
        signature: sign_domain(&[1; 32], SNAPSHOT_DOMAIN, &snapshot).unwrap(),
        snapshot,
    }
}
fn context(snapshot: SignedAuthoritySnapshot) -> AuthorityContext {
    AuthorityContext {
        snapshot: Some(snapshot),
        ..Default::default()
    }
}
fn cache() -> AuthorityCache {
    AuthorityCache::new(key(1), "network-test".into())
}

#[test]
fn authentic_presented_master_works_without_any_directory_or_renewal() {
    let mut c = cache();
    c.ingest(
        &AuthorityContext {
            master_certificate: Some(master(1)),
            ..Default::default()
        },
        LATER,
    )
    .unwrap();
    c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
        .unwrap();
    assert!(
        c.require_master("other", &key(3), &CommandScope::Workloads, LATER)
            .is_err()
    );
    assert!(
        c.require_master("master-one", &key(4), &CommandScope::Workloads, LATER)
            .is_err()
    );
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Updates, LATER)
            .is_err()
    );
    let mut foreign = AuthorityCache::new(key(4), "network-test".into());
    assert!(
        foreign
            .ingest(
                &AuthorityContext {
                    master_certificate: Some(master(1)),
                    ..Default::default()
                },
                LATER
            )
            .is_err()
    );
}

#[test]
fn signed_revocations_survive_reload_and_snapshot_omission_cannot_restore_grants() {
    let mut c = cache();
    c.ingest(&context(snapshot(1, vec![master(1)], 0)), THEN)
        .unwrap();
    c.ingest(&context(snapshot(2, vec![], 1)), THEN).unwrap();
    let bytes = serde_json::to_vec(&c).unwrap();
    let mut c: AuthorityCache = serde_json::from_slice(&bytes).unwrap();
    c.validate(LATER).unwrap();
    c.ingest(&context(snapshot(3, vec![], 0)), LATER).unwrap();
    assert!(
        c.ingest(&context(snapshot(1, vec![master(1)], 0)), LATER)
            .is_err()
    );
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
            .is_err()
    );
    c.ingest(
        &AuthorityContext {
            master_certificate: Some(master(2)),
            ..Default::default()
        },
        LATER,
    )
    .unwrap();
    c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
        .unwrap();
    assert!(
        c.ingest(
            &AuthorityContext {
                master_certificate: Some(master(1)),
                ..Default::default()
            },
            LATER
        )
        .is_err()
    );
}

#[test]
fn replacement_snapshot_does_not_revoke_older_independent_certificates() {
    let mut c = cache();
    c.ingest(&context(snapshot(1, vec![master(1)], 0)), THEN)
        .unwrap();
    c.ingest(&context(snapshot(2, vec![], 0)), LATER).unwrap();
    c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
        .unwrap();
    assert!(
        c.ingest(&context(snapshot(2, vec![master(1)], 0)), LATER)
            .is_err()
    );
}

#[test]
fn older_presented_announcement_cannot_replace_newer_state_or_block_valid_master() {
    let mut c = cache();
    c.ingest(&context(snapshot(3, vec![], 0)), LATER).unwrap();
    c.ingest_presented(&context(snapshot(1, vec![master(1)], 0)), LATER)
        .unwrap();
    assert_eq!(c.snapshot().unwrap().snapshot.revision, 3);
    c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
        .unwrap();
    c.ingest(&context(snapshot(4, vec![], 1)), LATER).unwrap();
    c.ingest_presented(&context(snapshot(1, vec![master(1)], 0)), LATER)
        .unwrap();
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
            .is_err()
    );
}

#[test]
fn expired_grant_in_historical_snapshot_cannot_hide_signed_revocations() {
    let mut expired = master(1);
    expired.certificate.expires_at_ms = Some(THEN + 10_000);
    expired.signature = sign_domain(&[1; 32], CERTIFICATE_DOMAIN, &expired.certificate).unwrap();
    let mut c = cache();
    c.ingest(&context(snapshot(2, vec![expired], 1)), LATER)
        .unwrap();
    c.validate(LATER).unwrap();
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
            .is_err()
    );
}

#[test]
fn clock_rollback_cannot_revive_an_observed_expired_certificate() {
    let mut expired = master(1);
    expired.certificate.expires_at_ms = Some(THEN + 10_000);
    expired.signature = sign_domain(&[1; 32], CERTIFICATE_DOMAIN, &expired.certificate).unwrap();
    let mut c = cache();
    c.ingest(
        &AuthorityContext {
            master_certificate: Some(expired),
            ..Default::default()
        },
        LATER,
    )
    .unwrap();
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Workloads, THEN)
            .is_err(),
        "rolling back the clock must not revive an expired grant"
    );
}

#[test]
fn command_replay_is_persisted_and_proof_binds_target_request_and_payload() {
    let mut c = cache();
    let binding = CommandBinding {
        control_id: "master-one",
        control_public_key: &key(3),
        target_node_id: "node-worker",
        request_id: "request-one",
        sequence: 7,
        payload_sha256: &"a".repeat(64),
        scopes: &[CommandScope::Workloads],
    };
    let command = CommandContext {
        schema_version: AUTHORITY_VERSION,
        network_id: "network-test".into(),
        control_id: binding.control_id.into(),
        target_node_id: binding.target_node_id.into(),
        request_id: binding.request_id.into(),
        sequence: binding.sequence,
        issued_at_ms: LATER,
        expires_at_ms: LATER + 60_000,
        payload_sha256: binding.payload_sha256.into(),
    };
    let proof = SignedCommandProof {
        signature: sign_domain(&[3; 32], COMMAND_DOMAIN, &command).unwrap(),
        context: command,
        certificate: master(1),
    };
    let mut bad = proof.clone();
    bad.context.target_node_id = "another-node".into();
    assert!(c.accept_command(&bad, &binding, LATER).is_err());
    assert!(
        c.require_master("master-one", &key(3), &CommandScope::Workloads, LATER)
            .is_err(),
        "failed proof must not mutate cache"
    );
    c.accept_command(&proof, &binding, LATER).unwrap();
    let mut restored: AuthorityCache =
        serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(restored.accept_command(&proof, &binding, LATER).is_err());
    let mut bad_payload = proof.clone();
    bad_payload.context.sequence = 8;
    bad_payload.context.payload_sha256 = "b".repeat(64);
    bad_payload.signature = sign_domain(&[3; 32], COMMAND_DOMAIN, &bad_payload.context).unwrap();
    let next = CommandBinding {
        sequence: 8,
        ..binding
    };
    assert!(restored.accept_command(&bad_payload, &next, LATER).is_err());
}
